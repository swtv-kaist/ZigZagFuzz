#!/usr/bin/env python3
"""
zzf-multicore.py - launch and supervise several ZigZagFuzz instances in parallel.

ZigZagFuzz builds on AFL++'s -M / -S synchronisation model: one *main* node and
any number of *secondary* nodes share a single output directory and periodically
import each other's finds.  This wrapper spawns one main + (N-1) secondaries for
a target, keeps them running, prints a compact live status table, and shuts the
whole fleet down cleanly on Ctrl-C.

Each instance runs from its own throwaway working directory under $TMPDIR, which
is removed on exit.  ZigZagFuzz mutates the target command line, so the target
tends to create files with arbitrary names in its working directory; this keeps
that clutter out of your own directory.  Findings still go to -o as usual.

Example
-------
    ./zzf-multicore.py -j 4 -i seeds -o out -a keywords.dict -- ./target.afl -v @@
"""

import argparse
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def say(*a, **kw):
    """print() that can never abort us.

    When stdout is a pipe whose reader has already died - `timeout 1h ... | tee
    log` signals the whole process group, so tee goes first - a plain print()
    raises BrokenPipeError.  Raised from the shutdown path, that abandons the
    fleet half-stopped and leaves orphaned instances behind, so every message
    this tool prints goes through here instead."""
    try:
        print(*a, **kw)
        sys.stdout.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass


def parse_args():
    p = argparse.ArgumentParser(
        prog="zzf-multicore.py",
        usage="%(prog)s -j JOBS -i INPUT -o OUTPUT -a DICT [options] "
              "-- TARGET [TARGET_ARGS ...]",
        description="Run several ZigZagFuzz instances in parallel (-M/-S).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="The target command goes after `--`, exactly as you would pass "
        "it to\nafl-fuzz (use @@ for the file-input placeholder). Example:\n\n"
        "  %(prog)s -j 4 -i seeds -o out -a keywords.dict -- ./target.afl -v @@",
    )
    p.add_argument("-j", "--jobs", type=int, required=True,
                   help="number of parallel instances (>=1; 1 main + rest "
                        "secondaries)")
    p.add_argument("-i", "--input", required=True,
                   help="initial seed directory (passed to afl-fuzz -i)")
    p.add_argument("-o", "--output", required=True,
                   help="shared output directory (passed to afl-fuzz -o)")
    p.add_argument("-a", "--dict", required=True,
                   help="argv keyword dictionary (passed to afl-fuzz -a)")
    p.add_argument("--afl-fuzz", default=None,
                   help="path to the afl-fuzz binary (default: the one next to "
                        "this script)")
    p.add_argument("--afl-arg", action="append", default=[], metavar="ARG",
                   help="extra argument forwarded verbatim to every afl-fuzz "
                        "instance; repeatable (e.g. --afl-arg=-K --afl-arg=2)")
    p.add_argument("-V", "--timeout", type=int, default=0,
                   help="stop the whole fleet after this many seconds "
                        "(0 = run until Ctrl-C)")
    p.add_argument("--no-affinity", action="store_true",
                   help="set AFL_NO_AFFINITY=1 so instances are not pinned to "
                        "CPU cores (needed when jobs > free cores)")
    p.add_argument("--status-interval", type=int, default=5,
                   help="seconds between status-table refreshes (0 = quiet)")

    argv = sys.argv[1:]
    if "-h" in argv or "--help" in argv:
        p.parse_args(["-h"])  # prints help and exits
    if "--" not in argv:
        p.error("missing `--`; put the target command after `--`")
    split = argv.index("--")
    ns = p.parse_args(argv[:split])
    ns.target = argv[split + 1:]
    if not ns.target:
        p.error("no target command given after `--`")
    if ns.jobs < 1:
        p.error("--jobs must be >= 1")
    return ns


def resolve_afl_fuzz(path):
    if path:
        cand = os.path.abspath(path)
    else:
        cand = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "afl-fuzz")
    if not (os.path.isfile(cand) and os.access(cand, os.X_OK)):
        sys.exit(f"[!] afl-fuzz binary not found or not executable: {cand}")
    return cand


def resolve_target_exe(exe):
    """Make the target executable path absolute when it refers to a file on
    disk, so it still resolves after we switch each instance's cwd.  A bare
    command name (no path separator) is left untouched for PATH lookup."""
    if os.sep in exe or (os.altsep and os.altsep in exe):
        return os.path.abspath(exe)
    if os.path.isfile(exe):  # e.g. "target.afl" sitting in the current dir
        return os.path.abspath(exe)
    return exe


def instance_names(jobs):
    """Return [main, s01, s02, ...]; the first is the main (-M) node."""
    return ["main"] + [f"s{k:02d}" for k in range(1, jobs)]


def build_cmd(afl_fuzz, args, name, is_main):
    role = "-M" if is_main else "-S"
    cmd = [afl_fuzz, "-i", args.input, "-o", args.output,
           "-a", args.dict, role, name]
    cmd += args.afl_arg
    cmd += ["--"] + args.target
    return cmd


def interruptible_sleep(duration, stop):
    """Sleep, but return early once a shutdown signal has been seen."""
    deadline = time.time() + duration
    while not stop["flag"]:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(0.1, remaining))


def launch(afl_fuzz, args, names, work_root, env, procs, stop):
    """Spawn the instances, appending each to `procs` as soon as it exists.

    `procs` is owned by the caller so that a shutdown signal arriving part-way
    through the staggered startup still finds - and stops - the instances that
    are already running.
    """
    for idx, name in enumerate(names):
        if stop["flag"]:
            say("[*] shutdown requested during startup; "
                "not launching the remaining instances.")
            break
        is_main = idx == 0
        cmd = build_cmd(afl_fuzz, args, name, is_main)
        # Give every instance its own scratch cwd, so junk files the target
        # creates from mutated command lines stay out of the user's directory
        # and cannot collide between instances.
        workdir = os.path.join(work_root, name)
        os.makedirs(workdir, exist_ok=True)
        # ZigZagFuzz prints a status line for every test case when stdout is not
        # a tty, which is tens of MB/s on a real target; we drop it. Live state
        # comes from the status table below, which reads fuzzer_stats.
        # New process group so we can signal the whole tree at shutdown.
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, env=env, cwd=workdir,
                             start_new_session=True)
        procs.append({"name": name, "proc": p, "main": is_main,
                      "workdir": workdir, "cmd": cmd})
        role = "main" if is_main else "secondary"
        say(f"[+] launched {name:>6} ({role}, pid {p.pid})")
        # Stagger startup so the main node creates the sync dir before the
        # secondaries scan it, and to avoid a thundering herd on the target.
        interruptible_sleep(0.5, stop)
    return procs


def read_stats(stats_path):
    stats = {}
    try:
        with open(stats_path) as f:
            for line in f:
                if ":" in line:
                    k, _, v = line.partition(":")
                    stats[k.strip()] = v.strip()
    except OSError:
        return None
    return stats


def print_status(args, procs, start):
    rows = []
    tot_execs = tot_corpus = tot_crashes = tot_hangs = 0
    for e in procs:
        alive = e["proc"].poll() is None
        st = read_stats(os.path.join(args.output, e["name"], "fuzzer_stats"))
        if st:
            eps = st.get("execs_per_sec", "?")
            corpus = st.get("corpus_count", "?")
            imported = st.get("corpus_imported", "?")
            crashes = st.get("saved_crashes", "?")
            hangs = st.get("saved_hangs", "?")
            cvg = st.get("bitmap_cvg", "?")
            try:
                tot_execs += int(st.get("execs_done", 0))
                tot_corpus += int(st.get("corpus_count", 0))
                tot_crashes += int(st.get("saved_crashes", 0))
                tot_hangs += int(st.get("saved_hangs", 0))
            except ValueError:
                pass
        else:
            eps = corpus = imported = crashes = hangs = cvg = "-"
        state = "run" if alive else f"DEAD({e['proc'].returncode})"
        rows.append((e["name"], state, eps, corpus, imported, crashes, hangs,
                     cvg))

    elapsed = int(time.time() - start)
    say()
    say(f"=== ZigZagFuzz fleet | {len(procs)} instances | "
        f"elapsed {elapsed//3600:02d}:{elapsed%3600//60:02d}:{elapsed%60:02d} "
        f"| total execs {tot_execs} | corpus {tot_corpus} | "
        f"crashes {tot_crashes} | hangs {tot_hangs}")
    say(f"    output: {args.output}")
    hdr = ("instance", "state", "exec/s", "corpus", "imp", "crash", "hang",
           "cvg")
    say("  {:<10}{:<12}{:>10}{:>8}{:>6}{:>7}{:>6}{:>9}".format(*hdr))
    for r in rows:
        say("  {:<10}{:<12}{:>10}{:>8}{:>6}{:>7}{:>6}{:>9}".format(*r))


def descendant_pids(pid):
    """Best-effort list of a process' descendants, via /proc.  Used to reach the
    target tree, which the forkserver puts in a session of its own."""
    out = []
    pending = [pid]
    while pending:
        cur = pending.pop()
        try:
            with open(f"/proc/{cur}/task/{cur}/children") as f:
                kids = [int(p) for p in f.read().split()]
        except (OSError, ValueError):
            continue
        out += kids
        pending += kids
    return out


def shutdown(procs, stop=None):
    if not procs:
        return
    say("\n[*] stopping fleet (SIGINT, letting instances flush stats)...")
    for e in procs:
        if e["proc"].poll() is None:
            try:
                # Signal the whole session group; afl-fuzz handles SIGINT by
                # writing out final stats and exiting.
                os.killpg(os.getpgid(e["proc"].pid), signal.SIGINT)
            except (ProcessLookupError, PermissionError):
                pass
    # Give them a moment to exit cleanly, then hard-kill stragglers. A repeated
    # signal (impatient Ctrl-C, or timeout's -k follow-up) cuts the grace short
    # rather than being swallowed while we wait.
    signals_seen = stop["count"] if stop else 0
    deadline = time.time() + 15
    while time.time() < deadline:
        if all(e["proc"].poll() is not None for e in procs):
            break
        if stop and stop["count"] > signals_seen:
            say("[*] second signal received; not waiting any longer.")
            break
        time.sleep(0.1)
    for e in procs:
        if e["proc"].poll() is None:
            say(f"[!] force killing {e['name']} (pid {e['proc'].pid})")
            # The forkserver calls setsid() (see afl-forkserver.c), so the
            # target tree lives in its own session and killpg on the instance
            # does not reach it. Collect the descendants first, then kill the
            # instance's group, then mop up whatever the instance would have
            # cleaned up had it exited on its own.
            descendants = descendant_pids(e["proc"].pid)
            try:
                os.killpg(os.getpgid(e["proc"].pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            for pid in descendants:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
    # Reap, so we do not leave zombies behind for the rest of our own lifetime.
    for e in procs:
        try:
            e["proc"].wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    say("[+] all instances stopped.")


def main():
    args = parse_args()
    afl_fuzz = resolve_afl_fuzz(args.afl_fuzz)
    names = instance_names(args.jobs)

    # Because each instance runs from its own scratch cwd (see launch()), every
    # path we hand to afl-fuzz must be absolute or it would resolve against the
    # wrong directory.
    args.input = os.path.abspath(args.input)
    args.output = os.path.abspath(args.output)
    args.dict = os.path.abspath(args.dict)
    args.target = [resolve_target_exe(args.target[0])] + args.target[1:]

    os.makedirs(args.output, exist_ok=True)
    work_root = tempfile.mkdtemp(prefix="zzf-multicore-")

    env = os.environ.copy()
    # The wrapper owns the terminal; instances must not draw the interactive UI.
    env["AFL_NO_UI"] = "1"
    if args.no_affinity:
        env["AFL_NO_AFFINITY"] = "1"

    say(f"[*] afl-fuzz : {afl_fuzz}")
    say(f"[*] target   : {' '.join(args.target)}")
    say(f"[*] output   : {args.output}")
    say(f"[*] work dir : {work_root}  (temporary, removed on exit)")
    say(f"[*] launching {args.jobs} instance(s): "
        f"1 main + {args.jobs - 1} secondary\n")

    procs = []
    stop = {"flag": False, "count": 0}

    def on_signal(signum, frame):
        stop["flag"] = True
        stop["count"] += 1

    # Install the handlers *before* the first instance is spawned. Until they
    # are in place SIGTERM/SIGINT have their default disposition, so a signal
    # arriving during the staggered startup (0.5s per instance, plus the probe
    # below - seconds of exposure at high -j) kills this process outright: the
    # cleanup path never runs and every instance launched so far is orphaned,
    # reparented to init, and keeps fuzzing forever. That is exactly what
    # `timeout ... ./zzf-multicore.py` used to do.
    for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(_sig, on_signal)

    start = time.time()
    fuzzing = False

    try:
        launch(afl_fuzz, args, names, work_root, env, procs, stop)
        start = time.time()

        # If the main node dies immediately (bad args, missing dict, ...), say so
        # and abort rather than leaving orphan secondaries running. Instance
        # output is discarded, so hand back the command to reproduce the error.
        interruptible_sleep(1.0, stop)
        if stop["flag"]:
            say("\n[*] shutdown requested before fuzzing started.")
            return
        main_proc = procs[0]["proc"]
        if main_proc.poll() is not None:
            say(f"\n[!] main node exited early (rc={main_proc.returncode}). "
                f"Run it directly to see why:\n\n"
                f"    {shlex.join(procs[0]['cmd'])}\n")
            sys.exit(1)
        fuzzing = True

        last_status = 0.0
        while not stop["flag"]:
            interruptible_sleep(0.5, stop)
            now = time.time()

            if args.timeout and now - start >= args.timeout:
                say(f"\n[*] timeout of {args.timeout}s reached.")
                break

            if (args.status_interval
                    and now - last_status >= args.status_interval):
                print_status(args, procs, start)
                last_status = now

            if all(e["proc"].poll() is not None for e in procs):
                say("\n[*] all instances have exited.")
                break
    finally:
        shutdown(procs, stop)
        if fuzzing and args.status_interval:
            print_status(args, procs, start)
        shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    main()
