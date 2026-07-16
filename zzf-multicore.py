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


def launch(afl_fuzz, args, names, work_root, env):
    procs = []
    for idx, name in enumerate(names):
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
        print(f"[+] launched {name:>6} ({role}, pid {p.pid})")
        # Stagger startup so the main node creates the sync dir before the
        # secondaries scan it, and to avoid a thundering herd on the target.
        time.sleep(0.5)
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
    print()
    print(f"=== ZigZagFuzz fleet | {len(procs)} instances | "
          f"elapsed {elapsed//3600:02d}:{elapsed%3600//60:02d}:{elapsed%60:02d} "
          f"| total execs {tot_execs} | corpus {tot_corpus} | "
          f"crashes {tot_crashes} | hangs {tot_hangs}")
    print(f"    output: {args.output}")
    hdr = ("instance", "state", "exec/s", "corpus", "imp", "crash", "hang",
           "cvg")
    print("  {:<10}{:<12}{:>10}{:>8}{:>6}{:>7}{:>6}{:>9}".format(*hdr))
    for r in rows:
        print("  {:<10}{:<12}{:>10}{:>8}{:>6}{:>7}{:>6}{:>9}".format(*r))


def shutdown(procs):
    print("\n[*] stopping fleet (SIGINT, letting instances flush stats)...")
    for e in procs:
        if e["proc"].poll() is None:
            try:
                # Signal the whole session group; afl-fuzz handles SIGINT by
                # writing out final stats and exiting.
                os.killpg(os.getpgid(e["proc"].pid), signal.SIGINT)
            except (ProcessLookupError, PermissionError):
                pass
    # Give them a moment to exit cleanly, then hard-kill stragglers.
    deadline = time.time() + 15
    for e in procs:
        remaining = max(0.0, deadline - time.time())
        try:
            e["proc"].wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            pass
    for e in procs:
        if e["proc"].poll() is None:
            print(f"[!] force killing {e['name']} (pid {e['proc'].pid})")
            try:
                os.killpg(os.getpgid(e["proc"].pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    print("[+] all instances stopped.")


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

    print(f"[*] afl-fuzz : {afl_fuzz}")
    print(f"[*] target   : {' '.join(args.target)}")
    print(f"[*] output   : {args.output}")
    print(f"[*] work dir : {work_root}  (temporary, removed on exit)")
    print(f"[*] launching {args.jobs} instance(s): "
          f"1 main + {args.jobs - 1} secondary\n")

    procs = launch(afl_fuzz, args, names, work_root, env)
    start = time.time()
    fuzzing = False

    try:
        # If the main node dies immediately (bad args, missing dict, ...), say so
        # and abort rather than leaving orphan secondaries running. Instance
        # output is discarded, so hand back the command to reproduce the error.
        time.sleep(1.0)
        main_proc = procs[0]["proc"]
        if main_proc.poll() is not None:
            print(f"\n[!] main node exited early (rc={main_proc.returncode}). "
                  f"Run it directly to see why:\n\n"
                  f"    {shlex.join(procs[0]['cmd'])}\n")
            sys.exit(1)
        fuzzing = True

        stop = {"flag": False}

        def on_signal(signum, frame):
            stop["flag"] = True

        signal.signal(signal.SIGINT, on_signal)
        signal.signal(signal.SIGTERM, on_signal)

        last_status = 0.0
        while not stop["flag"]:
            time.sleep(0.5)
            now = time.time()

            if args.timeout and now - start >= args.timeout:
                print(f"\n[*] timeout of {args.timeout}s reached.")
                break

            if (args.status_interval
                    and now - last_status >= args.status_interval):
                print_status(args, procs, start)
                last_status = now

            if all(e["proc"].poll() is not None for e in procs):
                print("\n[*] all instances have exited.")
                break
    finally:
        shutdown(procs)
        if fuzzing and args.status_interval:
            print_status(args, procs, start)
        shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    main()
