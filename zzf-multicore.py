#!/usr/bin/env python3
"""
zzf-multicore.py - launch and supervise several ZigZagFuzz instances in parallel.

ZigZagFuzz builds on AFL++'s -M / -S synchronisation model: one *main* node and
any number of *secondary* nodes share a single output directory and periodically
import each other's finds.  This wrapper spawns one main + (N-1) secondaries for
a target, keeps them running, prints a compact live status table, and shuts the
whole fleet down cleanly on Ctrl-C.

Example
-------
    ./zzf-multicore.py -j 4 -i seeds -o out -a paper_exp/keyword_dict/foo.dict \\
        -- ./target.afl -v @@

Everything after `--` is the target command line exactly as you would pass it to
afl-fuzz (use `@@` for the file-input placeholder).  ZigZagFuzz-specific flags
such as -K (interleaving) and -C (combined argv/file mode) can be forwarded with
--afl-arg, e.g.  --afl-arg=-K --afl-arg=2 .
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

# Reserved -M/-S names that ZigZagFuzz/AFL++ refuse or treat specially.
RESERVED_IDS = {"addseeds", "default"}


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
    p.add_argument("--name", default="zzf",
                   help="prefix for the -M/-S instance names (default: zzf)")
    p.add_argument("-V", "--timeout", type=int, default=0,
                   help="stop the whole fleet after this many seconds "
                        "(0 = run until Ctrl-C)")
    p.add_argument("--no-affinity", action="store_true",
                   help="set AFL_NO_AFFINITY=1 so instances are not pinned to "
                        "CPU cores (needed when jobs > free cores)")
    p.add_argument("--work-dir", default=None,
                   help="parent directory in which to create the per-instance "
                        "scratch working directories (default: a fresh temp "
                        "dir under $TMPDIR)")
    p.add_argument("--keep-work", action="store_true",
                   help="do not delete the scratch working directories on exit "
                        "(default: they are removed)")
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


def instance_names(prefix, jobs):
    """Return [main, sec01, sec02, ...]; the first is the main (-M) node."""
    names = [f"{prefix}-main"]
    for k in range(1, jobs):
        names.append(f"{prefix}-s{k:02d}")
    for n in names:
        if n in RESERVED_IDS:
            sys.exit(f"[!] instance name '{n}' is reserved, pick another --name")
    return names


def build_cmd(afl_fuzz, args, name, is_main):
    role = "-M" if is_main else "-S"
    cmd = [afl_fuzz, "-i", args.input, "-o", args.output,
           "-a", args.dict, role, name]
    cmd += args.afl_arg
    cmd += ["--"] + args.target
    return cmd


def launch(afl_fuzz, args, names, logdir, work_root, env):
    procs = []
    for idx, name in enumerate(names):
        is_main = idx == 0
        cmd = build_cmd(afl_fuzz, args, name, is_main)
        logpath = os.path.join(logdir, f"{name}.log")
        logf = open(logpath, "wb")
        # Give every instance its own scratch cwd. ZigZagFuzz mutates the target
        # command line, so the target may create files with arbitrary names in
        # its working directory; running there keeps that clutter out of the
        # user's directory and lets us clean it up afterwards. afl-fuzz's own
        # state still lives under -o, which we pass as an absolute path.
        workdir = os.path.join(work_root, name)
        os.makedirs(workdir, exist_ok=True)
        # New process group so we can signal the whole tree at shutdown.
        p = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, env=env, cwd=workdir,
                             start_new_session=True)
        procs.append({"name": name, "proc": p, "log": logpath, "logf": logf,
                      "main": is_main, "workdir": workdir})
        role = "main" if is_main else "secondary"
        print(f"[+] launched {name:>12} ({role}, pid {p.pid}) -> {logpath}")
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
    os.write(1, b"\n")
    print(f"=== ZigZagFuzz fleet | {len(procs)} instances | "
          f"elapsed {elapsed//3600:02d}:{elapsed%3600//60:02d}:{elapsed%60:02d} "
          f"| total execs {tot_execs} | corpus {tot_corpus} | "
          f"crashes {tot_crashes} | hangs {tot_hangs}")
    hdr = ("instance", "state", "exec/s", "corpus", "imp", "crash", "hang",
           "cvg")
    print("  {:<14}{:<12}{:>10}{:>8}{:>6}{:>7}{:>6}{:>9}".format(*hdr))
    for r in rows:
        print("  {:<14}{:<12}{:>10}{:>8}{:>6}{:>7}{:>6}{:>9}".format(*r))


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
    for e in procs:
        try:
            e["logf"].close()
        except Exception:
            pass
    print("[+] all instances stopped.")


def cleanup_work(work_root, own_temp, keep):
    """Remove the scratch working directories unless the user asked to keep
    them. Only auto-created temp roots are deleted; a user-supplied --work-dir
    is left in place."""
    if keep or not own_temp:
        if work_root:
            print(f"[*] scratch working dirs left in {work_root}")
        return
    try:
        shutil.rmtree(work_root)
    except OSError as e:
        print(f"[!] could not remove scratch dir {work_root}: {e}")


def main():
    args = parse_args()
    afl_fuzz = resolve_afl_fuzz(args.afl_fuzz)
    names = instance_names(args.name, args.jobs)

    # Because each instance runs from its own scratch cwd (see launch()), every
    # path we hand to afl-fuzz must be absolute or it would resolve against the
    # wrong directory.
    args.input = os.path.abspath(args.input)
    args.output = os.path.abspath(args.output)
    args.dict = os.path.abspath(args.dict)
    args.target = [resolve_target_exe(args.target[0])] + args.target[1:]

    os.makedirs(args.output, exist_ok=True)
    logdir = os.path.join(args.output, "zzf-multicore-logs")
    os.makedirs(logdir, exist_ok=True)

    # Scratch working directories for the fuzzed targets. A fresh temp dir by
    # default, so junk files from mutated command lines never touch the user's
    # directory; --work-dir overrides the location and is never auto-deleted.
    if args.work_dir:
        work_root = os.path.abspath(args.work_dir)
        os.makedirs(work_root, exist_ok=True)
        own_temp = False
    else:
        work_root = tempfile.mkdtemp(prefix="zzf-multicore-")
        own_temp = True

    env = os.environ.copy()
    # The wrapper owns the terminal; instances must not draw the interactive UI.
    env["AFL_NO_UI"] = "1"
    if args.no_affinity:
        env["AFL_NO_AFFINITY"] = "1"

    print(f"[*] afl-fuzz : {afl_fuzz}")
    print(f"[*] target   : {' '.join(args.target)}")
    print(f"[*] output   : {args.output}  (logs in {logdir})")
    print(f"[*] work dir : {work_root}"
          f"{'  (temporary, removed on exit)' if own_temp else ''}")
    print(f"[*] launching {args.jobs} instance(s): "
          f"1 main + {args.jobs - 1} secondary\n")

    procs = launch(afl_fuzz, args, names, logdir, work_root, env)

    # If the main node dies immediately (bad args, missing dict, ...), surface
    # its log and abort rather than leaving orphan secondaries running.
    time.sleep(1.0)
    main_proc = procs[0]["proc"]
    if main_proc.poll() is not None:
        print(f"\n[!] main node exited early (rc={main_proc.returncode}); "
              f"tail of {procs[0]['log']}:\n")
        with open(procs[0]["log"], "rb") as f:
            sys.stdout.buffer.write(f.read()[-2000:])
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
        shutdown(procs)
        cleanup_work(work_root, own_temp, args.keep_work)
        sys.exit(1)

    start = time.time()
    stop = {"flag": False}

    def on_signal(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
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
        if args.status_interval:
            print_status(args, procs, start)
        cleanup_work(work_root, own_temp, args.keep_work)


if __name__ == "__main__":
    main()
