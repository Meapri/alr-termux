#!/usr/bin/env python3
"""Regression gate — docs/07-acceptance.md §3.

The invariant that matters most is one line:

    supervisor.syscall_stops == 0

If that ever becomes non-zero somebody introduced PTRACE_SYSCALL, and at that
moment this product IS PRoot -- every performance claim in the repo is void.
The whole gate exists to make that impossible to merge quietly.

WHAT THIS DOES NOT DO, deliberately: it measures nothing.  Runtime invariants
can only come from a real Android app process (uid>=10000, Seccomp==2), and a
hosted CI runner is not one -- adb shell reports Seccomp: 0 and would turn every
gate into a false PASS.  So the device harnesses emit facts and this consumes
them.  Build-side invariants it can check itself, because they are properties of
the artifact rather than of a running system.

    # on the device
    ./scripts/dev-push.sh accept | tee accept.txt
    ./scripts/dev-push.sh bench-ab | tee bench.txt
    ./scripts/dev-push.sh bench    | tee rw.txt

    # anywhere
    bench/regression_gate.py --from accept.txt bench.txt rw.txt
    bench/regression_gate.py --build-only          # CI, no device output

Baselines live in bench/baseline.json.  --update rewrites them; nothing writes
them implicitly, because a gate that moves its own goalposts is not a gate.
"""

import argparse
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(REPO, "bench", "baseline.json")

# ── hard invariants (docs/07 §3) ─────────────────────────────────────────────
HARD = [
    ("supervisor.syscall_stops", "== 0", lambda v: v == 0),
    ("supervisor.path_traps", "== 0", lambda v: v == 0),
    ("preload.rw_abs_ns", "<= 100", lambda v: v <= 100),
    ("preload.rw_rel_ns", "<= 20", lambda v: v <= 20),
    ("preload.glibc_verneed_max", '== "2.17"', lambda v: v == "2.17"),
]

# preload.malloc_calls is specified as a hard invariant and NOTHING measures it.
# It is listed here so the gap is visible in the gate's own output rather than
# only in a doc footnote.  Do not quietly drop it to make the gate green.
UNENFORCED = [
    ("preload.malloc_calls", "== 0",
     "no runner counts allocations on the rewrite path; R1 is held by code "
     "review only, and getaddrinfo is a documented exception"),
]

SOFT = [
    ("git_status_10k_ms", 1.10),
    ("npm_ci_ms", 1.10),
    ("node_cold_ms", 1.10),
    ("exec_per_sec", None),      # higher is better; handled separately
]

PAT = {
    "supervisor.syscall_stops": r"syscall_stops=(\d+)",
    "supervisor.path_traps": r"path_traps=(\d+)",
    # rw_cost.c prints "PRELOAD RW ABS COST   61.0 ns  <=  100  PASS" -- aligned
    # columns, no colon.  An earlier pattern assumed the colon form used in
    # docs/07 §2 and matched nothing, which the gate correctly reported as
    # ABSENT rather than passing on facts it never saw.
    "preload.rw_abs_ns": r"PRELOAD RW ABS COST\s+([\d.]+)\s*ns",
    "preload.rw_rel_ns": r"PRELOAD RW REL COST\s+([\d.]+)\s*ns",
    "node_cold_ms": r"ALR BENCH NODE COLD vs PROOT:.*?alr\s+(\d+)\s*/",
    "exec_per_sec": r"ALR BENCH EXEC THROUGHPUT:\s*(\d+)\s*exec/s",
}


def scrape(paths):
    """Pull facts out of harness output.  Absent is absent -- never defaulted."""
    blob = ""
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                blob += f.read() + "\n"
        except OSError as e:
            die("cannot read %s: %s" % (p, e))
    out = {}
    for key, pat in PAT.items():
        hits = re.findall(pat, blob, re.S)
        if not hits:
            continue
        # syscall_stops/path_traps appear once per run; the gate must see the
        # WORST value, not the last one printed.
        vals = [float(h) for h in hits]
        out[key] = max(vals) if key.startswith("supervisor.") else vals[-1]
        if key.startswith("supervisor.") or key == "exec_per_sec":
            out[key] = int(out[key])
    return out


def build_facts():
    """Artifact properties, checkable without a device."""
    so = os.path.join(REPO, "build", "libalr_preload.so")
    if not os.path.exists(so):
        return {}, ["build/libalr_preload.so absent; run scripts/build-preload.sh"]
    objdump = os.environ.get("OBJDUMP", "objdump")
    try:
        p = subprocess.run([objdump, "-p", so], capture_output=True, text=True,
                           check=False)
    except FileNotFoundError:
        return {}, ["%s not found; cannot read the ELF" % objdump]
    if p.returncode != 0:
        return {}, ["%s -p failed on the .so" % objdump]
    vers = sorted(set(re.findall(r"GLIBC_(\d+\.\d+)", p.stdout)),
                  key=lambda v: tuple(int(x) for x in v.split(".")))
    if not vers:
        return {}, ["no GLIBC_ version references found; is this the right file?"]
    return {"preload.glibc_verneed_max": vers[-1]}, []


def die(msg):
    print("regression_gate: %s" % msg, file=sys.stderr)
    sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="inputs", nargs="*", default=[],
                    help="harness output files to scrape")
    ap.add_argument("--build-only", action="store_true",
                    help="check artifact invariants only (CI, no device)")
    ap.add_argument("--update", action="store_true",
                    help="rewrite bench/baseline.json from these facts")
    args = ap.parse_args()

    facts, notes = build_facts()
    if not args.build_only:
        if not args.inputs:
            die("no harness output given. Pass --from <files>, or --build-only "
                "if you have no device output. Refusing to pass a gate on "
                "facts it never saw.")
        facts.update(scrape(args.inputs))

    baseline = {}
    if os.path.exists(BASELINE):
        try:
            with open(BASELINE, encoding="utf-8") as f:
                baseline = json.load(f)
        except (OSError, ValueError) as e:
            die("baseline unreadable: %s" % e)

    print("── regression gate ─────────────────────────────────────────")
    for n in notes:
        print("  NOTE  %s" % n)

    failed = warned = checked = 0

    for key, desc, ok in HARD:
        if key not in facts:
            # Missing is NOT pass.  A gate that silently skips what it cannot
            # see reports green on an empty file.
            if args.build_only and not key.startswith("preload.glibc"):
                print("  %-28s SKIP    build-only run" % key)
            else:
                print("  %-28s ABSENT  not in the given output" % key)
                failed += 1
            continue
        checked += 1
        v = facts[key]
        if ok(v):
            print("  %-28s PASS    %s (%s)" % (key, v, desc))
        else:
            print("  %-28s FAIL    %s, want %s" % (key, v, desc))
            failed += 1
            if key == "supervisor.syscall_stops":
                print("        ^ PTRACE_SYSCALL is back. This is PRoot's model;")
                print("          every performance claim in the repo is void.")

    for key, desc, why in UNENFORCED:
        print("  %-28s UNENFORCED  %s" % (key, why))

    for key, tol in SOFT:
        if key not in facts:
            continue
        prev = baseline.get(key)
        v = facts[key]
        if prev is None:
            print("  %-28s BASELINE  %s (no previous value)" % (key, v))
            continue
        if tol is None:                       # higher is better
            if v < prev * 0.90:
                print("  %-28s WARN    %s < %s*0.90" % (key, v, prev))
                warned += 1
            else:
                print("  %-28s ok      %s (prev %s)" % (key, v, prev))
        elif v > prev * tol:
            print("  %-28s WARN    %s > %s*%.2f" % (key, v, prev, tol))
            warned += 1
        else:
            print("  %-28s ok      %s (prev %s)" % (key, v, prev))

    if args.update:
        keep = {k: facts[k] for k, _ in SOFT if k in facts}
        with open(BASELINE, "w", encoding="utf-8") as f:
            json.dump(keep, f, indent=2, sort_keys=True)
            f.write("\n")
        print("  baseline written: %s" % BASELINE)

    print("────────────────────────────────────────────────────────────")
    print("  hard checked=%d failed=%d   soft warnings=%d" % (checked, failed, warned))
    print("ALR REGRESSION GATE: %s" % ("FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
