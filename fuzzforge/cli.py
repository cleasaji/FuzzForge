"""Command-line interface: run / replay / minimize."""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import List

from .coverage import Tracer
from .engine import Fuzzer, Stats
from .loader import load_target
from .minimize import minimize_crash
from .mutators import harvest_dictionary


def _read_seeds(path: str) -> List[bytes]:
    if not path:
        return []
    files = [path] if os.path.isfile(path) else sorted(glob.glob(os.path.join(path, "*")))
    out = []
    for f in files:
        if os.path.isfile(f):
            with open(f, "rb") as fh:
                out.append(fh.read())
    return out


def _cmd_run(a) -> int:
    target, files = load_target(a.target, a.include or [])
    dictionary = [] if a.no_dict else harvest_dictionary(target)
    if a.dict:
        with open(a.dict, "rb") as fh:
            dictionary += [l.rstrip(b"\n") for l in fh.read().split(b"\n") if l.strip()]

    def progress(f: Fuzzer):
        s = f.stats
        print(f"\r[{s.elapsed:6.1f}s] execs={s.execs:<8} ({s.execs_per_sec:,.0f}/s) "
              f"corpus={len(f.corpus):<4} edges={s.edges:<4} crashes={len(s.crashes)} "
              f"hangs={s.hangs}", end="", file=sys.stderr, flush=True)

    fz = Fuzzer(target, files, seeds=_read_seeds(a.seeds), out_dir=a.out,
                rng_seed=a.seed, max_len=a.max_len, dictionary=dictionary,
                guided=not a.blind, max_events=a.max_events,
                on_progress=None if a.quiet else progress)
    try:
        stats = fz.run(max_time=a.time, max_execs=a.execs, stop_on_crash=a.stop_on_crash)
    except KeyboardInterrupt:
        stats = fz._finish()
    print(file=sys.stderr)

    if a.minimize:
        tr = Tracer(files, max_events=a.max_events)
        for c in stats.crashes.values():
            c.data = minimize_crash(target, tr, c.data, c.signature)
            fz._persist(c)

    mode = "blind (no feedback)" if a.blind else "coverage-guided"
    print(f"\nFuzzForge finished [{mode}]")
    print(f"  executions : {stats.execs:,} in {stats.elapsed:.1f}s ({stats.execs_per_sec:,.0f}/s)")
    print(f"  coverage   : {stats.edges} edges, {stats.features} features, corpus={stats.corpus_size}")
    print(f"  findings   : {len(stats.crashes)} unique crash(es), {stats.hangs} hang(s)")
    for sig, c in stats.crashes.items():
        print(f"    - {sig}  len={len(c.data)}  hits={c.hits}  "
              f"first@exec {c.found_at_exec:,}  input={c.data[:48]!r}")
    return 1 if stats.crashes else 0


def _cmd_replay(a) -> int:
    target, files = load_target(a.target, a.include or [])
    with open(a.input, "rb") as fh:
        data = fh.read()
    res = Tracer(files, max_events=a.max_events).run(target, data)
    if res.exc_type is None:
        print("no crash: target returned normally")
        return 0
    print(f"{res.signature}")
    if res.traceback:
        print(res.traceback)
    return 1


def _cmd_minimize(a) -> int:
    target, files = load_target(a.target, a.include or [])
    with open(a.input, "rb") as fh:
        data = fh.read()
    tr = Tracer(files, max_events=a.max_events)
    sig = tr.run(target, data).signature
    if sig is None:
        print("input does not crash the target", file=sys.stderr)
        return 2
    small = minimize_crash(target, tr, data, sig)
    out = a.output or a.input + ".min"
    with open(out, "wb") as fh:
        fh.write(small)
    print(f"{sig}: {len(data)} -> {len(small)} bytes, wrote {out}  ({small!r})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fuzzforge", description="Coverage-guided fuzzer for Python")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("target", help="file.py:function or module:function (takes bytes)")
        sp.add_argument("--include", action="append", help="extra source file to instrument")
        sp.add_argument("--max-events", type=int, default=200_000,
                        help="line-event budget per execution before it counts as a hang")

    r = sub.add_parser("run", help="fuzz a target")
    common(r)
    r.add_argument("--seeds", help="seed file or directory")
    r.add_argument("--out", default="fuzz-out", help="output directory")
    r.add_argument("--time", type=float, help="time budget in seconds")
    r.add_argument("--execs", type=int, help="execution budget")
    r.add_argument("--seed", type=int, help="RNG seed for reproducible campaigns")
    r.add_argument("--max-len", type=int, default=1024)
    r.add_argument("--dict", help="file of tokens, one per line")
    r.add_argument("--no-dict", action="store_true", help="skip auto-harvesting code constants")
    r.add_argument("--blind", action="store_true", help="disable coverage feedback (baseline)")
    r.add_argument("--minimize", action="store_true", help="minimize crashes after the run")
    r.add_argument("--stop-on-crash", action="store_true")
    r.add_argument("--quiet", action="store_true")
    r.set_defaults(fn=_cmd_run)

    rp = sub.add_parser("replay", help="re-run one input against the target")
    common(rp)
    rp.add_argument("input")
    rp.set_defaults(fn=_cmd_replay)

    m = sub.add_parser("minimize", help="shrink a crashing input")
    common(m)
    m.add_argument("input")
    m.add_argument("-o", "--output")
    m.set_defaults(fn=_cmd_minimize)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "run" and args.time is None and args.execs is None:
        args.time = 10.0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
