"""Blind vs coverage-guided vs guided+dictionary on the planted-bug targets.

Usage: python benchmarks/compare.py [--trials 10] [--budget 60000]
Each trial uses a different RNG seed; a trial "succeeds" if it finds any crash
within the execution budget.
"""
import argparse
import os
import statistics
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
from fuzzforge import Fuzzer, harvest_dictionary, load_target  # noqa: E402

TARGETS = [
    ("demo_parser", "targets/demo_parser.py:parse_packet", [b"AAAAAAAA"]),
    ("mini_json", "targets/mini_json.py:fuzz_json", [b'{"a": [1, 2, "x"]}']),
]
MODES = [("blind", False, False), ("guided", True, False), ("guided+dict", True, True)]


def trial(spec, seeds, guided, use_dict, rng_seed, budget):
    target, files = load_target(os.path.join(ROOT, spec.split(":")[0]) + ":" + spec.split(":")[1])
    d = harvest_dictionary(target) if use_dict else []
    fz = Fuzzer(target, files, seeds=seeds, rng_seed=rng_seed, guided=guided, dictionary=d)
    st = fz.run(max_execs=budget, stop_on_crash=True)
    return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--budget", type=int, default=60_000)
    a = ap.parse_args()
    print(f"| target | mode | found bug | median execs to bug | median edges covered |")
    print(f"|---|---|---|---|---|")
    for name, spec, seeds in TARGETS:
        for mode, guided, use_dict in MODES:
            found, execs, edges = 0, [], []
            for t in range(a.trials):
                st = trial(spec, seeds, guided, use_dict, t, a.budget)
                edges.append(st.edges)
                if st.crashes:
                    found += 1
                    execs.append(st.first_crash_exec)
            med = f"{int(statistics.median(execs)):,}" if execs else "n/a"
            print(f"| {name} | {mode} | {found}/{a.trials} | {med} | {int(statistics.median(edges))} |")


if __name__ == "__main__":
    main()
