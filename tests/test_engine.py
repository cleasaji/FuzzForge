import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fuzzforge import Fuzzer, load_target, minimize_crash, Tracer

ROOT = os.path.join(os.path.dirname(__file__), "..")
PARSER = os.path.join(ROOT, "targets", "demo_parser.py") + ":parse_packet"
HANG = os.path.join(ROOT, "targets", "hang_target.py") + ":tokenize"
JSON = os.path.join(ROOT, "targets", "mini_json.py") + ":fuzz_json"


def test_guided_finds_bug_behind_magic_without_dictionary():
    target, files = load_target(PARSER)
    fz = Fuzzer(target, files, seeds=[b"AAAAAAAA"], rng_seed=1)
    stats = fz.run(max_execs=150_000, stop_on_crash=True)
    assert stats.crashes, "coverage-guided fuzzing should reach the planted bug"
    assert any(s.startswith(("IndexError", "ZeroDivisionError")) for s in stats.crashes)


def test_blind_mode_does_not_get_past_the_magic():
    target, files = load_target(PARSER)
    fz = Fuzzer(target, files, seeds=[b"AAAAAAAA"], rng_seed=1, guided=False)
    stats = fz.run(max_execs=30_000)
    assert not stats.crashes


def test_guided_coverage_exceeds_blind_coverage():
    target, files = load_target(PARSER)
    g = Fuzzer(target, files, seeds=[b"AAAAAAAA"], rng_seed=4).run(max_execs=30_000)
    b = Fuzzer(target, files, seeds=[b"AAAAAAAA"], rng_seed=4, guided=False).run(max_execs=30_000)
    assert g.edges > b.edges


def test_same_rng_seed_is_reproducible():
    target, files = load_target(PARSER)
    runs = [Fuzzer(target, files, seeds=[b"AAAAAAAA"], rng_seed=7).run(max_execs=5000) for _ in range(2)]
    assert runs[0].edges == runs[1].edges and runs[0].corpus_size == runs[1].corpus_size


def test_hang_is_reported_not_stuck():
    target, files = load_target(HANG)
    stats = Fuzzer(target, files, rng_seed=2, max_events=5000).run(max_time=20, stop_on_crash=True)
    assert "Hang" in stats.crashes and stats.hangs >= 1


def test_crashes_are_deduplicated_by_signature():
    target, files = load_target(PARSER)
    stats = Fuzzer(target, files, seeds=[b"AAAAAAAA"], rng_seed=3).run(max_execs=120_000)
    assert len(stats.crashes) <= 2
    assert sum(c.hits for c in stats.crashes.values()) >= len(stats.crashes)


def test_minimizer_shrinks_and_preserves_signature():
    target, files = load_target(PARSER)
    tr = Tracer(files)
    big = b"FUZZ\x02\x01\x00\x00\x00" + b"junk" * 40
    sig = tr.run(target, big).signature
    assert sig and sig.startswith("ZeroDivisionError")
    small = minimize_crash(target, tr, big, sig)
    assert len(small) <= 9 and tr.run(target, small).signature == sig


def test_findings_are_persisted(tmp_path):
    target, files = load_target(JSON)
    out = tmp_path / "out"
    Fuzzer(target, files, seeds=[b'{"a": 1}'], out_dir=str(out), rng_seed=5).run(max_execs=20_000)
    assert (out / "stats.json").exists()
    assert any((out / "crashes").iterdir())
    assert any((out / "corpus").iterdir())
