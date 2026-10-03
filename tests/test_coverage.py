import os
from fuzzforge.coverage import Tracer, bucket, ExecutionTimeout

HERE = os.path.dirname(__file__)


def make_target():
    ns = {}
    src = "def t(d):\n    if d and d[0] == 1:\n        return 'one'\n    return 'other'\n"
    path = os.path.join(HERE, "_gen_target.py")
    with open(path, "w") as fh:
        fh.write(src)
    code = compile(src, path, "exec")
    exec(code, ns)
    return ns["t"], path


def test_distinct_paths_give_distinct_features():
    t, path = make_target()
    tr = Tracer([path])
    a = tr.run(t, b"\x01")
    b = tr.run(t, b"\x02")
    assert a.features != b.features
    assert a.signature is None and not a.crashed


def test_same_input_is_deterministic():
    t, path = make_target()
    tr = Tracer([path])
    assert tr.run(t, b"\x01").features == tr.run(t, b"\x01").features


def test_crash_signature_and_dedup_key():
    def boom(d):
        raise ValueError("x")
    res = Tracer([__file__]).run(boom, b"")
    assert res.crashed and res.exc_type == "ValueError"
    assert res.signature.startswith("ValueError@")


def test_hang_detected_even_if_target_swallows_exceptions():
    def spin(d):
        while True:
            try:
                pass
            except Exception:
                pass
    res = Tracer([__file__], max_events=500).run(spin, b"")
    assert res.hung and res.signature == "Hang"


def test_buckets_monotonic():
    vals = [bucket(n) for n in (1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 127, 128, 5000)]
    assert vals == sorted(vals) and len(set(vals)) == 8
