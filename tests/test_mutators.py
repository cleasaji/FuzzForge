import random
from fuzzforge.mutators import Mutator, harvest_dictionary


def test_havoc_respects_max_len_and_non_empty():
    m = Mutator(random.Random(0), max_len=16)
    data = b"A" * 16
    for _ in range(2000):
        out = m.havoc(data)
        assert 1 <= len(out) <= 16
        data = out


def test_havoc_actually_mutates():
    m = Mutator(random.Random(1))
    outs = {m.havoc(b"hello world") for _ in range(200)}
    assert len(outs) > 50


def test_dictionary_tokens_get_used():
    m = Mutator(random.Random(2), dictionary=[b"MAGIC"])
    assert any(b"MAGIC" in m.havoc(b"xxxxxxxxxx") for _ in range(500))


def test_splice_combines_inputs():
    m = Mutator(random.Random(3))
    s = m.splice(b"AAAAAAAA", b"BBBBBBBB")
    assert b"A" in s and b"B" in s


def test_harvest_dictionary_finds_magic_constants():
    def f(d):
        if d[:4] == b"FUZZ" or int.from_bytes(d[4:6], "little") == 0xCAFE:
            return "RIFF-header"
    toks = harvest_dictionary(f)
    assert b"FUZZ" in toks
    assert (0xCAFE).to_bytes(2, "little") in toks
