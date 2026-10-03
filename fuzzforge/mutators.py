"""Mutation engine: bit/byte flips, arithmetic, interesting values, block ops,
dictionary tokens, and corpus splicing, combined AFL-"havoc" style."""
from __future__ import annotations

import random
import struct
from typing import Callable, List, Optional, Sequence

INTERESTING_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
INTERESTING_16 = [0, 1, 127, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535]
INTERESTING_32 = [0, 1, 32768, 65535, 65536, 100000, 2147483647, 2147483648, 4294967295]


class Mutator:
    def __init__(self, rng: random.Random, max_len: int = 1024,
                 dictionary: Sequence[bytes] = ()):
        self.rng = rng
        self.max_len = max_len
        self.dictionary: List[bytes] = [d for d in dictionary if d]
        self._ops: List[Callable] = [
            self._bitflip, self._set_byte, self._set_byte, self._add_sub,
            self._interesting8, self._interesting16, self._interesting32,
            self._arith16, self._insert_random, self._delete_block,
            self._duplicate_block, self._overwrite_block, self._swap_bytes,
        ]
        if self.dictionary:
            self._ops += [self._dict_insert, self._dict_overwrite]

    def _pos(self, buf: bytearray, width: int = 1) -> Optional[int]:
        if len(buf) < width:
            return None
        return self.rng.randrange(len(buf) - width + 1)

    def _bitflip(self, buf):
        p = self._pos(buf)
        if p is not None:
            buf[p] ^= 1 << self.rng.randrange(8)

    def _set_byte(self, buf):
        p = self._pos(buf)
        if p is not None:
            buf[p] = self.rng.randrange(256)

    def _add_sub(self, buf):
        p = self._pos(buf)
        if p is not None:
            buf[p] = (buf[p] + self.rng.randint(-35, 35)) & 0xFF

    def _interesting8(self, buf):
        p = self._pos(buf)
        if p is not None:
            buf[p] = self.rng.choice(INTERESTING_8)

    def _interesting16(self, buf):
        p = self._pos(buf, 2)
        if p is not None:
            fmt = "<H" if self.rng.random() < 0.5 else ">H"
            buf[p:p + 2] = struct.pack(fmt, self.rng.choice(INTERESTING_16))

    def _interesting32(self, buf):
        p = self._pos(buf, 4)
        if p is not None:
            fmt = "<I" if self.rng.random() < 0.5 else ">I"
            buf[p:p + 4] = struct.pack(fmt, self.rng.choice(INTERESTING_32))

    def _arith16(self, buf):
        p = self._pos(buf, 2)
        if p is not None:
            fmt = "<H" if self.rng.random() < 0.5 else ">H"
            v = struct.unpack(fmt, bytes(buf[p:p + 2]))[0]
            buf[p:p + 2] = struct.pack(fmt, (v + self.rng.randint(-35, 35)) & 0xFFFF)

    def _insert_random(self, buf):
        n = self.rng.randint(1, 8)
        p = self.rng.randrange(len(buf) + 1)
        buf[p:p] = bytes(self.rng.randrange(256) for _ in range(n))

    def _delete_block(self, buf):
        if len(buf) < 2:
            return
        n = self.rng.randint(1, max(1, len(buf) // 2))
        p = self.rng.randrange(len(buf) - n + 1)
        del buf[p:p + n]

    def _duplicate_block(self, buf):
        if not buf:
            return
        n = self.rng.randint(1, min(len(buf), 32))
        p = self.rng.randrange(len(buf) - n + 1)
        chunk = bytes(buf[p:p + n])
        q = self.rng.randrange(len(buf) + 1)
        buf[q:q] = chunk * self.rng.randint(1, 4)

    def _overwrite_block(self, buf):
        if len(buf) < 2:
            return
        n = self.rng.randint(1, min(len(buf) // 2 or 1, 16))
        src = self.rng.randrange(len(buf) - n + 1)
        dst = self.rng.randrange(len(buf) - n + 1)
        buf[dst:dst + n] = bytes(buf[src:src + n])

    def _swap_bytes(self, buf):
        if len(buf) >= 2:
            a, b = self.rng.randrange(len(buf)), self.rng.randrange(len(buf))
            buf[a], buf[b] = buf[b], buf[a]

    def _dict_insert(self, buf):
        tok = self.rng.choice(self.dictionary)
        p = self.rng.randrange(len(buf) + 1)
        buf[p:p] = tok

    def _dict_overwrite(self, buf):
        tok = self.rng.choice(self.dictionary)
        if len(buf) >= len(tok):
            p = self.rng.randrange(len(buf) - len(tok) + 1)
            buf[p:p + len(tok)] = tok
        else:
            buf[:] = tok

    def splice(self, a: bytes, b: bytes) -> bytes:
        if len(a) < 2 or len(b) < 2:
            return a
        return a[: self.rng.randrange(1, len(a))] + b[self.rng.randrange(len(b)):]

    def havoc(self, data: bytes, splice_with: Optional[bytes] = None) -> bytes:
        if splice_with is not None:
            data = self.splice(data, splice_with)
        buf = bytearray(data)
        for _ in range(1 << self.rng.randint(0, 3)):
            self.rng.choice(self._ops)(buf)
        if len(buf) > self.max_len:
            del buf[self.max_len:]
        if not buf:
            buf.append(self.rng.randrange(256))
        return bytes(buf)


def harvest_dictionary(func: Callable, max_tokens: int = 128) -> List[bytes]:
    """Pull magic values out of the target's code constants.

    Python-specific trick: comparisons against literals (``data[:4] == b"FUZZ"``,
    ``x == 0xCAFE``) leave those literals in ``co_consts``, so the dictionary
    can be seeded with the exact tokens the parser is looking for.
    """
    seen, out = set(), []
    stack = [getattr(func, "__code__", None)]
    while stack and len(out) < max_tokens:
        code = stack.pop()
        if code is None:
            continue
        for c in code.co_consts:
            toks = []
            if isinstance(c, bytes):
                toks = [c]
            elif isinstance(c, str) and 1 < len(c) <= 32:
                toks = [c.encode("utf-8", "ignore")]
            elif isinstance(c, int) and not isinstance(c, bool) and 255 < c < 2 ** 32:
                n = 2 if c < 65536 else 4
                toks = [c.to_bytes(n, "little"), c.to_bytes(n, "big")]
            elif hasattr(c, "co_consts"):
                stack.append(c)
            for t in toks:
                if t and t not in seen and len(t) <= 32:
                    seen.add(t)
                    out.append(t)
    return out[:max_tokens]
