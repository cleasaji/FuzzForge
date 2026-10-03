"""Crash minimization: delta-debugging chunk removal, then byte simplification."""
from __future__ import annotations

from typing import Callable

from .coverage import Tracer


def minimize_crash(target: Callable[[bytes], object], tracer: Tracer, data: bytes,
                   signature: str, max_execs: int = 5000) -> bytes:
    budget = [max_execs]

    def still_crashes(candidate: bytes) -> bool:
        if budget[0] <= 0:
            return False
        budget[0] -= 1
        return tracer.run(target, candidate).signature == signature

    if not still_crashes(data):
        return data  # not reproducible; leave untouched
    best = data

    # phase 1: remove chunks, large to small (ddmin-style)
    chunk = max(1, len(best) // 2)
    while chunk >= 1:
        i, progressed = 0, False
        while i < len(best):
            cand = best[:i] + best[i + chunk:]
            if cand != best and still_crashes(cand):
                best, progressed = cand, True
            else:
                i += chunk
        if not progressed:
            chunk //= 2

    # phase 2: simplify bytes (prefer 0x00, then 0x41) so reproducers are readable
    for i in range(len(best)):
        for repl in (0x00, 0x41):
            if best[i] != repl:
                cand = best[:i] + bytes([repl]) + best[i + 1:]
                if still_crashes(cand):
                    best = cand
                    break
    return best
