"""Edge-coverage instrumentation using sys.settrace.

Coverage model (AFL-style, adapted to Python lines):
  * every executed line gets a stable 32-bit id (crc32 of "file:line")
  * an *edge* is the XOR of the current line id with the shifted previous id,
    so A->B and B->A are distinct edges
  * edge hit counts are folded into logarithmic buckets, so "this loop ran
    once" and "this loop ran 40 times" count as different behaviours
A "feature" is the pair (edge, hit-count bucket) packed into one int.
"""
from __future__ import annotations

import os
import sys
import traceback
import zlib
from dataclasses import dataclass
from typing import Callable, FrozenSet, Iterable, Optional


class ExecutionTimeout(BaseException):
    """Raised inside the target when it exceeds the line-event budget (a hang).

    Derives from BaseException so a target's own ``except Exception`` cannot
    swallow it.
    """


def bucket(n: int) -> int:
    if n <= 3:
        return n
    if n <= 7:
        return 4
    if n <= 15:
        return 8
    if n <= 31:
        return 16
    if n <= 127:
        return 32
    return 128


@dataclass
class ExecResult:
    features: FrozenSet[int]
    edges: FrozenSet[int]
    exc_type: Optional[str] = None
    signature: Optional[str] = None
    traceback: Optional[str] = None
    hung: bool = False
    events: int = 0

    @property
    def crashed(self) -> bool:
        return self.exc_type is not None and not self.hung


class Tracer:
    def __init__(self, files: Iterable[str], max_events: int = 200_000):
        self.files = frozenset(files)
        self.max_events = max_events
        self._loc_cache: dict = {}
        self._hits: dict = {}
        self._prev = 0
        self._events = 0

    def _loc(self, filename: str, line: int) -> int:
        key = (filename, line)
        v = self._loc_cache.get(key)
        if v is None:
            v = zlib.crc32(f"{os.path.basename(filename)}:{line}".encode())
            self._loc_cache[key] = v
        return v

    def _global(self, frame, event, arg):
        if frame.f_code.co_filename in self.files:
            return self._local
        return None

    def _local(self, frame, event, arg):
        if event == "line":
            self._events += 1
            if self._events > self.max_events:
                raise ExecutionTimeout()
            cur = self._loc(frame.f_code.co_filename, frame.f_lineno)
            edge = cur ^ self._prev
            self._hits[edge] = self._hits.get(edge, 0) + 1
            self._prev = cur >> 1
        return self._local

    def run(self, func: Callable[[bytes], object], data: bytes) -> ExecResult:
        self._hits = {}
        self._prev = 0
        self._events = 0
        exc: Optional[BaseException] = None
        old = sys.gettrace()
        sys.settrace(self._global)
        try:
            func(data)
        except ExecutionTimeout as e:
            exc = e
        except Exception as e:  # noqa: BLE001 - any target exception is a finding
            exc = e
        finally:
            sys.settrace(old)

        hits = self._hits
        features = frozenset((e << 8) | bucket(c) for e, c in hits.items())
        res = ExecResult(features=features, edges=frozenset(hits), events=self._events)
        if exc is not None:
            res.exc_type = type(exc).__name__
            if isinstance(exc, ExecutionTimeout):
                res.hung = True
                res.signature = "Hang"
            else:
                res.signature = self._signature(exc)
                res.traceback = "".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )
        return res

    def _signature(self, exc: BaseException) -> str:
        """Deduplication key: exception type + innermost frame in target code."""
        tb = exc.__traceback__
        chosen = None
        while tb is not None:
            if tb.tb_frame.f_code.co_filename in self.files:
                chosen = tb
            tb = tb.tb_next
        if chosen is None:  # exception escaped from a library call
            tb = exc.__traceback__
            while tb is not None and tb.tb_next is not None:
                tb = tb.tb_next
            chosen = tb
        if chosen is None:
            return type(exc).__name__
        code = chosen.tb_frame.f_code
        return (f"{type(exc).__name__}@{os.path.basename(code.co_filename)}"
                f":{chosen.tb_lineno}:{code.co_name}")
