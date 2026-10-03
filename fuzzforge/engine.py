"""The fuzzing loop: calibrate seeds, schedule corpus entries, mutate, execute,
keep anything that reaches new coverage, and deduplicate crashes."""
from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

from .corpus import Corpus, Entry
from .coverage import ExecResult, Tracer
from .mutators import Mutator


@dataclass
class Crash:
    signature: str
    data: bytes
    exc_type: str
    traceback: Optional[str]
    found_at_exec: int
    found_at_sec: float
    hits: int = 1


@dataclass
class Stats:
    execs: int = 0
    elapsed: float = 0.0
    corpus_size: int = 0
    edges: int = 0
    features: int = 0
    crashes: Dict[str, Crash] = field(default_factory=dict)
    hangs: int = 0
    first_crash_exec: Optional[int] = None
    first_crash_sec: Optional[float] = None

    @property
    def execs_per_sec(self) -> float:
        return self.execs / self.elapsed if self.elapsed else 0.0

    def to_dict(self) -> dict:
        return {
            "execs": self.execs, "elapsed_sec": round(self.elapsed, 2),
            "execs_per_sec": round(self.execs_per_sec, 1),
            "corpus_size": self.corpus_size, "edges": self.edges,
            "features": self.features, "unique_crashes": len(self.crashes),
            "hangs": self.hangs, "first_crash_exec": self.first_crash_exec,
            "first_crash_sec": self.first_crash_sec,
        }


class Fuzzer:
    def __init__(self, target: Callable[[bytes], object], files: Iterable[str],
                 seeds: Iterable[bytes] = (), out_dir: Optional[str] = None,
                 rng_seed: Optional[int] = None, max_len: int = 1024,
                 dictionary: Iterable[bytes] = (), guided: bool = True,
                 max_events: int = 200_000,
                 on_progress: Optional[Callable[["Fuzzer"], None]] = None):
        self.target = target
        self.guided = guided
        self.out_dir = out_dir
        self.rng = random.Random(rng_seed)
        self.tracer = Tracer(files, max_events=max_events)
        self.mutator = Mutator(self.rng, max_len=max_len, dictionary=list(dictionary))
        self.corpus = Corpus(self.rng, os.path.join(out_dir, "corpus") if out_dir else None)
        self.seeds = [s for s in seeds] or [b"", b"\x00\x00\x00\x00"]
        self.stats = Stats()
        self.on_progress = on_progress
        self._seen_features: set = set()
        self._seen_edges: set = set()
        self._start = 0.0
        self._last_progress = 0.0
        if out_dir:
            os.makedirs(os.path.join(out_dir, "crashes"), exist_ok=True)

    # -- execution ---------------------------------------------------------
    def _execute(self, data: bytes) -> ExecResult:
        res = self.tracer.run(self.target, data)
        st = self.stats
        st.execs += 1
        st.elapsed = time.monotonic() - self._start
        self._seen_edges |= res.edges
        st.edges = len(self._seen_edges)

        if res.exc_type is not None:
            if res.hung:
                st.hangs += 1
            self._record_crash(res, data)

        new_feats = res.features - self._seen_features
        if new_feats:
            self._seen_features |= new_feats
            st.features = len(self._seen_features)
            if self.guided and res.exc_type is None:
                self.corpus.add(Entry(data, res.features, found_at_exec=st.execs))
                st.corpus_size = len(self.corpus)

        if self.on_progress and time.monotonic() - self._last_progress >= 1.0:
            self._last_progress = time.monotonic()
            self.on_progress(self)
        return res

    def _record_crash(self, res: ExecResult, data: bytes):
        sig = res.signature
        known = self.stats.crashes.get(sig)
        if known is not None:
            known.hits += 1
            if len(data) < len(known.data):  # keep the smallest reproducer
                known.data = data
                self._persist(known)
            return
        c = Crash(sig, data, res.exc_type, res.traceback, self.stats.execs,
                  time.monotonic() - self._start)
        self.stats.crashes[sig] = c
        if self.stats.first_crash_exec is None:
            self.stats.first_crash_exec = c.found_at_exec
            self.stats.first_crash_sec = round(c.found_at_sec, 3)
        self._persist(c)

    def _persist(self, c: Crash):
        if not self.out_dir:
            return
        import hashlib
        d = os.path.join(self.out_dir, "crashes",
                         hashlib.sha1(c.signature.encode()).hexdigest()[:10])
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "input"), "wb") as fh:
            fh.write(c.data)
        with open(os.path.join(d, "report.json"), "w") as fh:
            json.dump({
                "signature": c.signature, "exception": c.exc_type,
                "input_hex": c.data.hex(), "input_len": len(c.data),
                "found_at_exec": c.found_at_exec,
                "found_at_sec": round(c.found_at_sec, 3), "hits": c.hits,
                "traceback": c.traceback,
            }, fh, indent=2)

    # -- main loop ---------------------------------------------------------
    def run(self, max_time: Optional[float] = None, max_execs: Optional[int] = None,
            stop_on_crash: bool = False) -> Stats:
        self._start = time.monotonic()
        self._last_progress = self._start

        def done() -> bool:
            if max_execs is not None and self.stats.execs >= max_execs:
                return True
            if max_time is not None and time.monotonic() - self._start >= max_time:
                return True
            return stop_on_crash and bool(self.stats.crashes)

        # calibrate: seeds always enter the corpus (guided mode), even w/o new coverage
        for s in self.seeds:
            res = self._execute(s)
            if self.guided and res.exc_type is None and not any(
                    e.data == s for e in self.corpus.entries):
                self.corpus.add(Entry(s, res.features, found_at_exec=self.stats.execs))
            if done():
                return self._finish()
        self.stats.corpus_size = len(self.corpus)

        pool = self.corpus if self.guided else None
        base_entries = [Entry(s, frozenset()) for s in self.seeds]
        while not done():
            if self.guided and len(self.corpus):
                entry = self.corpus.pick()
                rounds = self.corpus.energy(entry)
                entry.fuzz_rounds += 1
            else:  # blind mode: mutate seeds only, never learn
                entry = self.rng.choice(base_entries)
                rounds = 32
            for _ in range(rounds):
                other = None
                if self.guided and self.rng.random() < 0.1:
                    other = self.corpus.random_other(entry)
                self._execute(self.mutator.havoc(entry.data, splice_with=other))
                if done():
                    break
        return self._finish()

    def _finish(self) -> Stats:
        self.stats.elapsed = time.monotonic() - self._start
        self.stats.corpus_size = len(self.corpus)
        if self.out_dir:
            with open(os.path.join(self.out_dir, "stats.json"), "w") as fh:
                json.dump(self.stats.to_dict(), fh, indent=2)
        return self.stats
