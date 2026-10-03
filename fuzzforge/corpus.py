"""Corpus with rarity-based power scheduling (AFLFast-flavoured)."""
from __future__ import annotations

import hashlib
import os
import random
from collections import Counter
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional


@dataclass
class Entry:
    data: bytes
    features: FrozenSet[int]
    found_at_exec: int = 0
    fuzz_rounds: int = 0
    id: str = field(init=False)

    def __post_init__(self):
        self.id = hashlib.sha1(self.data).hexdigest()[:12]


class Corpus:
    def __init__(self, rng: random.Random, directory: Optional[str] = None):
        self.rng = rng
        self.entries: List[Entry] = []
        self.freq: Counter = Counter()
        self.directory = directory
        self._weights: Optional[List[float]] = None
        if directory:
            os.makedirs(directory, exist_ok=True)

    def __len__(self):
        return len(self.entries)

    def add(self, entry: Entry):
        self.entries.append(entry)
        self.freq.update(entry.features)
        self._weights = None
        if self.directory:
            with open(os.path.join(self.directory, entry.id), "wb") as fh:
                fh.write(entry.data)

    def _ensure_weights(self) -> List[float]:
        if self._weights is None:
            ws = []
            for e in self.entries:
                rarity = sum(1.0 / self.freq[f] for f in e.features) or 0.1
                # favour rare coverage, short inputs, and rarely-fuzzed entries
                ws.append(rarity / (1.0 + len(e.data) / 64.0) / (1.0 + e.fuzz_rounds * 0.05))
            self._weights = ws
        return self._weights

    def pick(self) -> Entry:
        return self.rng.choices(self.entries, weights=self._ensure_weights(), k=1)[0]

    def energy(self, entry: Entry, base: int = 32) -> int:
        """Number of havoc children to derive from ``entry`` this round."""
        ws = self._ensure_weights()
        mean = sum(ws) / len(ws)
        ratio = ws[self.entries.index(entry)] / mean if mean else 1.0
        return max(8, int(base * min(4.0, max(0.5, ratio))))

    def random_other(self, exclude: Entry) -> Optional[bytes]:
        if len(self.entries) < 2:
            return None
        other = self.rng.choice(self.entries)
        return other.data if other is not exclude else None
