"""FuzzForge - a coverage-guided fuzzer for Python targets."""

from .coverage import ExecResult, ExecutionTimeout, Tracer
from .engine import Fuzzer, Stats
from .loader import load_target
from .minimize import minimize_crash
from .mutators import Mutator, harvest_dictionary

__all__ = [
    "ExecResult", "ExecutionTimeout", "Tracer", "Fuzzer", "Stats",
    "load_target", "minimize_crash", "Mutator", "harvest_dictionary",
]
__version__ = "0.1.0"
