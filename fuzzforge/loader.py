"""Resolve a ``path/to/file.py:func`` or ``package.module:func`` target spec."""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import sys
from typing import Callable, List, Set, Tuple


def load_target(spec: str, include: List[str] = ()) -> Tuple[Callable, Set[str]]:
    if ":" not in spec:
        raise ValueError("target must look like 'file.py:function' or 'module:function'")
    where, name = spec.rsplit(":", 1)
    if where.endswith(".py") or os.sep in where:
        path = os.path.abspath(where)
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        mod_name = "fuzz_target_" + os.path.splitext(os.path.basename(path))[0]
        mspec = importlib.util.spec_from_file_location(mod_name, path)
        module = importlib.util.module_from_spec(mspec)
        sys.modules[mod_name] = module
        mspec.loader.exec_module(module)
    else:
        module = importlib.import_module(where)
    func = inspect.unwrap(getattr(module, name))
    files = {func.__code__.co_filename}
    files.add(getattr(module, "__file__", None) or func.__code__.co_filename)
    for extra in include:
        files.add(os.path.abspath(extra))
    return func, files
