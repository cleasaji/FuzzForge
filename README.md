# FuzzForge

A **coverage-guided fuzzer for Python**, written from scratch with zero dependencies.
It instruments the target, learns which inputs reach new code, and keeps mutating
those — the same feedback loop that powers AFL/libFuzzer, applied to Python functions.

```
python -m fuzzforge run targets/demo_parser.py:parse_packet --seeds seeds/parser.seed --no-dict --minimize
```

## How it works

| Stage | What it does | File |
|---|---|---|
| Instrumentation | `sys.settrace` records **edges** (line→line transitions, AFL-style XOR hash) and folds hit counts into log buckets, so loop-count changes count as new behaviour | `fuzzforge/coverage.py` |
| Mutation | havoc engine: bit/byte flips, ± arithmetic, interesting 8/16/32-bit values, block insert/delete/duplicate/overwrite, dictionary tokens, corpus splicing | `fuzzforge/mutators.py` |
| Scheduling | inputs that reach **rare** edges get more mutation budget; short and rarely-fuzzed inputs are favoured | `fuzzforge/corpus.py` |
| Triage | crashes are deduplicated by *exception type + innermost frame in target code*; the smallest reproducer per bug is kept | `fuzzforge/engine.py` |
| Hang detection | a line-event budget raises a `BaseException` inside the target, so even code that does `except Exception: pass` can't hide an infinite loop | `fuzzforge/coverage.py` |
| Minimization | delta-debugging chunk removal, then byte simplification, preserving the exact crash signature | `fuzzforge/minimize.py` |
| Auto-dictionary | harvests `bytes`/`str`/large-int literals from the target's code constants (`co_consts`) as mutation tokens | `fuzzforge/mutators.py` |

## CLI

```
fuzzforge run      file.py:func --seeds DIR --time 30 --out fuzz-out [--minimize] [--blind] [--no-dict]
fuzzforge replay   file.py:func crash-file
fuzzforge minimize file.py:func crash-file -o smaller
```

The target is any function taking `bytes`. Raising any exception is a finding.
`run` exits with code 1 if it found anything, so it drops straight into CI.
Results land in `--out`: `corpus/`, `crashes/<id>/{input,report.json}`, `stats.json`.
Use `--seed N` for reproducible campaigns.

## Demo targets (planted bugs)

- `targets/demo_parser.py` – binary parser; two bugs behind a 4-byte `FUZZ` magic, each byte in its own nested `if`.
- `targets/mini_json.py` – recursive-descent JSON parser; bugs on a lone `-` and on a `\u` escape with non-hex digits.
- `targets/hang_target.py` – tokenizer that never advances on a trailing backslash.

## Measured results

Benchmark: `python benchmarks/compare.py --trials 10 --budget 60000` (10 RNG seeds per row, Python 3.12):

| target | mode | found bug | median execs to bug | median edges covered |
|---|---|---|---|---|
| demo_parser | blind | 0/10 | n/a | 6 |
| demo_parser | guided | 10/10 | 17,207 | 19 |
| demo_parser | guided+dict | 10/10 | 17,207 | 19 |
| mini_json | blind | 10/10 | 1,120 | 101 |
| mini_json | guided | 10/10 | 1,161 | 100 |
| mini_json | guided+dict | 10/10 | 819 | 96 |

How to read this honestly:

- **Where feedback matters:** `demo_parser` hides its bugs behind four consecutive byte checks. Blind mutation never gets past the first byte (0/10, 6 edges); coverage guidance climbs the checks one byte at a time and finds the bug in 10/10 trials.
- **Where it doesn't:** the shallow `mini_json` bug (a lone `-`) is found just as fast blind, because a valid-JSON seed is already one mutation away. Guidance only pays off for bugs that sit behind deep checks.
- **Dictionary:** no effect on `demo_parser` because it compares against small integers, which aren't harvested (only `bytes`/`str` literals and integers > 255 are). It helped slightly on `mini_json`.
- A separate 60-second guided campaign on `mini_json` found **both** planted bugs; the minimizer shrank the 21-byte `\u` crash to the 3-byte `"\u`.
- Throughput is ~19k execs/s on the tiny parser and ~8k/s on the JSON parser (tracing overhead is the main cost).

## Limitations

- Line-level coverage via `settrace`; it does not see inside C extensions.
- No comparison-operand feedback (no equivalent of libFuzzer's `-use_value_profile`), so wide magic values (e.g. 32-bit constants) rely on the dictionary.
- Single process; no parallel fuzzing or corpus sync yet.

## Development

```
pip install -e .[dev]
pytest -q          # 21 tests: tracer, mutators, engine, minimizer, CLI
```

MIT licensed.
