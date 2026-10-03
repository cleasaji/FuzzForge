import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PARSER = os.path.join(ROOT, "targets", "demo_parser.py") + ":parse_packet"


def run(*args):
    return subprocess.run([sys.executable, "-m", "fuzzforge", *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)


def test_run_exit_code_and_report(tmp_path):
    r = run("run", PARSER, "--out", str(tmp_path), "--no-dict", "--seed", "1",
            "--execs", "150000", "--stop-on-crash", "--quiet")
    assert r.returncode == 1
    assert "unique crash" in r.stdout and "demo_parser.py" in r.stdout


def test_replay_and_minimize(tmp_path):
    f = tmp_path / "crash"
    f.write_bytes(b"FUZZ\x02\x01\x00\x00\x00" + b"x" * 50)
    r = run("replay", PARSER, str(f))
    assert r.returncode == 1 and "ZeroDivisionError" in r.stdout
    m = run("minimize", PARSER, str(f), "-o", str(tmp_path / "min"))
    assert m.returncode == 0
    assert len((tmp_path / "min").read_bytes()) <= 9


def test_replay_clean_input(tmp_path):
    f = tmp_path / "ok"
    f.write_bytes(b"hello")
    assert run("replay", PARSER, str(f)).returncode == 0
