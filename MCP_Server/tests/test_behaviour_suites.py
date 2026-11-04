"""Runs the behaviour suites (tests/behaviour/suite_*.py) under pytest.

Each suite loads the REAL bridge modules into Lua 5.3 (lupa) against a fake Cheat Engine API and prints PASS/FAIL
lines; see behaviour/README.md. They need `lupa` (skipped without it) and take a few seconds each.
"""
import subprocess
import sys

import pytest

from conftest import HERE

BEHAVIOUR = HERE / "behaviour"
SUITES = sorted(BEHAVIOUR.glob("suite_lua_*.py"))


@pytest.mark.parametrize("suite", SUITES, ids=[s.stem for s in SUITES])
def test_behaviour_suite(suite):
    proc = subprocess.run([sys.executable, str(suite)], cwd=BEHAVIOUR, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=600)
    out = proc.stdout + proc.stderr
    if proc.returncode == 77:
        pytest.skip((out.strip().splitlines() or ["prerequisite missing"])[-1])
    problems = "\n".join(l for l in out.splitlines() if l.startswith(("FAIL", "COMPILE FAIL", "LUA ERROR", "Traceback")) or "Error" in l)
    assert proc.returncode == 0, "%s failed:\n%s\n%s" % (suite.name, problems or out[-1500:], out.splitlines()[-1] if out else "")
