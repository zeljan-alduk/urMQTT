#!/usr/bin/env python3
"""Runs the Eclipse Paho interoperability suite against a broker, each test in
its own process with a timeout, and compares with the expected-failure list
(docs/MQTT5-CONFORMANCE.md, ADR-273, ADR-274).

    python3 scripts/mqtt5-conformance.py SUITE_DIR PORT XFAIL TIMEOUT SUITE...

SUITE_DIR is the `interoperability/` directory of a paho.mqtt.testing checkout
(third-party code: it runs from there, as its scripts import their local
`mqtt` package); SUITE is `client_test5` and/or `client_test`. XFAIL is the
expected-failure list, or `-` for none (the Mosquitto baseline).

Prints one line per test (PASS, FAIL, XFAIL, XPASS, TIMEOUT) and a summary;
exits non-zero on any FAIL, TIMEOUT or XPASS.
"""
import os
import re
import subprocess
import sys
import time

suite_dir, port, xfail_path, timeout = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
suites = sys.argv[5:]

# The wrapper each test runs in: the script's own argument parsing sees the
# port, unittest sees only the test name (client_test.py leaves -p in argv,
# which unittest then refuses). No -h: the scripts test `o in ("--help")`, a
# substring test that "-h" passes, and exit 0 without running anything; the
# host stays "localhost".
WRAPPER = r"""
import functools, runpy, sys, unittest
script, port, test = sys.argv[1], sys.argv[2], sys.argv[3]
sys.argv = [script, "-p", port]
unittest.main = functools.partial(unittest.main, argv=[script, test], exit=True)
runpy.run_path(script, run_name="__main__")
"""

xfail = {}
if xfail_path != "-":
    for line in open(xfail_path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        suite, test, phase, reason = line.split(None, 3)
        xfail[(suite, test)] = (phase, reason)

# Each test's output, for the failures: next to the checkout.
logdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(suite_dir))), "logs")
os.makedirs(logdir, exist_ok=True)
counts = {"PASS": 0, "FAIL": 0, "XFAIL": 0, "XPASS": 0, "TIMEOUT": 0}
start = time.time()
for suite in suites:
    script = os.path.join(suite_dir, suite + ".py")
    tests = re.findall(r"^    def (test_\w+)\(self\)", open(script).read(), re.M)
    for test in tests:
        t0 = time.time()
        try:
            p = subprocess.run(
                [sys.executable, "-c", WRAPPER, script, port, f"Test.{test}"],
                cwd=suite_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            # unittest reports "Ran 1 test"; anything else ran nothing.
            passed = p.returncode == 0 and "Ran 1 test" in p.stderr
            with open(os.path.join(logdir, f"{suite}.{test}.log"), "w") as f:
                f.write(p.stdout + p.stderr)
            verdict = "PASS" if passed else "FAIL"
            tail = "" if passed else (p.stderr.strip().splitlines() or ["?"])[-1][:160]
        except subprocess.TimeoutExpired:
            passed, verdict, tail = False, "TIMEOUT", f"after {timeout} s"
        expected = xfail.get((suite, test))
        if expected and passed:
            verdict = "XPASS"
        elif expected and not passed:
            verdict, tail = "XFAIL", f"[{expected[0]}] {expected[1]}"
        counts[verdict] += 1
        print(f"{verdict:7} {suite} {test} ({time.time() - t0:.1f} s) {tail}".rstrip(), flush=True)
        # Let the broker close what the test left open.
        time.sleep(0.5)

total = sum(counts.values())
print(
    f"summary: {total} tests, {counts['PASS']} passed, {counts['XFAIL']} expected failures, "
    f"{counts['FAIL']} failed, {counts['TIMEOUT']} timed out, {counts['XPASS']} unexpectedly passed, "
    f"{time.time() - start:.0f} s"
)
sys.exit(1 if counts["FAIL"] or counts["TIMEOUT"] or counts["XPASS"] else 0)
