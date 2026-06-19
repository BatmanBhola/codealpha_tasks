"""Simple test runner for the IDS unit tests.

This script imports `tests.test_nids` and executes each test function
that starts with `test_`, reporting pass/fail status.
"""

import sys
import traceback

import tests.test_nids as t

failed = []

for name in dir(t):
    if name.startswith('test_'):
        func = getattr(t, name)
        try:
            func()
            print(f"PASS: {name}")
        except AssertionError:
            print(f"FAIL: {name}")
            traceback.print_exc()
            failed.append(name)
        except Exception:  # pylint: disable=broad-exception-caught
            print(f"ERROR: {name}")
            traceback.print_exc()
            failed.append(name)

if failed:
    print(f"{len(failed)} tests failed")
    sys.exit(1)

print("All tests passed")
sys.exit(0)
