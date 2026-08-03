#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Count the published run passports that verify, and refuse if any does not.

Every file named `run-passport.json` anywhere under `examples/verified/` is a
published run. Each one is handed to the published verifier exactly as a reader
would hand it over, and the count is printed only when every one of them
returns PASS.

The count is the honest measure of this repository's evidence: it cannot be
raised by editing prose, only by publishing another run whose passport verifies.
A tampered twin is not a run and is not counted -- it is the demonstration's
negative case, re-proved separately by `check_demonstration.py`.

No network, no third-party package, no repository checkout beyond this one.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "tools" / "verify_run_passport.py"
PUBLISHED_ROOT = REPO_ROOT / "examples" / "verified"
PASSPORT_NAME = "run-passport.json"
PASS_VERDICT = "RUN_PASSPORT_VERDICT: PASS"


def published_passports(root: Path = PUBLISHED_ROOT) -> list[Path]:
    """Every published passport under `root`, in a stable order.

    Sorted so the printed order does not depend on the filesystem, and so a
    reader re-running this on another machine sees the same sequence.
    """
    return sorted(root.rglob(PASSPORT_NAME))


def verdict_of(passport: Path) -> tuple[int, str]:
    """The verifier's exit code and final verdict line for one passport."""
    completed = subprocess.run(
        [sys.executable, str(VERIFIER), str(passport)],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    return completed.returncode, lines[-1] if lines else "(no verdict printed)"


def main() -> int:
    passports = published_passports()
    if not passports:
        print("no published run passport found under examples/verified/")
        return 1

    failures: list[str] = []
    for passport in passports:
        code, verdict = verdict_of(passport)
        relative = passport.relative_to(REPO_ROOT).as_posix()
        if code != 0 or verdict != PASS_VERDICT:
            failures.append(f"{relative}: exit {code}, {verdict}")

    if failures:
        for failure in failures:
            print(failure)
        print(f"VERIFIED_RUNS: FAIL {len(failures)} of {len(passports)} did not verify")
        return 1

    print(f"verified runs: {len(passports)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
