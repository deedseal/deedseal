# SPDX-License-Identifier: CC-BY-4.0
"""Re-prove the published demonstration from this repository's own files.

Three checks, run in CI on every change and reproducible by any reader with a
clone and a Python interpreter:

1. The published run passport verifies PASS, exit code 0.
2. Its twin verifies BLOCK, exit code 1.
3. The twin differs from the passport by exactly one byte.

The third check is what makes the second honest. "A byte-tampered twin was
refused" means nothing if the twin were rewritten wholesale; this pins the
difference to a single byte, so the refusal is attributable to that byte and
to nothing else.

No network, no third-party package, no repository checkout beyond this one.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "tools" / "verify_run_passport.py"
PASSPORT = REPO_ROOT / "examples" / "verified" / "run-passport.json"
TAMPERED = REPO_ROOT / "examples" / "verified" / "run-passport.tampered.json"

PASS_VERDICT = "RUN_PASSPORT_VERDICT: PASS"
BLOCK_VERDICT_PREFIX = "RUN_PASSPORT_VERDICT: BLOCK"


class DemonstrationError(Exception):
    """One check failed. The message says which, and what was observed."""


def _run_verifier(passport: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(passport)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def _final_verdict_line(stdout: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise DemonstrationError("the verifier printed no verdict line")
    return lines[-1]


def check_passport_passes() -> str:
    completed = _run_verifier(PASSPORT)
    verdict = _final_verdict_line(completed.stdout)
    if completed.returncode != 0:
        raise DemonstrationError(
            "expected exit code 0 for the published passport, observed "
            f"{completed.returncode} ({verdict})"
        )
    if verdict != PASS_VERDICT:
        raise DemonstrationError(
            f"expected the final verdict line to be {PASS_VERDICT!r}, observed {verdict!r}"
        )
    return verdict


def check_twin_blocks() -> str:
    completed = _run_verifier(TAMPERED)
    verdict = _final_verdict_line(completed.stdout)
    if completed.returncode != 1:
        raise DemonstrationError(
            "expected exit code 1 for the tampered twin, observed "
            f"{completed.returncode} ({verdict})"
        )
    if not verdict.startswith(BLOCK_VERDICT_PREFIX):
        raise DemonstrationError(
            f"expected the final verdict line to start with {BLOCK_VERDICT_PREFIX!r}, "
            f"observed {verdict!r}"
        )
    return verdict


def check_twin_differs_by_one_byte() -> int:
    original = PASSPORT.read_bytes()
    twin = TAMPERED.read_bytes()
    if len(original) != len(twin):
        raise DemonstrationError(
            f"the twin must be the same length as the passport: {len(original)} vs {len(twin)}"
        )
    differing = [index for index, (a, b) in enumerate(zip(original, twin)) if a != b]
    if len(differing) != 1:
        raise DemonstrationError(
            f"the twin must differ by exactly one byte, observed {len(differing)}"
        )
    return differing[0]


def main() -> int:
    for path in (VERIFIER, PASSPORT, TAMPERED):
        if not path.is_file():
            sys.stderr.write(f"DEMONSTRATION_CHECK: FAIL missing file {path.name}\n")
            return 1
    try:
        pass_verdict = check_passport_passes()
        block_verdict = check_twin_blocks()
        offset = check_twin_differs_by_one_byte()
    except DemonstrationError as failure:
        sys.stderr.write(f"DEMONSTRATION_CHECK: FAIL {failure}\n")
        return 1
    print(f"published passport: {pass_verdict}")
    print(f"tampered twin: {block_verdict}")
    print(f"twin differs from the passport at exactly one byte, offset {offset}")
    print("DEMONSTRATION_CHECK: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
