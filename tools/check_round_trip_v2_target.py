#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate the byte-frozen seed or result of the public Evidence 2 target.

The controlled run is allowed to move this file from the seed bytes to exactly
the result bytes. This check accepts either of those two states and refuses every
other byte sequence; it does not by itself pin which of the two is currently
published.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "app" / "product" / "demo" / "test_demonstration_contract.py"
SEED = b'''# SPDX-License-Identifier: CC-BY-4.0
"""Contract tests for the public Evidence 2 target.

The seed has one passing test. The sole controlled result may add the frozen
``test_demonstration_marker_is_present`` test below it.
"""


def test_seed_is_present():
    assert True
'''
RESULT_SUFFIX = b'''\n\ndef test_demonstration_marker_is_present():
    value = "deedseal"
    assert isinstance(value, str)
    assert len(value.strip()) > 0
'''
RESULT = SEED + RESULT_SUFFIX


def fail(reason: str) -> int:
    sys.stderr.write(f"ROUND_TRIP_V2_TARGET: BLOCK {reason}\n")
    return 1


def _execute_contract(source: bytes, require_marker: bool) -> None:
    namespace: dict[str, object] = {}
    exec(compile(source, str(TARGET), "exec"), namespace)
    seed = namespace.get("test_seed_is_present")
    marker = namespace.get("test_demonstration_marker_is_present")
    if not callable(seed):
        raise RuntimeError("missing seed test")
    seed()
    if require_marker:
        if not callable(marker):
            raise RuntimeError("missing result test")
        marker()
    elif marker is not None:
        raise RuntimeError("unexpected result test in seed")


def main() -> int:
    try:
        source = TARGET.read_bytes()
    except OSError:
        return fail("missing_target")
    if source == SEED:
        try:
            _execute_contract(source, require_marker=False)
        except Exception:
            return fail("seed_contract_failed")
        print(f"ROUND_TRIP_V2_TARGET: SEED sha256={hashlib.sha256(source).hexdigest()}")
        return 0
    if source == RESULT:
        try:
            _execute_contract(source, require_marker=True)
        except Exception:
            return fail("result_contract_failed")
        print(f"ROUND_TRIP_V2_TARGET: RESULT sha256={hashlib.sha256(source).hexdigest()}")
        return 0
    return fail("unexpected_target_bytes")


if __name__ == "__main__":
    raise SystemExit(main())
