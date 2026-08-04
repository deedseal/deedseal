#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the language-neutral passport conformance vectors."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "examples" / "verified" / "conformance" / "manifest.json"
VERIFIER = REPO_ROOT / "tools" / "verify_run_passport.py"
SCHEMA_VERSION = "deedseal.passport-conformance/v1"
INPUT_KINDS = frozenset({"file", "absent", "directory"})
MANIFEST_FIELDS = frozenset({"schema_version", "specification", "vectors"})
VECTOR_REQUIRED_FIELDS = frozenset(
    {"id", "why", "input", "expect_verdict", "expect_exit_code"}
)
VECTOR_OPTIONAL_FIELDS = frozenset({"expect_reason", "input_kind"})
VERDICT_PREFIX = "RUN_PASSPORT_VERDICT: "


class ConformanceError(RuntimeError):
    pass


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ConformanceError(f"{label} must be an object with string keys")
    return value


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConformanceError(f"manifest unreadable: {exc}") from exc
    manifest = _object(document, "manifest")
    if set(manifest) != MANIFEST_FIELDS:
        raise ConformanceError("manifest fields do not match the closed contract")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ConformanceError("manifest schema_version is unsupported")
    if manifest["specification"] != "docs/passport-spec-v1.md":
        raise ConformanceError("manifest specification path is unexpected")
    if not isinstance(manifest["vectors"], list) or not manifest["vectors"]:
        raise ConformanceError("manifest vectors must be a non-empty array")
    return manifest


def _vector_path(manifest_path: Path, raw: object, vector_id: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ConformanceError(f"{vector_id}: input must be a non-empty string")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ConformanceError(f"{vector_id}: input must stay below the manifest directory")
    return manifest_path.parent / relative


def _verdict_lines(completed: subprocess.CompletedProcess[str]) -> list[str]:
    return [
        line.strip()
        for stream in (completed.stdout, completed.stderr)
        for line in stream.splitlines()
        if line.strip().startswith(VERDICT_PREFIX)
    ]


def evaluate_manifest(manifest_path: Path = DEFAULT_MANIFEST) -> list[dict[str, object]]:
    manifest = load_manifest(manifest_path)
    results: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for offset, raw_vector in enumerate(manifest["vectors"]):
        vector = _object(raw_vector, f"vector {offset}")
        vector_id = vector.get("id")
        if not isinstance(vector_id, str) or not vector_id:
            raise ConformanceError(f"vector {offset}: id must be a non-empty string")
        if vector_id in seen_ids:
            raise ConformanceError(f"{vector_id}: duplicate vector id")
        seen_ids.add(vector_id)
        fields = set(vector)
        if not VECTOR_REQUIRED_FIELDS <= fields or not fields <= (
            VECTOR_REQUIRED_FIELDS | VECTOR_OPTIONAL_FIELDS
        ):
            raise ConformanceError(f"{vector_id}: fields do not match the closed contract")
        if not isinstance(vector["why"], str) or not vector["why"]:
            raise ConformanceError(f"{vector_id}: why must be a non-empty string")

        input_kind = vector.get("input_kind", "file")
        if input_kind not in INPUT_KINDS:
            raise ConformanceError(f"{vector_id}: unknown input_kind {input_kind!r}")
        input_path = _vector_path(manifest_path, vector["input"], vector_id)
        if input_kind == "file" and not input_path.is_file():
            raise ConformanceError(f"{vector_id}: file input does not exist")
        if input_kind == "absent" and input_path.exists():
            raise ConformanceError(f"{vector_id}: absent input unexpectedly exists")
        if input_kind == "directory" and not input_path.is_dir():
            raise ConformanceError(f"{vector_id}: directory input does not exist")

        expected_verdict = vector["expect_verdict"]
        expected_code = vector["expect_exit_code"]
        expected_reason = vector.get("expect_reason")
        if expected_verdict not in {"PASS", "BLOCK"}:
            raise ConformanceError(f"{vector_id}: expect_verdict must be PASS or BLOCK")
        if type(expected_code) is not int or expected_code not in {0, 1}:
            raise ConformanceError(f"{vector_id}: expect_exit_code must be 0 or 1")
        if expected_verdict == "PASS":
            if expected_code != 0 or "expect_reason" in vector:
                raise ConformanceError(f"{vector_id}: PASS contract is inconsistent")
            expected_line = VERDICT_PREFIX + "PASS"
        elif input_kind in {"absent", "directory"}:
            if expected_code != 1 or "expect_reason" in vector:
                raise ConformanceError(f"{vector_id}: unreadable-path contract is inconsistent")
            expected_line = VERDICT_PREFIX + "BLOCK passport_unreadable ("
        else:
            if expected_code != 1 or not isinstance(expected_reason, str) or not expected_reason.startswith("block_"):
                raise ConformanceError(f"{vector_id}: BLOCK file vector needs a block_* reason")
            expected_line = VERDICT_PREFIX + "BLOCK " + expected_reason

        completed = subprocess.run(
            [sys.executable, str(VERIFIER), str(input_path)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        verdicts = _verdict_lines(completed)
        observed = verdicts[0] if len(verdicts) == 1 else repr(verdicts)
        line_matches = (
            len(verdicts) == 1
            and (
                verdicts[0].startswith(expected_line)
                if input_kind in {"absent", "directory"}
                else verdicts[0] == expected_line
            )
        )
        results.append(
            {
                "id": vector_id,
                "expected_reason": expected_reason,
                "observed": observed,
                "returncode": completed.returncode,
                "passed": completed.returncode == expected_code and line_matches,
            }
        )
    return results


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) > 1:
        print("CONFORMANCE_SUITE: FAIL usage: check_conformance.py [manifest]")
        return 2
    manifest_path = Path(arguments[0]).resolve() if arguments else DEFAULT_MANIFEST
    try:
        results = evaluate_manifest(manifest_path)
    except ConformanceError as exc:
        print(f"CONFORMANCE_SUITE: FAIL {exc}")
        return 1
    failures = 0
    for result in results:
        status = "PASS" if result["passed"] else "FAIL"
        print(
            f"{result['id']}: {status} exit {result['returncode']} "
            f"{result['observed']}"
        )
        failures += 0 if result["passed"] else 1
    if failures:
        print(f"CONFORMANCE_SUITE: FAIL {failures} of {len(results)} vectors failed")
        return 1
    print(f"CONFORMANCE_SUITE: PASS {len(results)} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
