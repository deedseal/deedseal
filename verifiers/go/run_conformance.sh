#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
binary="$(mktemp "${TMPDIR:-/tmp}/deedseal-go-verifier.XXXXXX")"
trap 'rm -f "$binary"' EXIT

cd "$repo_root/verifiers/go"
go build -trimpath -o "$binary" .
cd "$repo_root"

python3 - "$binary" <<'PY'
# SPDX-License-Identifier: Apache-2.0
import json
import pathlib
import subprocess
import sys

binary = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path("examples/verified/conformance/manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
failures = 0
for vector in manifest["vectors"]:
    path = manifest_path.parent / vector["input"]
    completed = subprocess.run(
        [str(binary), str(path)], capture_output=True, text=True, check=False
    )
    lines = [
        line.strip()
        for stream in (completed.stdout, completed.stderr)
        for line in stream.splitlines()
        if line.strip().startswith("RUN_PASSPORT_VERDICT: ")
    ]
    kind = vector.get("input_kind", "file")
    if vector["expect_verdict"] == "PASS":
        expected = "RUN_PASSPORT_VERDICT: PASS"
        line_ok = lines == [expected]
    elif kind in {"absent", "directory"}:
        expected = "RUN_PASSPORT_VERDICT: BLOCK passport_unreadable ("
        line_ok = len(lines) == 1 and lines[0].startswith(expected)
    else:
        expected = "RUN_PASSPORT_VERDICT: BLOCK " + vector["expect_reason"]
        line_ok = lines == [expected]
    passed = completed.returncode == vector["expect_exit_code"] and line_ok
    print(
        f"{vector['id']}: {'PASS' if passed else 'FAIL'} "
        f"exit {completed.returncode} {lines[0] if len(lines) == 1 else lines!r}"
    )
    failures += not passed
if failures:
    print(f"GO_CONFORMANCE: FAIL {failures} of {len(manifest['vectors'])} vectors failed")
    raise SystemExit(1)
print(f"GO_CONFORMANCE: PASS {len(manifest['vectors'])} vectors")
PY
