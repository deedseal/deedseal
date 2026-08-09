#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
native_binary="$(mktemp "${TMPDIR:-/tmp}/deedseal-go-verifier.XXXXXX")"
trap 'rm -f "$native_binary"' EXIT

if [[ ! -f "$repo_root/verifiers/wasm/deedseal-verifier.wasm.manifest.json" ]]; then
  printf 'WASM_CHECK: FAIL build the WebAssembly bundle first\n' >&2
  exit 1
fi

(
  cd "$repo_root/verifiers/go"
  go build -trimpath -o "$native_binary" .
)
node "$repo_root/verifiers/wasm/check_wasm.mjs" "$native_binary"
