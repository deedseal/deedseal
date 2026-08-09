#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
wasm_dir="$repo_root/verifiers/wasm"
go_binary="${GO:-go}"
runtime_source="$("$go_binary" env GOROOT)/lib/wasm/wasm_exec.js"
wasm_manifest="$wasm_dir/deedseal-verifier.wasm.manifest.json"
wasm_chunk_prefix="$wasm_dir/deedseal-verifier.wasm.base64."
runtime_output="$wasm_dir/wasm_exec.js"
temporary_wasm="$(mktemp "${TMPDIR:-/tmp}/deedseal-browser-verifier.XXXXXX")"
temporary_base64="$(mktemp "${TMPDIR:-/tmp}/deedseal-browser-verifier.XXXXXX")"
trap 'rm -f "$temporary_wasm" "$temporary_base64"' EXIT

if [[ ! -f "$runtime_source" ]]; then
  printf 'WASM_BUILD: FAIL missing Go browser runtime %s\n' "$runtime_source" >&2
  exit 1
fi

(
	cd "$repo_root/verifiers/go"
	GOOS=js GOARCH=wasm "$go_binary" build -trimpath -o "$temporary_wasm" .
)
rm -f "$wasm_dir/deedseal-verifier.wasm.base64"
shopt -s nullglob
for stale_chunk in "$wasm_dir"/deedseal-verifier.wasm.base64.[0-9][0-9][0-9]; do
	rm -f "$stale_chunk"
done
base64 < "$temporary_wasm" | tr -d '\n' > "$temporary_base64"
split -b 900000 -d -a 3 "$temporary_base64" "$wasm_chunk_prefix"
chunks=("$wasm_dir"/deedseal-verifier.wasm.base64.[0-9][0-9][0-9])
if [[ ${#chunks[@]} -eq 0 ]]; then
	printf 'WASM_BUILD: FAIL no transport chunks were created\n' >&2
	exit 1
fi
{
	printf '{\n'
	printf '  "schema_version": "deedseal-wasm-bundle/1",\n'
	printf '  "raw_bytes": %s,\n' "$(wc -c < "$temporary_wasm")"
	printf '  "base64_bytes": %s,\n' "$(wc -c < "$temporary_base64")"
	printf '  "chunks": [\n'
	for index in "${!chunks[@]}"; do
		comma=","; if [[ $index -eq $((${#chunks[@]} - 1)) ]]; then comma=""; fi
		printf '    "%s"%s\n' "$(basename "${chunks[$index]}")" "$comma"
	done
	printf '  ]\n}\n'
} > "$wasm_manifest"
# The public-record gate does not allow links to other GitHub repositories.
# Go 1.24.9 carries one such link only in a runtime comment, so scrub URLs while
# preserving the executable runtime and its copyright/license header.
sed -E 's#https?://[^[:space:])]+#upstream issue#g' "$runtime_source" > "$runtime_output"
printf 'WASM_BUILD: PASS raw %s bytes; transport %s bytes in %s chunks\n' \
	"$(wc -c < "$temporary_wasm")" "$(wc -c < "$temporary_base64")" "${#chunks[@]}"
