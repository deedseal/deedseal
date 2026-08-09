#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
browser=""
for candidate in google-chrome google-chrome-stable chromium chromium-browser; do
  if command -v "$candidate" >/dev/null 2>&1; then
    browser="$candidate"
    break
  fi
done
if [[ -z "$browser" ]]; then
  printf 'WASM_BROWSER_UI: FAIL no headless browser is available\n' >&2
  exit 1
fi

server_log="$(mktemp "${TMPDIR:-/tmp}/deedseal-wasm-server.XXXXXX")"
page_dump="$(mktemp "${TMPDIR:-/tmp}/deedseal-wasm-page.XXXXXX")"
browser_log="$(mktemp "${TMPDIR:-/tmp}/deedseal-wasm-browser.XXXXXX")"
python3 -m http.server 8123 --bind localhost --directory "$repo_root" >"$server_log" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; rm -f "$server_log" "$page_dump" "$browser_log"' EXIT

ready=false
for _ in $(seq 1 50); do
  if curl --fail --silent http://localhost:8123/verifiers/wasm/demo/ >/dev/null; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  cat "$server_log" >&2
  exit 1
fi

if ! "$browser" --headless --no-sandbox --disable-gpu --disable-background-networking \
  --no-first-run --no-default-browser-check --virtual-time-budget=30000 --dump-dom \
  http://localhost:8123/verifiers/wasm/demo/ >"$page_dump" 2>"$browser_log"; then
  cat "$browser_log" >&2
  exit 1
fi

if ! grep -Fq 'Offline verification complete. No network service was used.' "$page_dump" || \
  [[ "$(grep -Fc 'published passport: RUN_PASSPORT_VERDICT: PASS' "$page_dump")" -ne 2 ]] || \
  [[ "$(grep -Fc 'tampered twin: RUN_PASSPORT_VERDICT: BLOCK' "$page_dump")" -ne 2 ]] || \
  ! grep -Fq 'Self-selected one-byte probe:' "$page_dump" || \
  ! grep -Fq 'Restored published bytes: RUN_PASSPORT_VERDICT: PASS' "$page_dump"; then
  cat "$page_dump" >&2
  exit 1
fi
printf 'WASM_BROWSER_UI: PASS two published runs; PASS/BLOCK; self-selected flip; restore PASS\n'
