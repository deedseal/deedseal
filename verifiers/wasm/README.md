# Browser WebAssembly verifier

`deedseal-verifier.wasm.manifest.json` and its UTF-8 base64 chunks are the
public-text-safe transport form of a binary WASM artifact compiled from the
same Go package as the native second verifier:
`verifiers/go`. The browser entry point only turns a
`Uint8Array` into bytes and renders the common verifier result; it contains no
independent PASS/BLOCK logic.

Build the checked-in browser bundle with Go 1.24.9:

```text
GO=/path/to/go1.24.9/bin/go verifiers/wasm/build.sh
```

To run the offline browser proof, serve the repository root locally and open
`/verifiers/wasm/demo/` in a browser:

```text
python3 -m http.server
```

The page fetches only relative files from the checkout. It verifies both
published runs and their tampered twins (`PASS` / `BLOCK`), exposes a hex view
where a visitor can flip any selected byte and inspect the actual WASM verdict,
then restores the published bytes to `PASS`. Its probe also selects its own
one-byte mutation instead of relying on the demo's stored twin.

After building, run the native/WASM agreement and browser-bundle proof:

```text
PATH=/path/to/go1.24.9/bin:$PATH verifiers/wasm/run_checks.sh
```

The Deedseal verifier source and its WASM transport remain Apache-2.0
under [`LICENSE`](LICENSE), matching `verifiers/go`. `wasm_exec.js` comes from
Go 1.24.9 with URL-only comments scrubbed for the public-record policy; its
upstream BSD terms are preserved in [`GO-LICENSE`](GO-LICENSE).
