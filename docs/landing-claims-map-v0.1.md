# Landing claims map v0.1

This map is the public landing's sentence-level claim contract. Every product statement
in the marked landing scope bears `data-landing-statement` and appears exactly once
below; the remaining headings and explanatory copy are fixed support text validated by
the same gate. A `claim` row is constrained by the public evidence ledger. A
`design-target` row is explicitly not a shipped capability. A `status` or `boundary`
row is a visible limit rather than a product-capability claim.

The validator refuses an unknown claim ID, a status mismatch, a missing or edited mapped
sentence, a missing honest boundary, a drifted published-run count, and an
implemented-tense graph-memory statement.

<!-- landing-claims-map:start -->
| Key | Kind | CLM IDs | Status | Evidence or status source | Exact page sentence |
| --- | --- | --- | --- | --- | --- |
| LND-TWO-BOXES | design-target | — | design-target | docs/status.md#updates | Deedseal is being built toward a self-hosted two-box platform: a storage box keeps the record and an operations box runs governed work. Design target — not shipped. |
| LND-GITHUB-SPINE | claim | CLM-0004 | internally-verified | EVD-OFFICE-0001 | In the documented control path, repository files are the record: an owner-selected commit binds immutable task bytes, bounded write scope, and draft-only automation authority. |
| LND-GITHUB-OWNER | claim | CLM-0004, CLM-0005 | internally-verified | EVD-OFFICE-0001 | Postflight leaves readiness, approval, and merge as Owner actions; draft-only automation has no merge authority. |
| LND-LINUX-CELLS | status | — | engineering-reported | docs/status.md#updates | A 13-property live observation of Linux-native execution cells is engineering-reported; it is not a public capability claim. |
| LND-LINUX-DIRECTION | design-target | — | design-target | docs/status.md#updates | For untrusted agents, disposable Linux execution cells are a design target — not shipped. |
| LND-LINUX-BOUNDARY | claim | CLM-0011 | public-reproducible | EVD-PUBLIC-0002 | The published Ubuntu probe permits the recorded file write and refuses file creation, directory creation, symbolic-link creation, and unlink. |
| LND-PASSPORT-RECORD | claim | CLM-0002 | internally-verified | EVD-CORE-0001 | In the documented controlled path, a current run closes into a passport that binds authorization, custody outcome, execution identity, complete committed changes, artifact hashes, acceptance data, and final owner closure. |
| LND-PASSPORT-PROOF | claim | CLM-0008, CLM-0012 | public-reproducible | EVD-CORE-0003, EVD-CORE-0005 | 2 supervised runs are published, each with its passport, its tampered twin, and the verifier. A stranger can verify each published passport and its one-byte tampered twin offline with this repository's files and a Python interpreter. |
| LND-ENVELOPE-COMMITMENT | status | — | record-compatibility | docs/status.md#updates | The published record format is frozen at deedseal-run-passport/1.0 — a passport that verifies today keeps verifying, and new capability arrives as a new version, never as a silent change to this one. |
| LND-COCKPIT | status | — | active-build | docs/status.md#updates | The Owner cockpit is the human's control surface in active build; it is not yet a delivered product capability. |
| LND-GRAPH-MEMORY | design-target | — | design-target | docs/status.md#updates | Graph memory is planned as derived answers over the record and has no authority. Design target — not shipped. |
| LND-HYBRID-MODEL | design-target | — | design-target | docs/status.md#updates | The operating model is being built so the platform executes while the human is the governing element. Design target — not shipped. |
| LND-HUMAN-CONTROL | claim | CLM-0001, CLM-0005 | internally-verified | EVD-CORE-0001, EVD-OFFICE-0001 | In the documented controlled path, an owner-signed, scope-bound grant admits controlled effects; Owner action remains required for readiness, approval, and merge. |
| LND-VERIFY-YOURSELF | claim | CLM-0008 | public-reproducible | EVD-CORE-0003 | Run the published offline verifier against a passport and its one-byte tampered twin with this repository's files and a Python interpreter. |
| LND-REFUSAL-COVERAGE | claim | CLM-0010 | public-reproducible | EVD-PUBLIC-0001 | The published verifier declares 39 refusal reasons; the published mutation corpus demonstrates 35 exact refusal verdicts and classifies 4 as not reachable by mutation of the published bytes. |
| LND-VERIFY-BOUNDARY | boundary | — | required | docs/verify.md#what-a-pass-does-not-prove | This check verifies published signed bytes and tamper detection; it does not reproduce a run, prove semantic correctness, or make the owner-controlled keys independent. |
| LND-INDEPENDENT-REVIEW | status | — | required-boundary | docs/status.md#updates | Honest boundary: no part of this work has had independent human review. |
| LND-COMMERCIAL-STATUS | status | — | active-development | docs/status.md#updates | Deedseal is in active development. Pricing and sales are not open; they will open only after the full working state is reached. |
<!-- /landing-claims-map:end -->
