# Status

## Maturity

Deedseal is in active development. The authorization, signing, quarantine, custody, and offline-verification chain is implemented and has been exercised end to end in development; two supervised runs are published with offline-verifiable passports and one-byte tampered twins ([run index](../examples/verified/runs.md)), while a separate controlled run is published as a sanitized record only. The published passport envelope is frozen under a stated compatibility commitment; new capability arrives as a new version. Grant-derived filesystem confinement is applied by the kernel and recorded in the published run passports; resource and egress bounds remain open objectives. Deedseal is not yet available for production use, and no performance or economic claims are made.

## Workstreams

| Workstream | Scope | State |
| --- | --- | --- |
| Authorization and signed-grant chain | Owner-signed grants, deny-by-default gate, effect broker, OS-principal separation | active |
| Run passport format | The evidence record and what it binds | closed — frozen at `deedseal-run-passport/1.0` ([passport-spec-v1.md](passport-spec-v1.md)) |
| Offline verifier | Single-file, standard-library verification against pinned keys | active |
| Kernel-enforcement objectives | Resource bounds, egress bounds, grant-derived kernel sandboxing of the agent | active — filesystem write confinement is applied and recorded ([verify.md](verify.md)); resource and egress bounds remain planned |
| Unattended dispatch of agent work | Queue-driven execution of bounded task packets | draft — designed, fail-closed, not adopted |
| Public evidence record | Machine-validated claims, sanitized records, CI-checked disclosure rules | active |
| Public passport specification | A versioned, published format specification | closed — [passport-spec-v1.md](passport-spec-v1.md) |
| Public verifier release | A published verifier anyone can run, under Apache-2.0 | closed — `tools/verify_run_passport.py` |
| Published demonstrations | Two real passports, their byte-tampered twins, and the verifier, re-checked by CI on every change | closed — [verify.md](verify.md) and [run index](../examples/verified/runs.md) |
| Second controlled run | A byte-frozen public target moved from seed to precommitted result | closed — EVD-CORE-0004, no published passport |
| Operations appliance (two-box product form) | A storage box holding the record, and an operations box running the business runtime in disposable Linux virtual machines; derived graph memory; GitHub-native owner gates | draft — design target; no implemented capability is claimed |

States are drawn from a fixed set: `active`, `draft`, `planned`, `paused`, `closed`. A state may carry a short qualifier after an em dash; the state is the leading token. `closed` means the workstream's acceptance criteria are met; closed rows stay in the table.

## What done means

Each workstream closes against acceptance criteria, not dates. There are no calendar promises in this repository. Five workstreams have closed against the criteria that were stated here in advance:

- **Public verifier release** closed: the offline verifier is published here under Apache-2.0 and runs on a published passport from a clean checkout with no network.
- **Published demonstrations** closed: two real passports and their byte-tampered twins are published, continuous integration asserts PASS on each passport and BLOCK on each twin across every supported platform, and the corresponding claims are recorded as `public-reproducible`.
- **Second controlled run** closed: a byte-frozen public target moved from its accepted seed state to its precommitted result, the exact result bytes are published, and `EVD-CORE-0004` records the sanitized attestation. No passport for that run is published.
- **Run passport format** closed: the published envelope is frozen under a stated compatibility commitment, its behaviour is pinned by 48 committed conformance vectors, and a second implementation built from the specification reaches identical verdicts on all of them.
- **Public passport specification** closed: an engineer can implement an independent verifier from the published document alone, including exact parsing, canonical bytes, signature payloads, cross-bindings, verdict order, and a refusal list generated from the verifier.

## Updates

This file is the single source of status for Deedseal's public documentation. Entries are dated, latest first.

- **2026-08-05** — The product direction is recorded as a design target: Deedseal is being built toward a self-hosted operations appliance in a two-box form — a storage box that holds the immutable record, and an operations box that executes the business runtime in disposable Linux virtual machines, with a derived graph memory and GitHub-native owner control. Per the publication policy this carries status `design-target` throughout: none of it is claimed as implemented, and each capability will arrive here only with its own published evidence. The core enforcement chain published above is unchanged by this direction.

- **2026-08-04** — The published envelope `deedseal-run-passport/1.0` is frozen under an explicit compatibility commitment: passports carrying it keep verifying, the field set stays closed, and new capability arrives as a new version rather than a silent extension. What justifies the freeze is recorded as `CLM-0013` / `EVD-PUBLIC-0003`: two implementations, in different languages with different JSON decoders and signature libraries, produce identical verdicts on all 48 published conformance vectors. Both implementations come from this project; this is not independent verification.
- **2026-08-04** — A second supervised run was published (`CLM-0012`, `EVD-CORE-0005`). Its passport, its one-byte tampered twin, and the exact before and after bytes of the changed file are under `examples/verified/run-002/`; `tools/check_runs.py` now reports two verified runs. The run was the first dispatched under authority-enforced acceptance markers.
- **2026-08-03** — The Ubuntu boundary measurement became a limited public-reproducible claim (`CLM-0011`, `EVD-PUBLIC-0002`), and [passport-spec-v1.md](passport-spec-v1.md) specified the published envelope for independent verifier implementations with a generated refusal vocabulary.

- **2026-08-03** — Refusal coverage became a formal public-reproducible claim (`CLM-0010`): 39 reasons declared by the published verifier, 35 demonstrated as exact corpus verdicts, and 4 explicitly classified as not reachable by mutation of the published bytes. The survey, evidence record, ledger statement, and landing-page counts are checked for drift.
- **2026-08-03** — Public snapshot `DS-2026.08.1` finalized after the second controlled-run record landed. The publication gate now rejects any claim or evidence observation dated after the snapshot preparation date.
- **2026-08-03** — A second controlled run produced the frozen Evidence 2 result. The staged and materialized bytes matched, the named test was absent from the seed and present exactly once in both result views, and the exact result bytes are now committed in the public target. The sanitized record is `EVD-CORE-0004`; it is intentionally `internally-verified`, not presented as a signed commit-bound passport or a publicly reproducible run.
- **2026-08-03** — Published demonstration landed: the offline verifier `tools/verify_run_passport.py` (Apache-2.0), a real run passport and its byte-tampered twin under `examples/verified/`, and the verification walkthrough [verify.md](verify.md). The demonstration run added one test function to the demonstration target, and its committed bytes are published beside the passport that binds them. Continuous integration asserts PASS on the passport and BLOCK on the twin on every change. The corresponding claim (`CLM-0008`) is recorded as `public-reproducible`; the ledger now carries a claim of that class.
- **2026-08-02** — Decision 0006 accepted (publish the offline verifier under Apache-2.0); demonstration target added at `demo/`; brand assets published as source; publication gate hardened (required-file set, SPDX policy, README-to-ledger equality, scoped disclosure rules).
- **2026-08-01** — Repository published with its initial documentation and machine-validated evidence record (snapshot `DS-2026.08.1`).
