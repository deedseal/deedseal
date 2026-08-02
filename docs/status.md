# Status

## Maturity

Deedseal is in active development. The authorization, signing, quarantine, custody, and offline-verification chain is implemented and has been exercised end to end in development. The passport format is not frozen. Kernel-level sandboxing of the agent process is an open objective, not a shipped property. Deedseal is not yet available for production use, and no performance or economic claims are made.

## Workstreams

| Workstream | Scope | State |
| --- | --- | --- |
| Authorization and signed-grant chain | Owner-signed grants, deny-by-default gate, effect broker, OS-principal separation | active |
| Run passport format | The evidence record and what it binds | draft — not frozen |
| Offline verifier | Single-file, standard-library verification against pinned keys | active |
| Kernel-enforcement objectives | Resource bounds, egress bounds, grant-derived kernel sandboxing of the agent | planned |
| Unattended dispatch of agent work | Queue-driven execution of bounded task packets | draft — designed, fail-closed, not adopted |
| Public evidence record | Machine-validated claims, sanitized records, CI-checked disclosure rules | active |
| Public passport specification | A versioned, published format specification | planned |
| Public verifier release | A published verifier anyone can run, under Apache-2.0 | active |
| Published demonstration | A real passport, a byte-tampered twin, and the verifier, re-checked by CI on every change | active |

States are drawn from a fixed set: `active`, `draft`, `planned`, `paused`. A state may carry a short qualifier after an em dash; the state is the leading token.

## What done means

Each workstream closes against acceptance criteria, not dates. There are no calendar promises in this repository. Two criteria are stated here because they are already agreed:

- **Public verifier release** closes when the offline verifier is published here under Apache-2.0 and runs on a published passport from a clean checkout with no network.
- **Published demonstration** closes when a real passport and its byte-tampered twin are published, continuous integration asserts PASS on one and BLOCK on the other across every supported platform, and the corresponding claim is recorded as `public-reproducible`.

## Updates

This file is the single source of status for Deedseal's public documentation. Entries are dated, latest first.

- **2026-08-02** — Decision 0006 accepted (publish the offline verifier under Apache-2.0); demonstration target added at `demo/`; brand assets published as source; publication gate hardened (required-file set, SPDX policy, README-to-ledger equality, scoped disclosure rules).
- **2026-08-01** — Initial public documentation and machine-validated evidence record (snapshot `DS-2026.08.1`).
