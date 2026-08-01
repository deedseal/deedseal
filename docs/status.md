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
| Public verifier release | A published verifier anyone can run | planned |

States are drawn from a fixed set: `active`, `draft`, `planned`, `paused`.

## What done means

Each workstream closes against stated acceptance criteria, not dates. There are no calendar promises in this repository.

## Updates

This file is the single source of status for Deedseal's public documentation. Entries are dated, latest first.

- **2026-08-01** — Initial public documentation and machine-validated evidence record (snapshot `DS-2026.08.1`).
