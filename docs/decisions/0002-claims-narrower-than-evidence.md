# 0002 — Every public claim must be narrower than its evidence, machine-validated

- Status: accepted
- Date: 2026-08-01

## Context

Public statements about a security-relevant product tend to drift wider than their evidence — in README prose, in About lines, in future edits by future authors. Discipline that lives only in habit does not survive authorship changes.

## Decision

Machine-readable claims live in `evidence/ledger-v1.json`, each bound to a dated snapshot, an evidence record, a status from a closed set, and explicit limitations. The validation gate rejects prohibited claim vocabulary (for example "secure", "production-ready", "unique"), enforces exact field sets, verifies record digests, and requires every claim and evidence identifier to appear in the README and the properties document. The gate runs identically in CI and locally.

## Consequences

- A claim cannot be added or widened without passing review and the gate; marketing language in claim statements is mechanically impossible.
- Honesty markers ("internally-verified", limitations) are part of the data model, not editorial goodwill.
- The ledger costs maintenance: every snapshot update must keep hashes, statements, and documents consistent — the gate makes drift loud instead of silent.
