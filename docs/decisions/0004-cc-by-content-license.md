# 0004 — Repository content is CC BY 4.0; product source stays proprietary

- Status: accepted
- Date: 2026-08-01

## Context

The repository publishes documentation, schemas, sanitized evidence, and small validation tools — but represents a proprietary product whose source is private. Readers need certainty about what they may reuse, and the company needs certainty about what it has not granted.

## Decision

Everything in this repository is licensed under Creative Commons Attribution 4.0 (`LICENSE`), including the validation tools, which carry SPDX identifiers. `NOTICE.md` states explicitly that no rights to the private product source, implementation, or marks are granted by this publication.

## Consequences

- Documentation, diagrams, and the evidence format can be quoted and reused with attribution — useful for coverage and diligence.
- The public/private rights boundary is written down in two short files instead of implied.
- If substantial standalone code is ever published here, a code license (for example Apache-2.0) should be a new decision; CC BY is acceptable for the current small tools but is not a conventional code license.
