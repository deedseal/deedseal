# 0006 — Publish the offline verifier under Apache-2.0

- Status: accepted
- Date: 2026-08-02

## Context

A public record of claims is weaker than a public artifact a reader can check. The next step is a published demonstration: a real run passport, produced by a supervised run against a demonstration target in a private engineering repository, with the changed file's exact bytes published here, alongside the offline verifier that renders the verdict. The verifier is the one piece of product source code published here, and this repository's content license (CC BY 4.0, decision 0004) is not a code license.

## Decision

The offline verifier is published in this repository as a single standard-library Python file under **Apache-2.0**, carrying an SPDX identifier. Everything else in the repository remains CC BY 4.0; `NOTICE.md` records the split. The verifier ships with the public keys it pins, as literals, and accepts no key from any other channel.

Two artifacts accompany it: a real passport that verifies, and a byte-tampered twin that does not. Continuous integration runs the verifier against both on every change and requires exactly PASS and BLOCK, so the demonstration is re-proven rather than asserted.

## Consequences

- Readers can check the claim themselves; the corresponding claim moves from `internally-verified` to `public-reproducible`, a class the ledger did not previously carry.
- Apache-2.0 grants a patent license for the published file — deliberate, and the reason a permissive code license was chosen over the content license.
- The published public keys tie this repository to the signing lineage that produced the passport; forward-only key rotation remains the mechanism for retiring an anchor.
- Publishing a verifier invites scrutiny of its logic. That is the point: a verifier nobody can read is a verifier nobody should trust.
