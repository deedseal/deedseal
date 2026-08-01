# Public evidence records

This directory contains sanitized evidence summaries for claims published by
Deedseal. The records are designed for traceability without publishing private
source or operational detail.

## Evidence classes

- `internal-ci-attestation` — a fixed private-source snapshot and its acceptance
  workflow were inspected; the public record summarizes the result.
- `public-attestation` — a public signed or hashed artifact supports a claim,
  while some underlying inputs remain private.
- `public-reproducible` — public source and artifacts are sufficient to repeat
  the check.

The `DS-2026.08.1` snapshot contains only `internal-ci-attestation` records.

## What the hashes prove

The ledger stores the SHA-256 digest of each **public sanitized record**. The
digest binds a ledger entry to the exact record bytes inside the same snapshot
and detects an accidental record/ledger mismatch. Because both files can be
changed together, it does not independently anchor immutability. It also does
not reveal or prove private source contents and is not presented as independent
certification.

## Layout

- [`ledger-v1.json`](ledger-v1.json) maps claims to evidence.
- [`records/`](records/) contains the public evidence objects.
- [`../schemas/`](../schemas/) defines their contracts.
- [`../tools/validate_public_record.py`](../tools/validate_public_record.py)
  validates references, digests, allowed statuses, redaction codes, and public
  disclosure rules.
