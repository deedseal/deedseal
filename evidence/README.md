# Public evidence records

This directory contains evidence records for claims published by Deedseal. A
record may be a sanitized summary of private verification or a reproducible
measurement over public files. The records are designed for traceability without
publishing private source or operational detail.

## Evidence classes

- `internal-ci-attestation` — a fixed private-source snapshot and its acceptance
  workflow were inspected; the public record summarizes the result.
- `public-attestation` — a public signed or hashed artifact supports a claim,
  while some underlying inputs remain private.
- `public-reproducible` — public source and artifacts are sufficient to repeat
  the check.

The `DS-2026.08.1` snapshot was prepared on 2026-08-04. It contained both
internal attestations and five public-reproducible evidence records: two
published passport demonstrations, the refusal-coverage survey, the Ubuntu
filesystem-boundary replay, and the cross-implementation conformance result.

The current snapshot `DS-2026.08.2` was prepared on 2026-08-12 and is a
**review candidate**, not a published snapshot. It preserves every record of
`DS-2026.08.1` unchanged and adds seven sanitized `internal-ci-attestation`
records, `EVD-OFFICE-0002` through `EVD-OFFICE-0008`, for one night of live
work on the read side of a derived graph memory. Those seven are summarized for
a reader by the [proof index](../docs/proof/2026-08-12-neural-memory.md); six of
them record a refusal or a correction. None of them is publicly reproducible,
and the publication gate refuses a review-candidate snapshot on the default
branch.

## What the hashes prove

The ledger stores the SHA-256 digest of each **public sanitized record**. The
digest binds a ledger entry to the exact record bytes inside the same snapshot
and detects an accidental record/ledger mismatch. Because both files can be
changed together, it does not independently anchor immutability. It also does
not reveal or prove private source contents and is not presented as independent
certification.

## Published artifacts

`examples/verified/` holds two published run passports, their byte-tampered twins, and the exact pre-run and post-run bytes of the files the runs changed. A published passport carries the commit identifiers of the private repository the run happened in; they are disclosed deliberately as part of the record, so the publication gate scopes its commit-shaped disclosure rule out of that directory and nowhere else. The generated [run index](../examples/verified/runs.md) lists both published supervised runs.

A separate controlled run's exact result bytes are published at `app/product/demo/test_demonstration_contract.py`. No passport for that run is published; the sanitized record `EVD-CORE-0004` describes it. It is distinct from the two supervised runs whose passports are published under `examples/verified/`.

The refusal corpus and survey are published at `demo/refusals/` and
`tools/survey_refusals.py`. Record `EVD-PUBLIC-0001` binds the formal `39 / 35 /
4` claim to those mechanically evaluated public inputs.

## Layout

- [`ledger-v1.json`](ledger-v1.json) maps claims to evidence.
- [`records/`](records/) contains the public evidence objects.
- [`../schemas/`](../schemas/) defines their contracts.
- [`../tools/validate_public_record.py`](../tools/validate_public_record.py)
  validates references, digests, allowed statuses, redaction codes, and public
  disclosure rules.
