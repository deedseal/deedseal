# Product roadmap from public evidence

This roadmap is a status view of
[`build-journal/index.v1.json`](build-journal/index.v1.json), not a delivery
calendar. It records no dates or capabilities beyond its public coordinates.
The checker requires every entry below to match the JSON status and evidence
grade exactly.

<!-- journal-status-vocabulary: PROVED | IN_REVIEW | IN_DEVELOPMENT | BLOCKED | FAILED | PLANNED | UNKNOWN -->
<!-- journal-evidence-vocabulary: PUBLIC_REPRODUCIBLE | PUBLIC_OBSERVED | PUBLIC_PROPOSAL | UNKNOWN -->

## PROVED

- `PBJ-0001` — **Two run passports verify, and one-byte twins are refused.**
  Offline, fixed-input verification is publicly reproducible; the result stays
  bounded to the two records and pinned verifier keys.
  <!-- journal-entry: PBJ-0001 | PROVED | PUBLIC_REPRODUCIBLE -->
- `PBJ-0002` — **The public refusal corpus exercises 35 declared reasons.**
  The hostile corpus makes exact refusal outcomes repeatable.
  <!-- journal-entry: PBJ-0002 | PROVED | PUBLIC_REPRODUCIBLE -->
- `PBJ-0003` — **A recorded filesystem boundary can be replayed on Linux.**
  Compatible readers can re-observe the limited filesystem behavior.
  <!-- journal-entry: PBJ-0003 | PROVED | PUBLIC_REPRODUCIBLE -->
- `PBJ-0004` — **Python and Go agree on 48 passport vectors.**
  The two project-built implementations agree on the committed corpus only.
  <!-- journal-entry: PBJ-0004 | PROVED | PUBLIC_REPRODUCIBLE -->
- `PBJ-0005` — **v0.2.0 prerelease coordinate and release assets.**
  A protected source tag and bounded release inventory are publicly observable;
  they do not establish general availability.
  <!-- journal-entry: PBJ-0005 | PROVED | PUBLIC_OBSERVED -->

## IN_REVIEW

- `PBJ-0007` — **Brand Identity v1.0 remains a review candidate.**
  Candidate bytes and checks exist, without an adopted-identity claim.
  <!-- journal-entry: PBJ-0007 | IN_REVIEW | PUBLIC_OBSERVED -->

## IN_DEVELOPMENT

- `PBJ-0006` — **Offline-verifier maintenance remains active.**
  The public status is active; no additional capability is inferred.
  <!-- journal-entry: PBJ-0006 | IN_DEVELOPMENT | PUBLIC_OBSERVED -->

## BLOCKED

No entry has a qualifying public immutable object that records an unmet
precondition. This empty state is explicit; it is not evidence that no private
blocker exists.

## FAILED

- `PBJ-0008` — **The public landing relaunch was reversed.**
  The protected history preserves both the attempt and the revert.
  <!-- journal-entry: PBJ-0008 | FAILED | PUBLIC_OBSERVED -->
- `PBJ-0014` — **The tagged claim-count policy disagrees with the ledger.**
  The immutable cutoff preserves a two-versus-five public documentation drift.
  <!-- journal-entry: PBJ-0014 | FAILED | PUBLIC_OBSERVED -->

## PLANNED

- `PBJ-0009` — **Resource and network-egress bounds remain planned.**
  They remain open objectives rather than proved controls.
  <!-- journal-entry: PBJ-0009 | PLANNED | PUBLIC_PROPOSAL -->
- `PBJ-0010` — **Proof Check is a proposal, not a shipped tool.**
  The bounded concept has no public installable or reproducible product artifact.
  <!-- journal-entry: PBJ-0010 | PLANNED | PUBLIC_PROPOSAL -->

## UNKNOWN

- `PBJ-0011` — **Canonical portal availability is not established by GitHub evidence.**
  A public Pages run does not bind the canonical domain's current response bytes.
  <!-- journal-entry: PBJ-0011 | UNKNOWN | UNKNOWN -->
- `PBJ-0012` — **Cockpit and local-inference capability remain unknown.**
  The protected public evidence cutoff has no qualifying capability coordinate.
  <!-- journal-entry: PBJ-0012 | UNKNOWN | UNKNOWN -->
- `PBJ-0013` — **Marketplace, partner, connector-effect, and production state remain unknown.**
  No qualifying public immutable artifact establishes those states or effects.
  <!-- journal-entry: PBJ-0013 | UNKNOWN | UNKNOWN -->

Entry-level sources, limitations, and reproduction boundaries are in the
[human journal](build-journal/README.md). A future change moves an entry only by
changing the machine record and passing the same hostile validation again.
