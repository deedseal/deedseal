# Public build journal

This journal is a public evidence index, not a marketing timeline. Its canonical
data is [`index.v1.json`](index.v1.json); this page is the human-readable view.
Each entry says what a user can rely on, the status observed from public GitHub,
the evidence grade, an exact public coordinate, and the limit of the result.

The journal uses protected semantic-version tags for repository-byte evidence.
An Issue may support a proposal and an Actions run may support an observation,
but neither can promote an entry to `PROVED`. A mutable branch URL is never
accepted as proof.

<!-- journal-status-vocabulary: PROVED | IN_REVIEW | IN_DEVELOPMENT | BLOCKED | FAILED | PLANNED | UNKNOWN -->
<!-- journal-evidence-vocabulary: PUBLIC_REPRODUCIBLE | PUBLIC_OBSERVED | PUBLIC_PROPOSAL | UNKNOWN -->

## Status vocabulary

| Status | Meaning |
| --- | --- |
| `PROVED` | A public immutable artifact is reproducible or directly observable and supports the bounded statement. |
| `IN_REVIEW` | Public candidate bytes exist, but the recorded review or adoption boundary is still open. |
| `IN_DEVELOPMENT` | Public state says work is active; no unlisted capability is inferred. |
| `BLOCKED` | A public object records an unmet precondition. An empty section means no qualifying public blocked record was found. |
| `FAILED` | Public history preserves an attempt that failed or was reversed. |
| `PLANNED` | A public proposal exists without implementation evidence. |
| `UNKNOWN` | The inspected public evidence cannot establish a more specific status. |

## Evidence grades

| Grade | Meaning |
| --- | --- |
| `PUBLIC_REPRODUCIBLE` | Public bytes and instructions are sufficient to repeat the stated check. |
| `PUBLIC_OBSERVED` | A public immutable GitHub object directly records the bounded event or state. |
| `PUBLIC_PROPOSAL` | A public plan or candidate direction exists; implementation is not established. |
| `UNKNOWN` | No qualifying public artifact establishes the capability or effect. |

## Current entries

### PBJ-0001 — Two run passports verify, and one-byte twins are refused

<!-- journal-entry: PBJ-0001 | PROVED | PUBLIC_REPRODUCIBLE -->

- User value: run the published verifier offline and observe both fixed passports
  pass while each one-byte twin is refused.
- Evidence: [`evidence/README.md` at `v0.2.0`](https://github.com/deedseal/deedseal/blob/v0.2.0/evidence/README.md), coordinate
  `deedseal/deedseal@refs/tags/v0.2.0:evidence/README.md`.
- Limit: reproducing a verdict does not reproduce either run, establish semantic
  correctness, provide independent certification, or establish wider availability.

### PBJ-0002 — The public refusal corpus exercises 35 declared reasons

<!-- journal-entry: PBJ-0002 | PROVED | PUBLIC_REPRODUCIBLE -->

- User value: replay hostile inputs and compare exact refusal outcomes instead
  of trusting a prose count.
- Evidence: [`EVD-PUBLIC-0001`](https://github.com/deedseal/deedseal/blob/v0.2.0/evidence/records/EVD-PUBLIC-0001.json), coordinate
  `deedseal/deedseal@refs/tags/v0.2.0:evidence/records/EVD-PUBLIC-0001.json`.
- Limit: the `39 / 35 / 4` boundary belongs to this tagged verifier and corpus;
  it does not establish completeness or semantic correctness.

### PBJ-0003 — A recorded filesystem boundary can be replayed on Linux

<!-- journal-entry: PBJ-0003 | PROVED | PUBLIC_REPRODUCIBLE -->

- User value: on a compatible Linux kernel, observe the recorded rule permit the
  named write and refuse four out-of-scope operation classes.
- Evidence: [`EVD-PUBLIC-0002`](https://github.com/deedseal/deedseal/blob/v0.2.0/evidence/records/EVD-PUBLIC-0002.json), coordinate
  `deedseal/deedseal@refs/tags/v0.2.0:evidence/records/EVD-PUBLIC-0002.json`.
- Limit: this is a replay of recorded filesystem-write rules, not a rerun and not
  evidence of resource or network bounds.

### PBJ-0004 — Python and Go agree on 48 passport vectors

<!-- journal-entry: PBJ-0004 | PROVED | PUBLIC_REPRODUCIBLE -->

- User value: compare exact verdict lines and exit codes from two implementations
  over one language-neutral corpus.
- Evidence: [`EVD-PUBLIC-0003`](https://github.com/deedseal/deedseal/blob/v0.2.0/evidence/records/EVD-PUBLIC-0003.json), coordinate
  `deedseal/deedseal@refs/tags/v0.2.0:evidence/records/EVD-PUBLIC-0003.json`.
- Limit: both implementations are project-built, and agreement covers only the
  48 committed vectors.

### PBJ-0005 — v0.2.0 prerelease coordinate and release assets

<!-- journal-entry: PBJ-0005 | PROVED | PUBLIC_OBSERVED -->

- User value: inspect a protected source tag plus the public manifest and checksum
  inventory for the bounded distribution surface.
- Evidence: [GitHub Release `v0.2.0`](https://github.com/deedseal/deedseal/releases/tag/v0.2.0),
  coordinate `deedseal/deedseal@refs/tags/v0.2.0`.
- Limit: the coordinate covers a prerelease public record and verifier surface,
  not general availability or production qualification; its checksum inventory
  is not a signature.

### PBJ-0006 — Offline-verifier maintenance remains active

<!-- journal-entry: PBJ-0006 | IN_DEVELOPMENT | PUBLIC_OBSERVED -->

- User value: distinguish the already published verifier from continuing work
  that has not earned another `PROVED` entry.
- Evidence: [tagged status](https://github.com/deedseal/deedseal/blob/v0.2.0/docs/status.md),
  coordinate `deedseal/deedseal@refs/tags/v0.2.0:docs/status.md`.
- Limit: an `active` label is a repository status declaration, not evidence of
  an unpublished feature, schedule, or outcome.

### PBJ-0007 — Brand Identity v1.0 remains a review candidate

<!-- journal-entry: PBJ-0007 | IN_REVIEW | PUBLIC_OBSERVED -->

- User value: inspect the checked design study without mistaking it for the
  selected or current public identity.
- Evidence: [tagged candidate boundary](https://github.com/deedseal/deedseal/blob/v0.2.0/README.md#brand),
  coordinate `deedseal/deedseal@refs/tags/v0.2.0:README.md`.
- Limit: the record does not present the study as Owner-selected, adopted,
  deployed, or current, and its checks do not authorize placement.

### PBJ-0008 — The public landing relaunch was reversed

<!-- journal-entry: PBJ-0008 | FAILED | PUBLIC_OBSERVED -->

- User value: see an attempted presentation change and its reversal instead of
  an uninterrupted-success narrative.
- Evidence: [history through protected `v0.2.0`](https://github.com/deedseal/deedseal/commits/v0.2.0),
  coordinate `deedseal/deedseal@refs/tags/v0.2.0`.
- Limit: the merge-and-revert history establishes the reversal, not a cause
  beyond the public record or the bytes currently served by an external domain.

### PBJ-0009 — Resource and network-egress bounds remain planned

<!-- journal-entry: PBJ-0009 | PLANNED | PUBLIC_PROPOSAL -->

- User value: understand that the filesystem observation is narrower than
  whole-workload containment.
- Evidence: [tagged status](https://github.com/deedseal/deedseal/blob/v0.2.0/docs/status.md),
  coordinate `deedseal/deedseal@refs/tags/v0.2.0:docs/status.md`.
- Limit: open objectives are not implemented controls, dates, or acceptance
  evidence.

### PBJ-0010 — Proof Check is a proposal, not a shipped tool

<!-- journal-entry: PBJ-0010 | PLANNED | PUBLIC_PROPOSAL -->

- User value: see the proposed bounded pull-request evidence verdict without an
  implied install path.
- Evidence: [public implementation packet](https://github.com/deedseal/deedseal/issues/78),
  coordinate `github-issue:deedseal/deedseal#78`.
- Limit: no public Action, CLI, receipt, release, Marketplace listing, or
  reproducible Proof Check example is established. The Issue body is mutable and
  can never support `PROVED` on its own.

### PBJ-0011 — Canonical portal availability is not established by GitHub evidence

<!-- journal-entry: PBJ-0011 | UNKNOWN | UNKNOWN -->

- User value: avoid treating one successful repository Pages job as proof that
  the canonical domain serves particular bytes now.
- Evidence: [public Pages run](https://github.com/deedseal/deedseal/actions/runs/33295394238),
  coordinate `github-actions-run:deedseal/deedseal#33295394238`.
- Limit: the run records a Pages build and deploy job, but does not bind the
  canonical domain response bytes or current source. External reachability is
  not immutable GitHub proof.

### PBJ-0012 — Cockpit and local-inference capability remain unknown

<!-- journal-entry: PBJ-0012 | UNKNOWN | UNKNOWN -->

- User value: receive an explicit unknown rather than an inference from private
  development or product vocabulary.
- Evidence cutoff: [protected public tree `v0.2.0`](https://github.com/deedseal/deedseal/tree/v0.2.0),
  coordinate `deedseal/deedseal@refs/tags/v0.2.0`.
- Limit: no qualifying coordinate was found in that tree. Absence there does not
  prove that work does not exist elsewhere.

### PBJ-0013 — Marketplace, partner, connector-effect, and production state remain unknown

<!-- journal-entry: PBJ-0013 | UNKNOWN | UNKNOWN -->

- User value: avoid inferring distribution, endorsement, external side effects,
  or operational adoption from repository activity.
- Evidence cutoff: [tagged prerelease non-claims](https://github.com/deedseal/deedseal/blob/v0.2.0/docs/releases/v0.2.0-prerelease-notes.md),
  coordinate `deedseal/deedseal@refs/tags/v0.2.0:docs/releases/v0.2.0-prerelease-notes.md`.
- Limit: the record does not establish an accepted integration, partner status,
  provider endorsement, production deployment, Marketplace listing, or live
  connector effect.

### PBJ-0014 — The tagged claim-count policy disagrees with the ledger

<!-- journal-entry: PBJ-0014 | FAILED | PUBLIC_OBSERVED -->

- User value: see the public count disagreement instead of receiving whichever
  hand-written number sounds stronger.
- Evidence cutoff: [protected public tree `v0.2.0`](https://github.com/deedseal/deedseal/tree/v0.2.0),
  coordinate `deedseal/deedseal@refs/tags/v0.2.0`.
- Limit: at that tag, `docs/publication-policy.md` names two current
  public-reproducible claims while the machine ledger and evidence README carry
  five. This observation does not decide the underlying claims or repair the
  existing documents.

## Verification

Run the standard-library checker from the repository root:

```text
python3 tools/check_public_build_journal.py --self-test
python3 tools/check_public_build_journal.py --check-urls
```

The first command validates the schema, identifiers, coordinates, status/grade
rules, supersession graph, and both human views, then requires all six hostile
fixtures to be refused. The second performs anonymous reachability checks; it
sends no GitHub credential.
