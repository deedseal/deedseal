# Proof Check

**Journal status: `PLANNED`. Evidence grade: `PUBLIC_PROPOSAL`.**

Proof Check is a proposed free check for one bounded pull-request question. It
is not a shipped Action, CLI, hosted service, receipt format, release, or
Marketplace listing. The public status is
[`PBJ-0010`](build-journal/README.md#pbj-0010--proof-check-is-a-proposal-not-a-shipped-tool).

## Proposed V0 question

Does the complete changed-file set for one public pull request stay inside an
explicit exact-path manifest bound to the same repository, base, and head?

The manifest would be an input, not text inferred from a pull-request body. Its
bytes, digest, provenance, trust level, repository, base, and head would travel
with the result. V0 would use exact repository-relative UTF-8 paths only: no
globs, prefixes, negation, generated-file inference, or prose extraction.

## Proposed verdicts

- `PASS` — the changed-file list is complete, coordinates and manifest match,
  and every observed current path is allowed. A rename must also account for its
  previous path.
- `FAIL` — the inputs are complete and at least one observed path is outside the
  exact allowed set. The result names the sorted outside paths.
- `INDETERMINATE` — a required fact is missing or ambiguous: pagination is
  incomplete, an API cap is reached, base or head drifts, a fork head is
  unavailable, a path is invalid, or the manifest is not bound to the evaluated
  coordinates.

`PASS` would mean path-set coherence under the supplied manifest. It would not
mean code quality, merge approval, semantic correctness, security certification,
or production readiness.

## Explicit V0 non-goals

The proposal does not add stale-review enforcement, generic review/check SHA
equality, merge-queue reconstruction, branch-protection or bypass inference,
CODEOWNERS resolution, deployment gates, attestations, identity correlation,
private-repository support, or a dashboard. GitHub already owns its native
checks, reviews, rules, and merge state; Proof Check would consume selected
public facts without replacing them.

## Evidence required before promotion

The journal must not move Proof Check out of `PLANNED` until public GitHub carries
the state needed for that move. At minimum, implementation claims require public
bytes at an immutable coordinate, deterministic PASS/FAIL/INDETERMINATE fixtures,
hostile missing-data and drift cases, exact result semantics, a permission and
data boundary, and an independently repeatable verification path.

Availability, Marketplace eligibility, external effects, and production use are
separate claims. None follows from an implementation commit, passing check, or
Draft pull request.

The public implementation packet is [Issue #78](https://github.com/deedseal/deedseal/issues/78).
An Issue is a proposal surface whose body may change; it is not immutable proof
of implementation.
