# Engineering properties

This document expands the claims registered in
[`evidence/ledger-v1.json`](../evidence/ledger-v1.json). Each claim is bounded by
its public snapshot and evidence limitations.

## `CLM-0001` — authority before admitted effects

**Statement.** A run can be admitted by a signed, scope-bound owner grant before
controlled effects are accepted.

**Meaning.** The authorization object is data, not a natural-language promise.
It binds a run to an explicit repository state and a bounded change scope before
the controlled execution path proceeds.

**Boundary.** This does not assert control over processes or effects outside the
documented controlled-execution path.

## `CLM-0002` — complete current run-passport binding

**Statement.** A current run passport binds authorization, custody outcome,
execution identity, complete committed changes, artifact hashes, acceptance
data, and final owner closure.

**Meaning.** The current passport contract checks the clean execution state,
produced commit, complete changed-path set, committed file hashes, acceptance
contract, authenticated positive custody outcome, and final owner signature as
one envelope. A broken link yields a refusal rather than a partial success.

**Boundary.** The passport is evidence about authority, process, provenance,
scope, custody, and tamper detection. It is not a proof that the produced code is
semantically correct.

## `CLM-0003` — portable offline verdict

**Statement.** The standalone run-passport verifier needs one passport file and
no network, repository checkout, running service, private key, or
third-party Python package.

**Meaning.** A reviewer can copy the verifier and a passport into an isolated
directory and evaluate the whole supported envelope using the Python standard
library and pinned public trust anchors.

**Boundary.** This claim was first observed against a private-source snapshot.
The verifier has since been published under Apache-2.0; public reproducibility
of the published verifier and passport demonstration is tracked separately by
`CLM-0008`.

## `CLM-0004` — commit-pinned dispatch

**Statement.** Repository-native dispatch binds immutable task bytes, bounded
write scope, an execution-profile digest, and draft-only automation authority to
an owner-selected commit.

**Meaning.** A branch name or moving `latest` reference is not sufficient
authorization. The selected commit, packet digest, target state, accepted paths,
execution profile, and authority flags are validated before worker execution.

**Boundary.** Internal schema fields, limits, credentials, transports, and
deployment recipes are intentionally not published.

## `CLM-0005` — publication stops at owner review

**Statement.** Postflight checks worker history and scope before publication;
readiness, approval, and merge remain owner actions.

**Meaning.** Validation examines the worker's commit history and admitted scope,
then automation may publish a Draft pull request and observe checks. Passing
checks are evidence, not approval.

**Boundary.** This is an authority separation property, not a statement that
every GitHub or host setting is permanently immutable.

## `CLM-0006` — terminal lifecycle and bounded retry

**Statement.** Typed interruptions and recorded failures receive terminal
dispositions; retry admits a closed failure set and reclaims prior worker state.

**Meaning.** Once run-record reservation begins, interruption and failure paths
are normalized into terminal states. Retry is limited to recognized terminal
failures, prior worker state is reclaimed, and zero or unknown states remain
blocked.

**Boundary.** This claim applies to the audited private-source snapshot and its
tested launcher lifecycle. It is not a general availability guarantee.

## `CLM-0007` — positive and designed-negative evidence

**Statement.** An internal 10-entry controlled-execution series records eight
positive lifecycles and two designed-negative lifecycles refused before effects.

**Meaning.** Designed refusals are retained as results in their own right rather
than relabeled as successes. The aggregate shows both admitted and refused
paths in the same engineering record.

**Boundary.** Raw passports, grants, custody records, paths, identities, and run
artifacts are not published. The public record is an internally verified
aggregate, not an independently reproducible dataset.

## `CLM-0008` — a verdict anyone can reproduce

**Statement.** A published run passport verifies PASS with the published offline
verifier, and a one-byte tampered copy verifies BLOCK, using only this
repository's files and a Python interpreter.

**Meaning.** This is the one claim on this page that does not ask to be
believed. The passport, a twin of it differing at exactly one byte, and the
verifier that renders the verdict are all published here. A reader runs the
verifier twice and sees PASS and then BLOCK, hashes the published post-run bytes
and finds the digest the passport signs, and reads the applied kernel boundary
in the same signed bytes as the grant it was derived from. Continuous
integration repeats the whole check on three operating systems on every change,
so the demonstration is re-proven rather than asserted.

**Boundary.** The verdict is reproducible; the run is not. Producing a new
passport requires the private system and its signing keys, and signing-key
secrecy remains a trusted prerequisite. A PASS attests authorization, bounded
scope, applied boundary, and committed-byte provenance for one run — never the
semantic quality of the change, and never anything about runs it does not bind.

## `CLM-0009` — a second exact-byte controlled result

**Statement.** A second controlled run produced the precommitted target bytes,
proved staged-to-materialized equality, and published those exact result bytes
in this repository.

**Meaning.** Before execution, the public target had one accepted seed state and
one accepted result state. The controlled run moved the target to the result,
the staged and materialized digests matched, and the named test was absent from
the seed and present exactly once in both result views. The merged public target
carried the same precommitted result digest at the time of the record. Continuous
integration re-runs the target's byte contract on Ubuntu, Windows, and macOS,
admitting exactly the seed state or the result state; it does not pin which of
the two is checked in, so a reader who wants the result digest should hash the
file.

**Boundary.** The run evidence remains private and is published only as a
sanitized internal attestation. This record is not a signed commit-bound
passport and does not make the second run publicly reproducible. It proves
exact-byte result presence, not semantic quality.
