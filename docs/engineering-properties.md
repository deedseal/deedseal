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

**Meaning.** This claim does not ask to be believed. The passport, a twin of it
differing at exactly one byte, and the verifier that renders the verdict are all
published here. A reader runs the
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

## `CLM-0010` — refusal coverage measured from published bytes

**Statement.** The published verifier declares 39 refusal reasons; the
published mutation corpus demonstrates 35 exact refusal verdicts and classifies
4 as not reachable by mutation of the published bytes.

**Meaning.** The survey parses every `block_*` string from the verifier source
instead of relying on a hand-maintained count. It runs every named corpus case,
accepts a reason as demonstrated only when the exact final verdict and exit code
match, and requires the demonstrated and not-reachable sets to account for all
declared reasons. The same measured values generate the landing-page counts and
are checked against this claim and its evidence record.

**Boundary.** The 39 reasons are declarations in this published verifier, not a
claim about every rejection path in private components. The 35 demonstrated
reasons are reachable from the published passport and hostile file inputs under
the verifier's fixed first-failure order. Of the other four, three require a
differently signed owner grant or custody record before the verifier can reach a
later check; one is declared as a custody failure reason but is not returned as
a passport-verifier verdict. The corpus demonstrates refusal behavior, not
semantic correctness or completeness.

## `CLM-0011` — recorded filesystem boundary re-observed

**Statement.** The boundary recorded in the published passport, applied on an
unrelated Ubuntu runner's kernel, permits the recorded file write and refuses
file creation, directory creation, symbolic-link creation, and unlink;
continuous integration re-observes these operations on Ubuntu on every change.

**Meaning.** The public probe reads the signed boundary description, applies
equivalent write-class rules to a temporary directory, and reports each
operation's observed errno. The merged-run log recorded passport ABI 8, runner
ABI 7, success for the permitted append, and `EACCES` for all four out-of-scope
operations.

**Boundary.** This demonstrates the recorded ruleset on the reader's kernel; it
does not re-execute or prove the boundary of the original run. A kernel without
Landlock cannot demonstrate it. The probe covers filesystem write classes, not
resource or network bounds.

## `CLM-0012` — a second published run

**Statement.** A second supervised run is published with its passport, its
one-byte tampered twin, and the exact before and after bytes of the file it
changed; the passport verifies PASS and the twin verifies BLOCK using only this
repository's files and a Python interpreter.

**Meaning.** The record is now a sequence rather than a single event. Each
published passport binds the commit it produced and the head its grant signed,
so a reader can walk the runs in order from `examples/verified/runs.md` and
check each one independently. The tampered twin for this run differs from its
passport at exactly one byte, derived by the published rule rather than chosen.

**Boundary.** Two published runs are two data points, not a rate, a benchmark,
or a statement about availability. Reproducing either verdict does not reproduce
the run; producing new passports requires the private system and its signing
keys.

## `CLM-0013` — two implementations agree

**Statement.** Two implementations of the published run-passport envelope
produce identical verdicts and exit codes on all 48 published conformance
vectors, and continuous integration re-observes this on every change.

**Meaning.** The published specification was complete enough to build a working
verifier from. The second implementation uses a different language, a different
JSON decoder, and a different signature library — and Go's decoder differs from
Python's in exactly the places where implementations quietly diverge: duplicate
keys, key order, and re-serialization escaping. Neither implementation was
adjusted to make the other agree. The one gap the exercise found — trust-anchor
public keys omitted from the specification — is recorded in that document rather
than quietly patched.

**Boundary.** Both implementations come from this project. This is agreement
between two implementations, not two parties checking each other, and no
statement here should be read as independent verification. Agreement covers the
48 published vectors; it establishes nothing about inputs outside them and does
not establish correctness in general. Four declared refusal reasons cannot be
reached by mutating the published bytes and are absent from the vectors.
