# How Deedseal is built

Deedseal is built by AI workers operating under the same trust model the product enforces. We publish the method because the process is part of the claim: the evidence you can verify (the run passport) is produced by the discipline described here.

## Committed-state engineering

Only committed, verifiable artifacts count as durable engineering state: committed files, hash-verified evidence, explicit not-verified declarations with reasons, contracts, and deterministic checks. Chat transcripts, model memory, terminal scrollback, and uncommitted work do not count — by written rule, not by habit. A machine-checked current-state index pins what is done, what is active, what is blocked, and what is explicitly not verified, so any fresh working session — human or machine — resumes from committed state alone. A reasoned "not verified" beats an unsupported claim, by written rule.

## Bounded task packets

Every piece of work is a committed packet: a pinned base commit, a frozen allowed-file scope, explicit exclusions, and an acceptance record. Anything discovered outside the frozen scope becomes a later packet instead of quietly widening the current one. Problems found along the way — including the project's own gaps — are recorded as committed findings with explicit open or mitigated states, not fixed silently or hidden.

## Acceptance probes

Acceptance is a single canonical entrypoint that runs an exact, ordered list of deterministic, standard-library-only checks — and continuous integration is bound to the identical list by an exact-match argument contract, so what runs locally and what runs in CI cannot drift apart.

Roughly half of the checks are hostile negative probes. They mutate temporary copies of the repository to weaken a setting and assert that the check rejects it; they feed adversarial inputs — malformed records, path traversal, digest mismatches, credential-shaped environment names — and assert the precise, stable refusal code, not merely any failure. Gates are proven to reject, not assumed to. Known-open gaps are committed as passing tests that must break when the gap closes, so closing a gap is a visible event.

For foundational formats, test vectors are committed before the code that must satisfy them, so an implementation bug cannot quietly become the reference behavior.

## Asymmetric authority

AI workers author branches and open draft pull requests — only drafts, enforced in code. A single human owner alone marks work ready, approves, and merges. Passing checks are evidence, not approval. Pull-request eligibility is delegated to GitHub-native enforcement — one ruleset, one required check, no bypass actors — and that enforcement was probed empirically: a deliberately broken commit producing a recorded failure, then a valid commit producing a recorded success, with the failure left visible in history.

## Negative results are first-class

A refusal is a result. Designed refusals — validly signed grants that the system correctly declined before any effect — are closed with signed, offline-verifiable negative records, and they count as successful proofs of refusal. The record of what the system would not do is part of the evidence, not an embarrassment to be cleaned up.

Status itself follows the same rule: an engineering objective counts as closed only when a bound implementation fact and a passing hostile probe both verify. A status cannot be claimed in prose.

## Scope of this document

This document describes the method. Internal tooling, repository names, task identifiers, and operational metrics are not published.
