# Deedseal

[![Public record validation](https://github.com/deedseal/deedseal/actions/workflows/validate-public-record.yml/badge.svg)](https://github.com/deedseal/deedseal/actions/workflows/validate-public-record.yml)

**Deedseal is an owner-controlled system for sending work to AI, reviewing the result, and deciding what may become durable business memory.**

Category: Deedseal is an owner-governed AI business platform for deploying and operating a business.

Deploy an AI office for your business while keeping authority, business memory and the final decision with the owner. Visit [deedseal.com](https://deedseal.com).

## For owners and operators

Deedseal is for people who want AI workers without giving a model provider the final decision or the owner-held business memory.

## Platform direction

The wider product is intended to use modules, bounded adapters and bounded AI workers to move accepted work into owner-held business memory. This is product direction, not a claim that the wider platform is implemented today. West Coast KBP ADU / Construction OS is the Owner-operated first reference use and product direction only. No trademark-clearance claim is made.

## Current availability

- **PUBLISHED PROOF:** two real run passports and their one-byte tampered twins, an offline verifier, 48 conformance vectors, Python/Go verdict agreement, and a limited replay of the recorded Linux write boundary.
- **IN DEVELOPMENT:** the authorization, signing, quarantine, custody, and verification chain; resource and egress bounds remain open.
- **PRODUCT DIRECTION:** the wider business platform, Cockpit, accepted memory, and external-system modules.
- **AVAILABILITY:** prerelease / design-partner stage; not generally available and not represented as production-qualified.

## What is published today

This repository is the public documentation and machine-validated evidence record. It proves only the properties bound by its checked-in artifacts; it does not prove the wider business-platform capability, a customer outcome, or private implementation. The engineering repositories remain private.

## Verify it yourself

Try the proof now in the way that suits you. All three paths use the same published passport and tampered twin.

1. **Browser.** Open the latest [Actions runs](https://github.com/deedseal/deedseal/actions/workflows/validate-public-record.yml), then inspect `Re-prove the published demonstration`. To test it under your account, fork the repository, change one character in `examples/verified/run-passport.json`, and watch that step fail.
2. **AI assistant.** Ask it:

   > Clone https://github.com/deedseal/deedseal and run `python3 tools/check_demonstration.py` from the repository root. Report the verdict lines verbatim. Then copy `examples/verified/run-passport.json`, change one byte of the copy, run `python3 tools/verify_run_passport.py` on it, and report what happens.

3. **Terminal.** From a checkout, with standard Python and no network:

```
python3 tools/verify_run_passport.py examples/verified/run-passport.json
python3 tools/verify_run_passport.py examples/verified/run-passport.tampered.json
```

The first command must end with:

```
RUN_PASSPORT_VERDICT: PASS
```

and exit `0`. The second must end with:

```
RUN_PASSPORT_VERDICT: BLOCK block_owner_authorization_signature_invalid
```

and exit `1`. The files differ by one byte. For the full byte-level walkthrough, see [Verify the demonstration](docs/verify.md).

## The controlled-work loop

**Product direction:** intent → bounded work → worker/model → independent review → Owner decision → accepted memory.

Intent is recorded before work begins. The task names its allowed boundary. A worker or model produces a candidate; a separate reviewer checks the exact candidate. Checks and reviews provide evidence, while the Owner alone accepts or refuses the result. Only accepted work is intended to enter durable memory.

## GitHub is the first work plane

GitHub is where this loop is first made visible: [Issues](https://github.com/deedseal/deedseal/issues) hold bounded intent, Draft pull requests hold candidate work, [Actions](https://github.com/deedseal/deedseal/actions) hold rerunnable checks, and exact commits keep review tied to the bytes inspected. GitHub remains authoritative for its Issues, pull requests, reviews, and checks. Deedseal is intended to add authority, evidence, and accepted-memory boundaries around that work; it does not replace GitHub or let automation approve itself.

## Proof Check — planned first free entry

**PLANNED / IN DEVELOPMENT — not available today.** Proof Check is intended to be a free standalone Action and CLI for one narrow question: does one pull request's complete changed-path set fit an explicit path scope bound to that exact head? It is intended to return `PASS`, `FAIL`, or `INDETERMINATE` with a portable receipt and visible provenance. It will not review code, approve a merge, or turn missing evidence into PASS. Its public planning status is included in [Issue #78](https://github.com/deedseal/deedseal/issues/78); no Action, CLI, receipt, release, or Marketplace listing is claimed.

## Architecture at a glance

| Part | Role | Current public status |
|---|---|---|
| **Deedseal** | Authority and orchestration boundary: grants, bounded execution, evidence, Owner decision, and accepted-memory direction. | Execution-control evidence is published; the wider platform is product direction. |
| **Models** | Replaceable workers that propose results inside a declared boundary; never the accepting authority. | A model-provider boundary is evidenced internally; cross-provider portability is not public proof. |
| **GitHub** | First work plane and source of truth for Issues, pull requests, reviews, checks, and commits. | In use for this public repository; wider Deedseal integration remains product direction. |
| **Cockpit** | Intended Owner interface for seeing work, evidence, and decisions. | In development / product direction; no production iPad or local-inference capability is claimed. |
| **External systems** | Documents, email, calendars, CRM, social, and other business tools reached through bounded adapters. | Product direction unless a public evidence record says otherwise. |

Technical detail: [architecture](docs/architecture.md), [trust model](docs/trust-model.md), and [method](docs/method.md).

## Strongest current public evidence

| Public evidence | What a visitor can check | Exact coordinate |
|---|---|---|
| Two supervised runs | Each real passport returns PASS; each one-byte twin returns BLOCK. | [Published run index in `v0.2.0`](https://github.com/deedseal/deedseal/blob/v0.2.0/examples/verified/runs.md) |
| Offline verifier | One standard-library Python file verifies against pinned public keys without a service or network. | [`verify_run_passport.py` in `v0.2.0`](https://github.com/deedseal/deedseal/blob/v0.2.0/tools/verify_run_passport.py) |
| Refusal corpus | Published mutations reproduce 35 exact refusal verdicts; four declared reasons are classified as unreachable from published bytes. | [Refusal corpus in `v0.2.0`](https://github.com/deedseal/deedseal/blob/v0.2.0/demo/refusals/README.md) |
| Two implementations | Python and Go agree on verdict and exit code across all 48 published vectors. Both implementations come from this project. | [Conformance corpus in `v0.2.0`](https://github.com/deedseal/deedseal/blob/v0.2.0/examples/verified/conformance/README.md) |
| Recorded write boundary | A local Linux probe can replay the recorded rules and observe the bounded filesystem operations. | [Boundary walkthrough in `v0.2.0`](https://github.com/deedseal/deedseal/blob/v0.2.0/docs/verify.md#demonstrate-the-recorded-write-boundary-on-your-kernel) |
| Continuous validation | GitHub Actions re-ran the public record and browser-verifier checks successfully on the prepared `main`. | [Public record run `33295394495`](https://github.com/deedseal/deedseal/actions/runs/33295394495) · [browser run `33295394478`](https://github.com/deedseal/deedseal/actions/runs/33295394478) |
| Prerelease bundle | Release assets inventory the bounded distributable surface and publish checksums; checksums are not signatures. | [`v0.2.0` prerelease](https://github.com/deedseal/deedseal/releases/tag/v0.2.0) |

## What this does not prove

- A passport PASS does not prove code quality, semantic or business correctness, security certification, availability, or anything about another run.
- The public record does not prove a live Proof Check product, autonomous scheduling, the wider platform, Cockpit deployment, connector effects, or accepted business memory.
- No GitHub Marketplace availability or partnership, live LinkedIn effect, Face ID acceptance, production iPad/local inference, customer deployment, revenue, certification, or production qualification is claimed.
- Private implementation is not public proof. `internally-verified` means checked against a fixed private-source snapshot, not independently certified or publicly reproducible.

## Choose your path

| Visitor | Start here | Then go deeper |
|---|---|---|
| **User** | [Try the proof](#verify-it-yourself) and read [current status](docs/status.md). | [FAQ](docs/faq.md) and [deedseal.com](https://deedseal.com) |
| **Engineer** | [Architecture](docs/architecture.md) and [passport specification](docs/passport-spec-v1.md). | [Conformance vectors](examples/verified/conformance/README.md) and [method](docs/method.md) |
| **Reviewer** | [Verification walkthrough](docs/verify.md) and [run index](examples/verified/runs.md). | [Trust model](docs/trust-model.md) and [evidence model](evidence/README.md) |
| **Potential partner** | Read the [availability boundary](docs/status.md) and verify one public artifact. | Use the design-partner path on [deedseal.com](https://deedseal.com) only if the current limits fit. |

## Security, contributions, and license

Report vulnerabilities through [private vulnerability reporting](https://github.com/deedseal/deedseal/security/advisories/new) and read [SECURITY.md](SECURITY.md). Questions and corrections are welcome under [CONTRIBUTING.md](CONTRIBUTING.md). Documentation is licensed under [CC BY 4.0](LICENSE); executable files declare their own SPDX license, and the private product source is not covered. See [NOTICE.md](NOTICE.md).

<details>
<summary><strong>Complete machine-validated claim index</strong></summary>

The table is derived from the public evidence ledger and checked for exact agreement on every change. `internally-verified` is not independent certification; `public-reproducible` identifies the bounded claims a reader can reproduce from public bytes.

| Claim | Statement | Evidence | Status |
|---|---|---|---|
| `CLM-0001` | A run can be admitted by a signed, scope-bound owner grant before controlled effects are accepted. | `EVD-CORE-0001` | `internally-verified` |
| `CLM-0002` | A current run passport binds authorization, custody outcome, execution identity, complete committed changes, artifact hashes, acceptance data, and final owner closure. | `EVD-CORE-0001` | `internally-verified` |
| `CLM-0003` | The standalone run-passport verifier needs one passport file and no network, repository checkout, running service, private key, or third-party Python package. | `EVD-CORE-0001` | `internally-verified` |
| `CLM-0004` | Repository-native dispatch binds immutable task bytes, bounded write scope, an execution-profile digest, and draft-only automation authority to an owner-selected commit. | `EVD-OFFICE-0001` | `internally-verified` |
| `CLM-0005` | Postflight checks worker history and scope before publication; readiness, approval, and merge remain owner actions. | `EVD-OFFICE-0001` | `internally-verified` |
| `CLM-0006` | Typed interruptions and recorded failures receive terminal dispositions; retry admits a closed failure set and reclaims prior worker state. | `EVD-OFFICE-0001` | `internally-verified` |
| `CLM-0007` | An internal 10-entry controlled-execution series records eight positive lifecycles and two designed-negative lifecycles refused before effects. | `EVD-CORE-0002` | `internally-verified` |
| `CLM-0008` | A published run passport verifies PASS with the published offline verifier, and a one-byte tampered copy verifies BLOCK, using only this repository's files and a Python interpreter. | `EVD-CORE-0003` | `public-reproducible` |
| `CLM-0009` | A second controlled run produced the precommitted target bytes, proved staged-to-materialized equality, and published those exact result bytes in this repository. | `EVD-CORE-0004` | `internally-verified` |
| `CLM-0010` | The published verifier declares 39 refusal reasons; the published mutation corpus demonstrates 35 exact refusal verdicts and classifies 4 as not reachable by mutation of the published bytes. | `EVD-PUBLIC-0001` | `public-reproducible` |
| `CLM-0011` | The boundary recorded in the published passport, applied on an unrelated Ubuntu runner's kernel, permits the recorded file write and refuses file creation, directory creation, symbolic-link creation, and unlink; continuous integration re-observes these operations on Ubuntu on every change. | `EVD-PUBLIC-0002` | `public-reproducible` |
| `CLM-0012` | A second supervised run is published with its passport, its one-byte tampered twin, and the exact before and after bytes of the file it changed; the passport verifies PASS and the twin verifies BLOCK using only this repository's files and a Python interpreter. | `EVD-CORE-0005` | `public-reproducible` |
| `CLM-0013` | Two implementations of the published run-passport envelope produce identical verdicts and exit codes on all 48 published conformance vectors, and continuous integration re-observes this on every change. | `EVD-PUBLIC-0003` | `public-reproducible` |
| `CLM-0014` | A live controlled request traversed the owner-grant and broker path and was refused at the configured input bound; no completion was accepted. | `EVD-OFFICE-0002` | `internally-verified` |
| `CLM-0015` | A live model-read receipt retained digests rather than the response body in the disposable cell; retaining words required a separate bounded retrieval step into quarantine. | `EVD-OFFICE-0003` | `internally-verified` |
| `CLM-0016` | A one-byte mismatch between grant-covered prompt bytes and transmitted prompt bytes was refused; one normalized byte source now feeds both legs. | `EVD-OFFICE-0004` | `internally-verified` |
| `CLM-0017` | A live call exposed that the retrieval client and its passing test double read the completion from the wrong response field; both were corrected to the actual broker contract. | `EVD-OFFICE-0005` | `internally-verified` |
| `CLM-0018` | Quarantine refused prose when the committed candidate contract required structured JSON; the request was corrected to state the enforced shape. | `EVD-OFFICE-0006` | `internally-verified` |
| `CLM-0019` | The retrieval boundary can extract one balanced JSON object without editing its contents and refuses truncated objects or unstructured prose; the focused source-snapshot suite passed 17/17. | `EVD-OFFICE-0007` | `internally-verified` |
| `CLM-0020` | A structured live answer that exceeded the admitted output bound was refused rather than guessed complete; the request envelope was narrowed to fit the bound. No later successful accepted candidate set is claimed. | `EVD-OFFICE-0008` | `internally-verified` |

Claim boundaries: [engineering properties and non-claims](docs/engineering-properties.md), [evidence model](evidence/README.md), and [publication policy](docs/publication-policy.md).

</details>
