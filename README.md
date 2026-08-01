# Deedseal

**Controlled execution and verifiable records for AI coding-agent work.**

[![Public record validation](https://github.com/deedseal/deedseal/actions/workflows/validate-public-record.yml/badge.svg)](https://github.com/deedseal/deedseal/actions/workflows/validate-public-record.yml)

Deedseal is the public engineering record for the product developed across the
private **KBP Core** and **DEV OFFICE** repositories. This repository publishes
reviewed architecture summaries, bounded engineering claims, and sanitized
verification records. It is not a source mirror or a product distribution.

> **Status:** active research engineering. No general-availability, security
> certification, compliance, or commercial-readiness claim is made here.

## Why this exists

An agent-produced diff says little about the authority under which the agent
worked. It does not, by itself, establish which repository state was admitted,
which paths were authorized, what changed, how the result was accepted, or who
retained approval authority.

The engineering focus is the complete chain:

**owner authorization → controlled execution → admitted commit → verifiable run
record → owner review**

## System boundary

- **KBP Core** is the private controlled-execution and proof layer. It admits a
  signed run scope, checks effects through a deterministic control path, binds
  the resulting commit, and produces a RunPassport that can be checked offline.
- **DEV OFFICE** is the private engineering control plane. It binds task packets
  to commits and execution profiles, runs workers in isolated work areas,
  validates their history and scope, and publishes Draft pull requests for
  owner review.
- **Deedseal** is a reviewed public projection of that work. It contains only
  claims and evidence summaries that have passed the publication boundary.

The conceptual flow and trust boundary are documented in
[System boundary](docs/system-boundary.md).

## Engineering properties

The table uses deliberately narrow language. `internally-verified` means that
the property was checked against a fixed private-source snapshot and successful
internal acceptance run. It does **not** mean that a public reader can reproduce
the result from this repository alone.

| Claim | Property | Evidence | Status |
|---|---|---|---|
| `CLM-0001` | A run can be admitted by a signed, scope-bound owner grant before controlled effects are accepted. | `EVD-CORE-0001` | `internally-verified` |
| `CLM-0002` | A current RunPassport binds authorization, custody outcome, execution identity, complete committed changes, artifact hashes, acceptance data, and final owner closure. | `EVD-CORE-0001` | `internally-verified` |
| `CLM-0003` | The standalone RunPassport verifier needs one passport file and no network, repository checkout, running KBP service, private key, or third-party Python package. | `EVD-CORE-0001` | `internally-verified` |
| `CLM-0004` | Repository-native dispatch binds immutable task bytes, bounded write scope, an execution-profile digest, and draft-only automation authority to an owner-selected commit. | `EVD-OFFICE-0001` | `internally-verified` |
| `CLM-0005` | Postflight checks worker history and scope before publication; readiness, approval, and merge remain owner actions. | `EVD-OFFICE-0001` | `internally-verified` |
| `CLM-0006` | Typed interruptions and recorded failures receive terminal dispositions; retry admits a closed failure set and reclaims prior worker state. | `EVD-OFFICE-0001` | `internally-verified` |
| `CLM-0007` | An internal 10-entry controlled-execution series records eight positive lifecycles and two designed-negative lifecycles refused before effects. | `EVD-CORE-0002` | `internally-verified` |

Detailed scope and non-claims are in
[Engineering properties](docs/engineering-properties.md).

The DEV OFFICE properties above describe an implemented, hermetically validated
control path. At this snapshot its production actuator was **not adopted**, and
no real model-provider execution through that actuator is claimed.

## Evidence model

The current review candidate is `DS-2026.08.1`. It is not a published snapshot
until owner review and merge complete the publication boundary.

- [`evidence/ledger-v1.json`](evidence/ledger-v1.json) is the machine-readable
  claim-to-evidence map.
- [`evidence/records/`](evidence/records/) contains sanitized public records.
- [`schemas/`](schemas/) defines their public data contracts.
- `validate-public-record.yml` checks structure, references, hashes, and
  disclosure rules on every pull request and `main` update.

That workflow verifies the **integrity of this publication**, not the private
product implementation. The current evidence class is internal attestation with
explicit public limitations; it is not independent certification.

## Deliberate non-claims

This repository does not claim:

- semantic correctness of agent-produced code;
- containment of activity outside the documented execution path;
- model or provider neutrality;
- product security, formal verification, certification, or compliance;
- production, client, general-availability, or commercial readiness;
- benchmark, cost, or speed superiority.

## Repository guide

- [System boundary](docs/system-boundary.md)
- [Engineering properties](docs/engineering-properties.md)
- [Publication policy](docs/publication-policy.md)
- [Evidence records](evidence/README.md)
- [Security reporting](SECURITY.md)
- [Contribution policy](CONTRIBUTING.md)
- [Rights and source availability](NOTICE.md)
