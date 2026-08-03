# Trust model

## Roles and vocabulary

- **Owner** — the single human authority. Issues and signs work grants offline; alone approves, merges, and signs closures.
- **Agent** (worker) — an AI coding agent doing the actual implementation work. Untrusted by definition.
- **Grant** — an owner-signed authorization for one bounded piece of work: pinned repository state, validity window, exact allowed file set, exact task prompt.
- **Gate** — the deny-by-default authorization decision point.
- **Broker** — the single code path that turns an authorized decision into a physical effect.
- **Authority service** — the trusted OS principal that runs the gate and broker, observes results, and signs custody records.
- **Run passport** — the signed, offline-verifiable evidence record a supervised run closes into.

## Assumptions

All agent output — code, files, reports, claims of success — is treated as untrusted until it has passed the gate and been observed. The agent runner is assumed capable of lying about its own result; its exit status is never taken as evidence. Verification of evidence is designed to require no trust in the machine that produced it.

## Threats considered

- An agent attempts an action outside the granted file set, or under an ambiguous scope.
- An agent or runner substitutes file contents after observation.
- A run's records are tampered with after the fact.
- Automation attempts to approve, merge, or sign its own work.
- A grant is replayed outside its validity window or run identity.
- A validly signed failure record is presented as a success.

## Goals

Stated as invariants of the design:

- No effect without a grant.
- Every supervised run leaves signed evidence, produced before and after the effect.
- A passport verifies offline, against pinned keys, or it does not count.
- A validly signed failure can never verify as a success.
- The complete changeset is bound: a selected subset of changes can never verify.
- Automation never approves, merges, or signs.

## Residual trust

Trusted computing bases are unavoidable; Deedseal's goal is to keep the list short and explicit. Using Deedseal, you still trust:

- the Linux kernel of the host;
- the owner's custody of the signing key;
- the host that runs the authority service.

Today's containment of the agent is based on OS privilege separation, quarantine, and a grant-derived kernel write boundary recorded in the passport and checked by the published verifier. Resource and egress bounds are open objectives tracked in [status.md](status.md).

## Out of scope

- Sandboxing or fully containing the workload itself — compose Deedseal with a sandbox or virtual machine for that.
- Hardware side channels.
- Availability guarantees.

## Skeptic's questions

**Is this just seccomp or AppArmor with extra steps?** No. Kernel mechanisms confine what a process may do while it runs; Deedseal governs what a run is allowed to change, and leaves portable signed evidence of what it did change. They answer different questions, and they compose — the published run records grant-derived kernel write confinement; resource and egress bounds remain open objectives.

**Is a run passport just a log entry?** A log is trusted because of where it sits and who ran the collector. A passport carries its own verifiability: it can leave the host, travel anywhere, and still be checked against pinned keys by a third party.

**Why can't the AI approve its own work?** Approval is not a field in a request. Requests that carry self-approval or negotiation fields are rejected outright at the gate, and no automation holds a signing route. Approval is an act only the owner can perform.
