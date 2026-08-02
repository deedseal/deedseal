# Product direction

> **Status:** product target, not a shipped-capability claim. The implemented and
> publicly evidenced state remains defined by [Status](status.md) and the
> [public evidence record](../evidence/README.md).

## Product north star

**Deedseal Business Runtime** is an owner-controlled hybrid execution
environment for bounded AI-assisted work.

The target product runs authority, policy, business context, approvals, and
evidence on customer-controlled Linux infrastructure. Authoritative business
data remains in customer-controlled storage. External models and reference
services receive only the payload permitted for a specific operation and never
receive standing authority over the business.

The operating principle is:

> External intelligence may perform bounded work. Authority, data custody,
> acceptance, and spending policy remain with the owner.

Deedseal is not a model, a NAS appliance, a chatbot, or a replacement for CRM,
ERP, accounting, or document systems. The product is the runtime that connects
local business state to external computation through explicit delegation,
controlled effects, and verifiable outcomes.

## Public product surface

The product implementation and engineering control plane remain private. This
repository is the public presentation and verification surface: it may publish
the product direction, public specifications, the offline verifier, and
disclosure-reviewed evidence. Publishing Stage 1 does not publish the producer
or the private engineering repositories.

## The hybrid product boundary

| Plane | Product responsibility |
| --- | --- |
| **Deedseal Runtime** | Coordinates jobs, context, skills, policies, approvals, execution, and lifecycle state. This is the commercial product. |
| **Linux substrate** | Provides the local execution and authority boundary. The target is office-class hardware such as a laptop for evaluation or a mini-PC for continuous operation; local model inference is not required by the architecture. |
| **Local data plane** | Stores authoritative business data, private context, policies, credentials, execution records, evidence, and recovery state. Storage may be directly attached or provided by customer-controlled NAS or TrueNAS infrastructure. |
| **External model and reference plane** | Supplies replaceable inference, search, public reference, and specialist services. These services are dependencies, not sources of authority or acceptance. |
| **Authority and evidence plane** | Defines what may run, constrains execution, observes results, records approvals and refusals, and produces independently verifiable passports. |
| **Owner economics plane** | Applies provider, model, operation, and period budgets; records attributable usage and cost; and relates cost to accepted, refused, or failed operations. |

Customer-controlled storage does not mean that data can never leave the local
environment. Any outbound disclosure to a model, reference service, or business
system is itself a controlled effect: explicit, bounded, attributable, and
governed by policy. Encryption, backup, access control, retention, and recovery
remain part of the deployment contract.

## One runtime, versioned business profiles

A business is represented as a versioned profile containing roles, authority
boundaries, skills, operating procedures, context schemas, model and spending
policies, connectors, approvals, and evidence-retention rules.

Profiles configure one shared runtime; they do not fork the security-sensitive
core. A construction profile may serve as the customer-zero deployment without
becoming a separate product architecture.

## Release path

### Stage 1 — Deedseal Evidence Release 1.0

The first public technical presentation of the product principle: one
authorized execution, one observed result, and one independently verifiable
record.

The release publishes a real public-safe passport, the offline verifier, a
deliberately byte-tampered twin that must be rejected, the documented threat
boundaries and limitations, and continuous integration that reproduces PASS for
the authentic record and BLOCK for the altered record. The
[demonstration target](../demo/README.md) and [run-passport
contract](passport.md) define that proof surface.

This stage proves the authority-and-evidence foundation. It is not a Business
Runtime 1.0, production-readiness claim, supported-hardware claim, or economic
claim.

**Exit criterion:** a clean public checkout independently reproduces the stated
verification results, and every public claim maps to published evidence.

### Stage 2 — Deployable Engineering Runtime

Package the execution foundation as one supported installation: one Linux
distribution and architecture, one agent and model route, deterministic setup,
update and rollback, backup and restore, recovery, local-storage integration,
and repeatable bounded file and Git work.

**Exit criterion:** an independent operator can install, run, verify, upgrade,
and recover the system without private engineering intervention.

### Stage 3 — Hybrid Business Runtime pilot

Add policy-bound model and reference connectors, explicit outbound-data
controls, provider and model selection, per-operation and periodic budgets,
usage and billing reconciliation, NAS deployment support, and typed connectors
to existing business systems.

External effects require action-specific authority, least-privilege
credentials, human approval for consequential actions, idempotency and replay
protection, external-system receipts, revocation, recovery, and business-action
passports.

**Exit criterion:** one narrow customer-zero workflow runs repeatedly under a
declared protocol, produces no effect outside granted authority, and yields
measured cost, owner-time, failure, and acceptance data.

### Stage 4 — Deedseal Business Runtime 1.0

Release the first supportable business product only after independent install
and disaster recovery are demonstrated, the supported hardware and software
matrix is evidence-backed, one business profile operates without a core fork,
at least one external design partner reproduces the deployment, and operational
and commercial claims are limited to measured results.

## Owner-controlled economics

The economic purpose is to make externally supplied AI capacity governable and
measurable. The owner chooses which provider and model class may be used,
reserves higher-cost capability for work that justifies it, sets spending
ceilings, and attributes cost to a specific accepted, refused, or failed
operation.

This establishes a design for cost control and measurement. It does not yet
prove labor replacement, lower total cost, higher productivity, or positive
return on investment. Those claims require declared experiments and operating
evidence.

## Product invariants

- Local authority remains authoritative; an external model never approves its
  own result.
- Models and reference providers remain replaceable dependencies.
- Business data is local-first; outbound context is explicitly authorized.
- Business profiles configure one core rather than forking it.
- Consequential external actions require owner approval and system receipts.
- Every material operation closes into a verifiable terminal record, including
  refusals and failures.
- Hardware, performance, security, and economic claims follow evidence rather
  than product intent.

The intended result is not an open-ended "AI employee." It is a controlled AI
operator whose authority, data access, external effects, and cost are defined by
the owner and visible after execution.
