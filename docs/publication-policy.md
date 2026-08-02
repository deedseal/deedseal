# Publication policy

## Principle

Public material is a reviewed projection of private engineering state. A claim
must be narrower than its evidence, tied to a dated snapshot, and explicit about
what a public reader cannot reproduce.

## Claim statuses

| Status | Meaning |
|---|---|
| `public-reproducible` | Public source and artifacts are sufficient to repeat the stated check. |
| `public-attested` | A public signed or hashed attestation supports the statement, but the underlying source is not fully public. |
| `internally-verified` | Private source and verification passed at a fixed internal snapshot; this repository publishes a sanitized summary. |
| `experimental` | Observed in research work but not accepted as a stable property. |
| `design-target` | Intended behavior that is not claimed as implemented. |
| `withdrawn` | Previously published statement that is no longer current. |

No current product claim is classified as `public-reproducible`.

## Required claim fields

Every machine-readable claim includes:

- a stable claim identifier;
- one bounded statement;
- a component and public snapshot;
- a status and observation date;
- linked evidence identifiers;
- explicit limitations.

## Disclosure classes

| Code | Withheld class |
|---|---|
| `R-SEC` | Security-sensitive mechanism, attack detail, trust material, or unresolved control. |
| `R-OPS` | Host, service, credential, transport, identity, or operational topology. |
| `R-PRIV` | Personal, account, or private organization information. |
| `R-IP` | Private source, internal contract, recipe, prompt, or implementation detail. |
| `R-VULN` | Vulnerability detail that is not ready for coordinated public disclosure. |

Redaction metadata names only the class and reason. It must not reveal the
withheld value.

## Prohibited public claims

Unless supported by a later, separately reviewed public record, publication must
not describe the product as:

- secure, tamper-proof, unhackable, formally verified, certified, or compliant;
- production-ready, client-ready, generally available, or commercially ready;
- model-neutral or provider-neutral;
- faster, cheaper, safer, or superior by benchmark;
- patented or patent-pending;
- a proof of semantic correctness.

Words such as “first,” “only,” and “unique” are not substitutes for evidence.
Distinctiveness should be shown by the concrete combination of bounded
properties, not by an exclusivity claim.

## Material that is not published

- private repository URLs, branches, pull requests, internal commit identifiers,
  account names, and source paths;
- raw grants, passports, custody records, proof manifests, refusal receipts, and
  task prompts;
- keys, trust-anchor constants, rotations, nonces, credential paths, tokens, and
  signer details;
- hostnames, network addresses, VM identifiers, service accounts, sockets,
  filesystem layouts, and deployment recipes;
- exact attack cases, refusal codes, limits, traversal rules, allowlists, and
  unresolved security objectives;
- benchmark or economic data that has not passed a separate publication review.

## Publication sequence

1. Re-anchor both private components.
2. Confirm the claim in implementation, merged change record, and successful
   acceptance evidence.
3. Produce a sanitized record with an opaque source-snapshot identifier.
4. Review for security, operations, privacy, intellectual-property, and
   vulnerability disclosure.
5. Update the ledger and public artifact hashes.
6. Pass public-record validation in a pull request.
7. Publish only after owner review and merge.

