# Run passport specification v1

## Status and conformance

This specification describes the one public envelope admitted by the published verifier. It is written for implementers. The envelope it describes is **frozen**; the commitment that word carries, and its exact limits, are stated under [Compatibility commitment](#compatibility-commitment) below. An implementation must refuse an unrecognized version rather than guess how to interpret it.

A conforming verifier admits exactly `deedseal-run-passport/1.0`. It accepts a passport only if every check below succeeds in the stated order. The [language-neutral conformance suite](../examples/verified/conformance/README.md) provides committed passing and refusal inputs with exact expected verdicts and exit codes.

## JSON envelope

The input is one UTF-8 JSON text whose root value is an object. An array, scalar, or `null` is "not an object". Duplicate object member names are refused at every depth. Non-JSON constants including `NaN`, `Infinity`, and `-Infinity` are refused. After the first JSON value, only JSON whitespace may remain; any other trailing content is refused.

The required top-level members are exactly `schema_version`, `roadmap_step`, `run_id`, `execution_id`, `implementation_head_sha`, `authorization`, `custody`, `scope`, `execution`, `committed_binding`, and `closure`.

The only optional top-level member is `supplementary_evidence`. It is not trusted for the verdict, but because the owner closure covers the whole passport core it is authenticated when present. Every other top-level member is refused. The `authorization`, `custody`, `scope`, `execution`, `committed_binding`, and `closure` values must be objects. The four top-level identity values `roadmap_step`, `run_id`, `execution_id`, and `implementation_head_sha` must be non-empty strings.

The closed section member sets and their value constraints are defined by the verification algorithm below. `scope` is exactly `allowed_files`, `new_files`, and `acceptance_contract`; `acceptance_contract` is exactly `expected_changed_paths` and `markers`. `execution` is exactly `observed_pre_worktree_entries`, `observed_post_worktree_entries`, `observed_post_head_sha`, `observed_changed_file_count`, and `sha256_chain`. Each `sha256_chain` entry is exactly `seed_sha256`, `staged_sha256`, `materialized_sha256`, `seed_staged_differ`, and `stage_materialize_equal`. `committed_binding` is exactly `commit_identity`, `changed_paths`, and `committed_file_hashes`; `commit_identity` is exactly `parent_sha` and `commit_sha`. Commit identifiers are 40 lowercase hexadecimal characters and SHA-256 values are 64 lowercase hexadecimal characters.

## Canonical JSON bytes

Canonical JSON is produced recursively with object member names sorted in Unicode code-point order, no whitespace between tokens, `,` between array items and object members, `:` between each member name and value, and all non-ASCII characters escaped using the JSON serializer's ASCII form. The resulting JSON text is encoded as UTF-8. Non-finite numbers are forbidden. In Python terms, the operation is exactly:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"),
           ensure_ascii=True, allow_nan=False).encode("utf-8")
```

The complete input text, decoded strictly as UTF-8 without newline translation, must equal this canonical serialization of the parsed object. This exact-wire check is performed last, only after every signature and binding check succeeds. Doing it earlier would mask the authenticated failure an implementer is trying to test: a non-canonical mutation of a signed field must report the broken signature or binding before serialization, while a whitespace-only rewrite of an otherwise passing passport reports non-canonical serialization.

## Trust anchors and Ed25519

The verifier contains closed constant maps for two trust-anchor identifiers. Public keys are constants inside the implementation; they are never read from the passport, a file, an environment variable, or a command-line option — a verifier that accepts a key from its input verifies nothing.

An implementation must pin exactly these two, as 32-byte Ed25519 public keys:

| Identifier | Public key, hexadecimal |
|---|---|
| `kbp-owner-ed25519-v0.2` | `5e6e3cd40ec7feed51f0a3d803a4e105f14dd07d2a221e6edef072cc7952bcde` |
| `kbp-service-custody-ed25519-v0.1` | `86f86166be52a9264cd9176b7a31fb5dccaa6c5c6fd2d01aa2a33b769dd6a6c5` |

These are public keys, not secrets: they are what a reader checks signatures *against*, and they are published in full in every implementation. An earlier revision of this document withheld them as "key material" and named only the identifiers. That made the specification insufficient — an implementation built from it could not pin the same anchors, which a second implementation discovered by hitting exactly that wall. The corresponding private keys are held by the owner and appear nowhere.

All three signatures use Ed25519. `signature_hex` is exactly 128 lowercase hexadecimal characters encoding the 64-byte signature `R || S`. Public keys are 32 bytes. Verification follows RFC 8032 with SHA-512. A decoded public-key point of small order is refused. `S` must be strictly less than the Ed25519 group order, which rejects the scalar malleability form. Encodings that do not decode to curve points are refused. The implementation explicitly rejects a small-order public key; it does not separately reject a small-order `R` point.

## Signature payloads and order

All payload objects below are serialized with the canonical JSON rule and then UTF-8 encoded.

1. **Owner grant.** The public envelope requires signature version `owner-grant-signature-v0.6`, algorithm `ed25519`, and the pinned owner key. Construct an object containing `signature_version` with that value and the grant values `grant_id`, `issued_by`, `allowed_scope`, `operation_class`, `nonce`, `issued_at`, `expires_at`, `run_id`, `head_sha`, normalized `allowed_files`, exact `task_prompt`, normalized `new_files`, normalized `acceptance_contract`, and `publication_class`. Canonical sorting, not insertion order, determines the bytes. A normalized path list contains strings stripped at both ends, deduplicated while retaining the earliest occurrence, then sorted. The acceptance contract must have exactly `expected_changed_paths` and `markers`; normalize its paths the same way and normalize marker keys by stripping them and marker values with string conversion. `publication_class` must be `public-full-record`; `budget` must be absent or `null`. Verify `authorization.owner_signature` over these bytes before the custody signature.
2. **Custody record.** Require record schema `deedseal-supervised-run-custody/1.0`. Its closed unsigned member set is the set present in the published passport minus `signature`; the signed record has exactly that set plus `signature`. The signature object has exactly `signature_version`, `signature_algorithm`, `signing_key_id`, and `signature_hex`, with version `kbp-service-custody-record-signature/0.1` and algorithm `ed25519`. Construct `{ "domain": "kbp-service-custody-record-signature-v0.1", "signature_version": "kbp-service-custody-record-signature/0.1", "signature_algorithm": "ed25519", "signing_key_id": <declared custody key identifier>, "record": <all unsigned custody members> }`. Verify these bytes against the pinned custody anchor second. Then validate the public custody contract, including its runner report and applied Landlock boundary.
3. **Owner closure.** Verify this last, after all cross-bindings. `closure` has exactly `closure_version` and `signature`; both the closure version and the signature version are `kbp-run-passport-v1-owner-closure/0.1`, the algorithm is `ed25519`, and the signature object has the same closed four-member set as above. Remove the entire `closure` member from the passport to obtain `passport_core`, then sign the canonical bytes of `{ "domain": "kbp-run-passport-v1-owner-closure-signature-v0.1", "closure_version": "kbp-run-passport-v1-owner-closure/0.1", "passport_core": <passport_core> }`. Verify against the pinned owner anchor and require its key identifier to equal the verified grant owner identifier.

## Verification and cross-bindings

After the owner-grant and custody signatures verify, enforce these checks in order and stop at the earliest failure:

1. The public envelope, v0.6 grant, public-full-record publication class, neutral custody schema, and custody publication class select each other. The custody target equals the grant's `allowed_scope`; the operation class is `agent_subprocess`; the passport and custody roadmap steps agree. The custody record is `OUTCOME_SUCCESS` with the required public-capture constants and a structurally valid runner report.
2. SHA-256 of the canonical complete embedded `authorization` object equals `custody.grant_sha256`. The applied boundary's `grant_sha256` is structurally a digest and, through the signed custody record, equals this same value.
3. `run_id` is equal across passport, grant, and custody. `execution_id` is equal across passport and custody. `implementation_head_sha` equals grant `head_sha`, custody `head_sha`, and custody `observed_post_head_sha`. `grant_id` is equal across grant and custody.
4. Normalize and require equality of `scope.allowed_files`, `authorization.allowed_files`, and `custody.allowed_files`. Normalize and require equality of scope and authorization `new_files`, each new path being in the allowed set. Normalize the scope and authorization acceptance contracts as described above; require them equal and require `expected_changed_paths` to equal the allowed set.
5. The execution pre/post path lists and post-head/count fields equal the custody-signed observations. The changed count equals the allowed-set length; the sorted, deduplicated post paths equal the allowed set.
6. `sha256_chain` has exactly one member per allowed path. Staged and materialized hashes are valid and equal, and `stage_materialize_equal` is true. A new file has null seed and null `seed_staged_differ`; an existing file has a valid seed different from staged and `seed_staged_differ` true.
7. `committed_binding.commit_identity.parent_sha` equals the pinned `implementation_head_sha`; `commit_sha` is valid and differs from the parent. Normalize `changed_paths` and require the stored list already be canonical and equal the allowed set. `committed_file_hashes` has exactly those keys, and each committed hash equals that path's materialized hash.
8. The applied boundary has schema `deedseal-landlock-applied-boundary/1.1`, status `applied`, `no_new_privs` true, default `deny`, and the exact ten handled write rights shown in the published passport. Its ordered rule paths equal the sorted signed allowed-file list; each rule permits only `write_file`. The runtime-scratch object has the exact class, rights, pinned root digest, and non-negative device/inode values shown in the published passport. This check authenticates recorded boundary data; it does not re-apply the boundary.
9. Verify the owner closure and same-owner-key equality as specified above.
10. Only now compare the complete input text to canonical JSON.

## Closed custody and boundary contracts

The custody record has exactly these unsigned members, plus `signature`:
`record_schema`, `publication_class`, `step`, `record_status`, `reason_code`,
`execution_id`, `run_id`, `roadmap_step`, `evidence_ref`, `head_sha`, `target`,
`allowed_files`, `argv`, `working_directory`, `agent_executable`, `grant_id`,
`grant_sha256`, `gate_verdict`, `gate_reason_code`, `client_uid`, `authorized_at`,
`completed_at`, `observed_pre_worktree_entries`,
`observed_post_worktree_entries`, `observed_post_head_sha`,
`observed_changed_file_count`, and `runner_report`.

For `public-full-record`, `execution_id` is 32 lowercase hexadecimal characters;
`step` is `deedseal-bounded-file-set/1.0`; `roadmap_step` and `evidence_ref` are
`deedseal-public-run/1.0`; `target` is
`deedseal-bounded-file-set/1.0/edit`; `agent_executable` is
`/opt/agent-runner/bin/agent`; `working_directory` is that execution identifier
under `/var/lib/deedseal-quarantine/`; nonempty `argv` begins with the agent
executable. An outcome success has reason
`allow_supervised_agent_capture_recorded`. The runner report has exactly
`protocol_version`, `execution_id`, `run_id`, `head_sha`, `report_status`,
`argv`, `exit_code`, `stdout_sha256`, `stderr_sha256`, `stdout_excerpt`,
`stderr_excerpt`, `os_boundary`, and `publication_class`. Its protocol is
`deedseal-agent-runner/1.0`; its publication class and argv equal custody; both
output digests are SHA-256 strings and both excerpts equal
`[redacted:public-full-record]`. The verifier does not otherwise constrain the
report's identity, status, exit-code, or head fields directly; they remain inside
the signed custody bytes.

The applied-boundary object has exactly `schema_version`, `application_status`,
`abi`, `no_new_privs`, `handled_access_fs`, `default_for_handled_access`,
`grant_sha256`, `rules`, and `runtime_scratch`. ABI is an integer of at least one.
The exact ordered handled rights are `write_file`, `remove_dir`, `remove_file`,
`make_char`, `make_dir`, `make_reg`, `make_sock`, `make_fifo`, `make_block`, and
`make_sym`. Every nonempty rule has exactly `allowed_file`, `object_dev`,
`object_ino`, and `allowed_access_fs`; the last value is exactly `["write_file"]`
and device/inode values are non-negative integers. Runtime scratch has exactly
`scratch_class`, `scratch_root_sha256`, `object_dev`, `object_ino`, and
`allowed_access_fs`; its class is `agent_runtime_scratch`, its rights are exactly
`["write_file", "make_dir", "make_reg"]`, and its root digest is
`768f8b3b2a86cdbe6f711c61f47642ef334b113d22fdfee51ee28eb945e5ad8a`.

The grant signature object is required to provide the four signature members
used above. Unlike custody and closure signatures, the current verifier does not
refuse additional members in `authorization.owner_signature`; those members are
excluded from the grant signature payload but included in the grant digest,
custody signature, and owner closure. Likewise, authorization itself is not
checked against a closed member set; fields outside the constructed grant payload
are authenticated by the custody digest and closure, and `budget` is the one
extra field explicitly required to be absent or null by grant-payload construction.

## Verdict protocol

The command accepts exactly one positional path and no flags. Invalid invocation writes a two-line usage message to stderr and exits `2`; it is not a verdict. An unreadable path writes `RUN_PASSPORT_VERDICT: BLOCK passport_unreadable (<operating-system error>)` to stderr and exits `1`. Invalid UTF-8 writes `RUN_PASSPORT_VERDICT: BLOCK block_run_passport_unparseable` to stderr and exits `1`.

For a readable UTF-8 input, stdout is exactly three newline-terminated lines:

```text
owner_trust_anchor_key_id: <verified owner identifier or unverified>
custody_trust_anchor_key_id: kbp-service-custody-ed25519-v0.1
RUN_PASSPORT_VERDICT: PASS
```

PASS exits `0`. BLOCK replaces the last line with `RUN_PASSPORT_VERDICT: BLOCK <reason>` and exits `1`; the owner identifier is `unverified`. Verification stops at the earliest failure. Consequently one mutated input surfaces only one reason, even when it breaks several later checks.

## Refusal reasons

Generated by `tools/build_publication.py`. Do not edit between the markers.

<!-- generated:passport-refusal-reasons -->
- `block_acceptance_contract_binding_mismatch` — Refuses acceptance contract binding mismatch.
- `block_allowed_files_binding_mismatch` — Refuses allowed files binding mismatch.
- `block_cargo_commit_equals_execution_head` — Refuses cargo commit equals execution head.
- `block_commit_identity_binding_mismatch` — Refuses commit identity binding mismatch.
- `block_committed_hash_binding_mismatch` — Refuses committed hash binding mismatch.
- `block_complete_cargo_changeset_binding_mismatch` — Refuses complete cargo changeset binding mismatch.
- `block_custody_outcome_not_success` — Refuses custody outcome not success.
- `block_custody_publication_contract_malformed` — Refuses custody publication contract malformed.
- `block_custody_record_malformed` — Refuses custody record malformed.
- `block_custody_record_schema_unsupported` — Refuses custody record schema unsupported.
- `block_custody_record_signature_invalid` — Refuses custody record signature invalid.
- `block_custody_record_wrong_key` — Refuses custody record wrong key.
- `block_execution_id_binding_mismatch` — Refuses execution id binding mismatch.
- `block_grant_custody_binding_mismatch` — Refuses grant custody binding mismatch.
- `block_grant_id_binding_mismatch` — Refuses grant id binding mismatch.
- `block_implementation_head_binding_mismatch` — Refuses implementation head binding mismatch.
- `block_new_files_binding_mismatch` — Refuses new files binding mismatch.
- `block_observed_paths_binding_mismatch` — Refuses observed paths binding mismatch.
- `block_owner_authorization_malformed` — Refuses owner authorization malformed.
- `block_owner_authorization_signature_invalid` — Refuses owner authorization signature invalid.
- `block_owner_authorization_wrong_key` — Refuses owner authorization wrong key.
- `block_owner_closure_signature_invalid` — Refuses owner closure signature invalid.
- `block_owner_closure_signature_malformed` — Refuses owner closure signature malformed.
- `block_owner_closure_signature_missing` — Refuses owner closure signature missing.
- `block_owner_closure_signature_wrong_key` — Refuses owner closure signature wrong key.
- `block_owner_closure_unknown_field` — Refuses owner closure unknown field.
- `block_public_run_passport_contract_malformed` — Refuses public run passport contract malformed.
- `block_public_run_passport_noncanonical_serialization` — Refuses public run passport noncanonical serialization.
- `block_run_id_binding_mismatch` — Refuses run id binding mismatch.
- `block_run_passport_duplicate_key` — Refuses run passport duplicate key.
- `block_run_passport_malformed_section` — Refuses run passport malformed section.
- `block_run_passport_missing_field` — Refuses run passport missing field.
- `block_run_passport_not_object` — Refuses run passport not object.
- `block_run_passport_schema_unsupported` — Refuses run passport schema unsupported.
- `block_run_passport_trailing_content` — Refuses run passport trailing content.
- `block_run_passport_unknown_field` — Refuses run passport unknown field.
- `block_run_passport_unparseable` — Refuses run passport unparseable.
- `block_sha256_chain_binding_mismatch` — Refuses sha256 chain binding mismatch.
- `block_supervised_agent_capture_failed` — Refuses supervised agent capture failed.
<!-- /generated:passport-refusal-reasons -->

`passport_unreadable` is a CLI I/O reason, not a declared `block_*` verifier reason. Its operating-system detail is appended only on the unreadable-path path.

## Compatibility commitment

The envelope `deedseal-run-passport/1.0` is frozen. A promise stated vaguely is
worse than none, so both halves of this one are explicit.

**What is promised.** A passport carrying this `schema_version` will continue to
verify with the published verifier. The top-level field set stays closed exactly
as specified above. The canonical byte form, the three signature payloads, the
order in which checks run, the refusal vocabulary, and the verdict protocol do
not change. The published trust anchors are not removed. Passports already
published keep verifying, and the committed conformance vectors keep producing
the verdicts recorded for them.

**What is not promised.** That the envelope never gains capability. New
capability — a boundary that also covers network egress, say — arrives as a new
`schema_version`, admitted by a verifier that recognizes it, while passports
under this one keep verifying unchanged. This is why unknown fields are refused
rather than ignored: additive change is a version, never a silent extension. An
implementation that tolerates an unknown field to be helpful has broken the
property the refusal exists to hold.

**What freezing does not say about implementations.** That an implementation
passes the conformance suite establishes agreement on the published vectors. It
does not establish correctness in general, and it is not a statement that any
implementation is safe to rely on.

## Deviations

The reader explainer formerly called the synthetic example illustrative without pointing to an implementation specification. It now points here. The published verifier is authoritative where an earlier explanatory summary omitted detail. In particular, the exact-wire canonical serialization check runs after closure, the optional `supplementary_evidence` member is tolerated but closure-authenticated, and the implementation rejects small-order public keys but does not separately reject a small-order signature `R` point.
