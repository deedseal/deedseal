#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline verifier for one Deedseal run passport. PASS or BLOCK, nothing else.

WHAT THIS IS. One file, Python standard library only. No network, no repository checkout,
no running service, no private key, no third-party package, no configuration. Hand it one
passport and it answers with a single line -- `RUN_PASSPORT_VERDICT: PASS` and exit code 0,
or `RUN_PASSPORT_VERDICT: BLOCK <reason_code>` and exit code 1. A missing argument exits 2
and is not a verdict. An unreadable or nonexistent path prints
`RUN_PASSPORT_VERDICT: BLOCK passport_unreadable` and exits 1. Read the file before you
trust its answer; that is why it is one file.

WHAT A PASS MEANS, PRECISELY. Every link below verified over exactly the bytes you supplied:

  1. The owner authorized the run BEFORE it happened. The work grant is signed by the pinned
     owner key and binds the repository state, a validity window, the exact file set the run
     was allowed to change, and the exact instruction the agent was given.
  2. A service recorded custody of the run under a DIFFERENT key than the owner's. A service
     that could sign with the owner's key would be a service that could mint authority.
  3. The kernel boundary that was actually applied is recorded: which filesystem rights were
     denied by default, which exact files were re-permitted, and the one non-grant scratch
     class the agent needs to start. It is bound to the digest of the grant it was derived
     from, so a boundary from some other run cannot be presented with this one.
  4. The complete set of changed paths equals the granted set, with a digest of the committed
     bytes for each. A passport cannot present a flattering subset of what happened.
  5. The owner closed the assembled record as the final act, signing everything above.

WHAT A PASS DOES NOT MEAN. It says nothing about whether the change was a good change --
authorization, boundary, and provenance are not code review. It says nothing about any run it
does not bind. It does not prove the machine that produced it was uncompromised: signing-key
secrecy is a trusted prerequisite, and an attacker holding the private keys can mint records
this file will accept. It is not a replay ledger -- a genuine old passport stays a genuine old
passport, because substitution and tampering are the problems this answers, not re-presentation.

THE KEYS ARE PINNED, NOT SUPPLIED. Two Ed25519 public keys are literals below. No flag, no
environment variable, and no field inside a passport can select, override, or add one. A public
key carried inside a passport is attacker-controlled data; there is no code path here that would
read one. Key substitution is not rejected by a check -- it is unrepresentable.

WHY THE VERDICT IS BINARY. Anything unexpected fails closed with one bounded reason code: an
unknown field, a missing field, a duplicate JSON key, a trailing byte, a non-canonical
serialization, a signature over different bytes. There is no partial credit and no warning
level, because a passport that is almost valid is not evidence of anything.

SCOPE OF THIS COPY. This verifier admits exactly one envelope -- the published
`deedseal-run-passport/1.0` -- and nothing else. Internal formats predating publication are
verified by their own tooling, which is not published; a passport of any other schema is
refused here rather than partially understood. Publication hygiene -- the rule that a
publishable record carries no operational text -- is enforced where a record is signed, not
here: you can read this passport yourself, and this file's job is the signature chain.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from typing import Any, Mapping


# --- The pinned production trust anchors. Not defaults to override; the CLI never
# --- supplies a substitute, and no passport field can name one. --------------------------
#
# The owner anchor set published here is a closed, one-key map: the live
# v0.2 owner key. Earlier keys and the records signed under them are not
# published, and this copy cannot verify them.
LIVE_OWNER_KEY_ID = "kbp-owner-ed25519-v0.2"
LIVE_OWNER_PUBLIC_KEY_HEX = (
    "5e6e3cd40ec7feed51f0a3d803a4e105f14dd07d2a221e6edef072cc7952bcde"
)
# The service-custody key signs the custody record and mirrors the private
# custody signer's committed anchor.
PRODUCTION_CUSTODY_KEY_ID = "kbp-service-custody-ed25519-v0.1"
PRODUCTION_CUSTODY_PUBLIC_KEY_HEX = (
    "86f86166be52a9264cd9176b7a31fb5dccaa6c5c6fd2d01aa2a33b769dd6a6c5"
)

PRODUCTION_OWNER_TRUST_ANCHORS: dict[str, str] = {
    LIVE_OWNER_KEY_ID: LIVE_OWNER_PUBLIC_KEY_HEX,
}
PRODUCTION_CUSTODY_TRUST_ANCHORS: dict[str, str] = {
    PRODUCTION_CUSTODY_KEY_ID: PRODUCTION_CUSTODY_PUBLIC_KEY_HEX,
}


# --- The fixed envelope + signature contract. Copied verbatim from the in-repo signers so
# --- this file needs no import from them. ------------------------------------------------

# The frozen v1 envelope remains the only interpretation of every historical artifact.
# `deedseal-run-passport/1.0` is an additive, separately-dispatched public successor: it
# has the same proof topology, but a neutral envelope, separately qualified closure
# dispatch, and a mandatory full-byte hygiene rule.  A schema value is inside the owner
# closure's signed core, so a v1 artifact can never be reclassified as the public
# successor after signing.
PUBLIC_PASSPORT_SCHEMA_VERSION_V10 = "deedseal-run-passport/1.0"

PASSPORT_TOP_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "roadmap_step",
        "run_id",
        "execution_id",
        "implementation_head_sha",
        "authorization",
        "custody",
        "scope",
        "execution",
        "committed_binding",
        "closure",
    }
)
# Optional top-level fields tolerated (present-and-well-formed only; never trusted for the
# verdict). A routine passport needs no negative probe, so this stays optional.
PASSPORT_OPTIONAL_TOP_FIELDS: frozenset[str] = frozenset({"supplementary_evidence"})

SCOPE_FIELDS: frozenset[str] = frozenset(
    {"allowed_files", "new_files", "acceptance_contract"}
)
ACCEPTANCE_CONTRACT_FIELDS: frozenset[str] = frozenset(
    {"expected_changed_paths", "markers"}
)
EXECUTION_FIELDS: frozenset[str] = frozenset(
    {
        "observed_pre_worktree_entries",
        "observed_post_worktree_entries",
        "observed_post_head_sha",
        "observed_changed_file_count",
        "sha256_chain",
    }
)
SHA_CHAIN_ENTRY_FIELDS: frozenset[str] = frozenset(
    {
        "seed_sha256",
        "staged_sha256",
        "materialized_sha256",
        "seed_staged_differ",
        "stage_materialize_equal",
    }
)
COMMITTED_BINDING_FIELDS: frozenset[str] = frozenset(
    {"commit_identity", "changed_paths", "committed_file_hashes"}
)

# Owner-grant v0.5 signing contract, copied from the private grant signer.
OWNER_GRANT_SIGNATURE_VERSION_V0_5 = "owner-grant-signature-v0.5"
OWNER_GRANT_SIGNATURE_VERSION_V0_6 = "owner-grant-signature-v0.6"
OWNER_GRANT_PUBLICATION_CLASS_INTERNAL = "internal"
OWNER_GRANT_PUBLICATION_CLASS_PUBLIC_FULL_RECORD = "public-full-record"
OWNER_GRANT_PUBLICATION_CLASSES: frozenset[str] = frozenset(
    {
        OWNER_GRANT_PUBLICATION_CLASS_INTERNAL,
        OWNER_GRANT_PUBLICATION_CLASS_PUBLIC_FULL_RECORD,
    }
)
OWNER_GRANT_SIGNATURE_ALGORITHM = "ed25519"
_OWNER_GRANT_SIGNED_FIELDS = ("grant_id", "issued_by", "allowed_scope", "operation_class")
_OWNER_GRANT_FRESHNESS_FIELDS = ("nonce", "issued_at", "expires_at", "run_id", "head_sha")

# Service-custody signing contract, copied from the private custody signer.
# The compatibility spelling remains fixed for existing signed records.
CUSTODY_RECORD_SCHEMA_NEUTRAL_V10 = "deedseal-supervised-run-custody/1.0"
# Signature contract retained for the published custody record.
CUSTODY_SIGNATURE_VERSION = "kbp-service-custody-record-signature/0.1"
CUSTODY_SIGNATURE_ALGORITHM = "ed25519"
CUSTODY_SIGNATURE_DOMAIN = "kbp-service-custody-record-signature-v0.1"
PUBLICATION_CLASS_INTERNAL = "internal"
PUBLICATION_CLASS_PUBLIC_FULL_RECORD = "public-full-record"
PUBLICATION_CLASSES: frozenset[str] = frozenset(
    {PUBLICATION_CLASS_INTERNAL, PUBLICATION_CLASS_PUBLIC_FULL_RECORD}
)
PUBLIC_OUTPUT_REDACTION_MARKER = "[redacted:public-full-record]"
NEUTRAL_RUNNER_PROTOCOL_VERSION = "deedseal-agent-runner/1.0"
PUBLIC_RECORD_STEP = "deedseal-bounded-file-set/1.0"
PUBLIC_RECORD_ROADMAP_STEP = "deedseal-public-run/1.0"
PUBLIC_RECORD_TARGET = "deedseal-bounded-file-set/1.0/edit"
PUBLIC_RECORD_SUCCESS_REASON = "allow_supervised_agent_capture_recorded"
PUBLIC_RECORD_FAILURE_REASON = "block_supervised_agent_capture_failed"
PUBLIC_AGENT_EXECUTABLE = "/opt/agent-runner/bin/agent"
PUBLIC_QUARANTINE_ROOT = "/var/lib/deedseal-quarantine"
NEUTRAL_RUNNER_REPORT_FIELDS: frozenset[str] = frozenset(
    {
        "protocol_version",
        "execution_id",
        "run_id",
        "head_sha",
        "report_status",
        "argv",
        "exit_code",
        "stdout_sha256",
        "stderr_sha256",
        "stdout_excerpt",
        "stderr_excerpt",
        "os_boundary",
        "publication_class",
    }
)
# --- The grant-derived Landlock write boundary (copied contract, verbatim) -----------
#
# This verifier imports nothing from the product, so the Landlock contract is copied here
# the same way every other contract in this file is.  Until now it was not copied at all:
# `os_boundary` was admitted as an opaque member of the runner report, which meant the
# central published claim -- that the worker's write boundary is derived from the owner's
# signed grant -- was the one claim a recipient could NOT check offline.  It can now.
#
# Two schema tracks, each with a frozen version and an additive successor.  The successors
# exist because the agent binary cannot start under a boundary that denies every create
# right everywhere: it must write inside its own private runtime home first.  That single
# non-grant capability is recorded in its own top-level `runtime_scratch` object, never as
# a member of `rules`, so `rules` keeps meaning "the owner granted this file" exactly.
LANDLOCK_APPLICATION_SCHEMA_VERSION_NEUTRAL_V10 = (
    "deedseal-landlock-applied-boundary/1.0"
)
LANDLOCK_APPLICATION_SCHEMA_VERSION_NEUTRAL_V11 = (
    "deedseal-landlock-applied-boundary/1.1"
)
LANDLOCK_APPLICATION_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "application_status",
        "abi",
        "no_new_privs",
        "handled_access_fs",
        "default_for_handled_access",
        "grant_sha256",
        "rules",
    }
)
LANDLOCK_APPLICATION_FIELDS_V02: frozenset[str] = LANDLOCK_APPLICATION_FIELDS | {
    "runtime_scratch"
}
LANDLOCK_APPLICATION_FIELDS_BY_SCHEMA: Mapping[str, frozenset[str]] = {
    LANDLOCK_APPLICATION_SCHEMA_VERSION_NEUTRAL_V10: LANDLOCK_APPLICATION_FIELDS,
    LANDLOCK_APPLICATION_SCHEMA_VERSION_NEUTRAL_V11: LANDLOCK_APPLICATION_FIELDS_V02,
}
LANDLOCK_SCHEMAS_WITH_RUNTIME_SCRATCH: frozenset[str] = frozenset(
    {
        LANDLOCK_APPLICATION_SCHEMA_VERSION_NEUTRAL_V11,
    }
)
LANDLOCK_RULE_FIELDS: frozenset[str] = frozenset(
    {
        "allowed_file",
        "object_dev",
        "object_ino",
        "allowed_access_fs",
    }
)
LANDLOCK_RUNTIME_SCRATCH_FIELDS: frozenset[str] = frozenset(
    {
        "scratch_class",
        "scratch_root_sha256",
        "object_dev",
        "object_ino",
        "allowed_access_fs",
    }
)
LANDLOCK_RUNTIME_SCRATCH_CLASS = "agent_runtime_scratch"
# All ten write-class rights are HANDLED, which under Landlock means denied everywhere the
# ruleset does not explicitly re-permit them.  A record listing fewer would be describing a
# weaker boundary than the one claimed.
LANDLOCK_HANDLED_ACCESS_FS: tuple[str, ...] = (
    "write_file",
    "remove_dir",
    "remove_file",
    "make_char",
    "make_dir",
    "make_reg",
    "make_sock",
    "make_fifo",
    "make_block",
    "make_sym",
)
# A grant-derived rule permits writing an existing file and NOTHING else -- no creation, no
# removal, no node.
LANDLOCK_GRANT_RULE_ACCESS_FS: tuple[str, ...] = ("write_file",)
# The runtime-scratch class permits creating and writing under the agent's own runtime home.
# It withholds `remove_file`/`remove_dir` (so the runner's provider credential can be
# neither unlinked nor atomically replaced -- ABI-1 has no REFER, so a cross-directory
# rename is denied outright), `make_sym`, and every device- and node-creating right.
LANDLOCK_RUNTIME_SCRATCH_ACCESS_FS: tuple[str, ...] = (
    "write_file",
    "make_dir",
    "make_reg",
)
# The digest of the ONE admitted scratch root. Pinned, not merely well-formed: without this
# constant a record could claim the non-grant create-and-write rule was applied over `/`, or
# over the repository worktree, and a reader checking only the shape would accept it. The
# path itself is never carried in a record, but its digest discloses WHICH root was used
# while disclosing nothing about the string. Equal by construction to SHA-256 of the
# private boundary builder's committed runtime-scratch path constant; the acceptance
# suite proves the copies agree.
LANDLOCK_RUNTIME_SCRATCH_ROOT_SHA256 = (
    "768f8b3b2a86cdbe6f711c61f47642ef334b113d22fdfee51ee28eb945e5ad8a"
)
CUSTODY_RECORD_FIELDS_NEUTRAL_V10: frozenset[str] = frozenset(
    {
        "record_schema",
        "publication_class",
        "step",
        "record_status",
        "reason_code",
        "execution_id",
        "run_id",
        "roadmap_step",
        "evidence_ref",
        "head_sha",
        "target",
        "allowed_files",
        "argv",
        "working_directory",
        "agent_executable",
        "grant_id",
        "grant_sha256",
        "gate_verdict",
        "gate_reason_code",
        "client_uid",
        "authorized_at",
        "completed_at",
        "observed_pre_worktree_entries",
        "observed_post_worktree_entries",
        "observed_post_head_sha",
        "observed_changed_file_count",
        "runner_report",
    }
)
CUSTODY_SIGNED_RECORD_FIELDS_NEUTRAL_V10: frozenset[str] = (
    CUSTODY_RECORD_FIELDS_NEUTRAL_V10 | {"signature"}
)
CUSTODY_SIGNATURE_FIELDS: frozenset[str] = frozenset(
    {"signature_version", "signature_algorithm", "signing_key_id", "signature_hex"}
)
POSITIVE_CUSTODY_RECORD_STATUS = "OUTCOME_SUCCESS"

# The final owner-closure contract. The owner signs
# the canonical bytes of the ENTIRE passport minus its own `closure` object.
CLOSURE_FIELDS: frozenset[str] = frozenset({"closure_version", "signature"})
CLOSURE_VERSION_V01 = "kbp-run-passport-v1-owner-closure/0.1"
CLOSURE_SIGNATURE_DOMAIN_V01 = "kbp-run-passport-v1-owner-closure-signature-v0.1"
# Owner decision: signature-version/domain anchors are forward-only and remain frozen here.
# The envelope schema is itself in the signed passport_core, which already prevents replay
# between historical and public envelopes without minting a new closure anchor.
PUBLIC_CLOSURE_VERSION_V10 = CLOSURE_VERSION_V01
PUBLIC_CLOSURE_SIGNATURE_DOMAIN_V10 = CLOSURE_SIGNATURE_DOMAIN_V01
CLOSURE_SIGNATURE_ALGORITHM = "ed25519"
CLOSURE_SIGNATURE_FIELDS: frozenset[str] = frozenset(
    {"signature_version", "signature_algorithm", "signing_key_id", "signature_hex"}
)

_SIGNATURE_HEX_RE = re.compile(r"\A[0-9a-f]{128}\Z")
_HEAD_SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_EXECUTION_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")


def closure_contract_for_passport_schema(
    schema_version: object,
) -> tuple[str, str] | None:
    """Return the exact closure version/domain selected by a signed envelope schema.

    Both envelope schemas use the owner-approved frozen closure anchor. Replay remains
    impossible because ``schema_version`` is inside the signed ``passport_core`` bytes.
    """

    if schema_version == PUBLIC_PASSPORT_SCHEMA_VERSION_V10:
        return PUBLIC_CLOSURE_VERSION_V10, PUBLIC_CLOSURE_SIGNATURE_DOMAIN_V10
    return None


# --- Deterministic refusal vocabulary. One bounded reason code per broken link. ----------

BLOCK_PASSPORT_UNPARSEABLE = "block_run_passport_unparseable"
BLOCK_PASSPORT_DUPLICATE_KEY = "block_run_passport_duplicate_key"
BLOCK_PASSPORT_TRAILING_CONTENT = "block_run_passport_trailing_content"
BLOCK_PASSPORT_NOT_OBJECT = "block_run_passport_not_object"
BLOCK_PASSPORT_UNKNOWN_FIELD = "block_run_passport_unknown_field"
BLOCK_PASSPORT_MISSING_FIELD = "block_run_passport_missing_field"
BLOCK_PASSPORT_SCHEMA_UNSUPPORTED = "block_run_passport_schema_unsupported"
BLOCK_PASSPORT_MALFORMED_SECTION = "block_run_passport_malformed_section"
BLOCK_PUBLIC_PASSPORT_CONTRACT_MALFORMED = (
    "block_public_run_passport_contract_malformed"
)
BLOCK_PUBLIC_PASSPORT_NONCANONICAL_SERIALIZATION = (
    "block_public_run_passport_noncanonical_serialization"
)

BLOCK_OWNER_AUTHORIZATION_MALFORMED = "block_owner_authorization_malformed"
BLOCK_OWNER_AUTHORIZATION_WRONG_KEY = "block_owner_authorization_wrong_key"
BLOCK_OWNER_AUTHORIZATION_SIGNATURE_INVALID = "block_owner_authorization_signature_invalid"

BLOCK_CUSTODY_MALFORMED = "block_custody_record_malformed"
BLOCK_CUSTODY_SCHEMA_UNSUPPORTED = "block_custody_record_schema_unsupported"
BLOCK_CUSTODY_WRONG_KEY = "block_custody_record_wrong_key"
BLOCK_CUSTODY_SIGNATURE_INVALID = "block_custody_record_signature_invalid"
BLOCK_CUSTODY_OUTCOME_NOT_SUCCESS = "block_custody_outcome_not_success"
BLOCK_CUSTODY_PUBLICATION_CONTRACT_MALFORMED = (
    "block_custody_publication_contract_malformed"
)
BLOCK_GRANT_CUSTODY_BINDING_MISMATCH = "block_grant_custody_binding_mismatch"
BLOCK_RUN_ID_MISMATCH = "block_run_id_binding_mismatch"
BLOCK_EXECUTION_ID_MISMATCH = "block_execution_id_binding_mismatch"
BLOCK_HEAD_SHA_MISMATCH = "block_implementation_head_binding_mismatch"
BLOCK_GRANT_ID_MISMATCH = "block_grant_id_binding_mismatch"

BLOCK_ALLOWED_FILES_MISMATCH = "block_allowed_files_binding_mismatch"
BLOCK_NEW_FILES_MISMATCH = "block_new_files_binding_mismatch"
BLOCK_ACCEPTANCE_CONTRACT_MISMATCH = "block_acceptance_contract_binding_mismatch"

BLOCK_OBSERVED_PATHS_MISMATCH = "block_observed_paths_binding_mismatch"
BLOCK_SHA_CHAIN_MISMATCH = "block_sha256_chain_binding_mismatch"
BLOCK_COMMITTED_HASH_MISMATCH = "block_committed_hash_binding_mismatch"
BLOCK_COMMIT_IDENTITY_MISMATCH = "block_commit_identity_binding_mismatch"
BLOCK_COMPLETE_CHANGESET_MISMATCH = "block_complete_cargo_changeset_binding_mismatch"
BLOCK_CARGO_COMMIT_EQUALS_EXECUTION_HEAD = "block_cargo_commit_equals_execution_head"

BLOCK_CLOSURE_UNKNOWN_FIELD = "block_owner_closure_unknown_field"
BLOCK_CLOSURE_SIGNATURE_MISSING = "block_owner_closure_signature_missing"
BLOCK_CLOSURE_SIGNATURE_MALFORMED = "block_owner_closure_signature_malformed"
BLOCK_CLOSURE_WRONG_KEY = "block_owner_closure_signature_wrong_key"
BLOCK_CLOSURE_SIGNATURE_INVALID = "block_owner_closure_signature_invalid"


# --- Canonical bytes. Byte-for-byte the same convention as every in-repo signer. ---------


def canonical_json(payload: object) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


# --- Strict JSON parse. A lax parser is an attacker's affordance. ------------------------


class _DuplicateKey(ValueError):
    pass


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateKey(key)
        seen[key] = value
    return seen


def _reject_nan(_token: str) -> Any:
    raise ValueError("non-finite JSON constant")


def parse_passport_json(text: str) -> dict[str, Any]:
    """Parse ONE passport strictly. Raises `ValueError` with one reason code."""

    if not isinstance(text, str):
        raise ValueError(BLOCK_PASSPORT_UNPARSEABLE)
    decoder = json.JSONDecoder(
        object_pairs_hook=_pairs_without_duplicates, parse_constant=_reject_nan
    )
    try:
        parsed, end = decoder.raw_decode(text)
    except _DuplicateKey:
        raise ValueError(BLOCK_PASSPORT_DUPLICATE_KEY) from None
    except (ValueError, RecursionError):
        raise ValueError(BLOCK_PASSPORT_UNPARSEABLE) from None
    if text[end:].strip():
        raise ValueError(BLOCK_PASSPORT_TRAILING_CONTENT)
    if not isinstance(parsed, dict):
        raise ValueError(BLOCK_PASSPORT_NOT_OBJECT)
    return parsed


# --- Pure-Python Ed25519 verification (RFC 8032), included here so the verifier needs
# --- no private imports. ----------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int:
    if y >= _P:
        raise ValueError("ed25519 point y coordinate out of range")
    xx = ((y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        raise ValueError("ed25519 point is not on curve")
    if (x & 1) != sign:
        x = _P - x
    return x


_B_Y = (4 * pow(5, _P - 2, _P)) % _P
_B_X = _recover_x(_B_Y, 0)
_BASE_POINT = (_B_X, _B_Y, 1, (_B_X * _B_Y) % _P)


def _point_add(point_a, point_b):
    x1, y1, z1, t1 = point_a
    x2, y2, z2, t2 = point_b
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _point_mul(point, scalar: int):
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _point_equal(point_a, point_b) -> bool:
    x1, y1, z1, _t1 = point_a
    x2, y2, z2, _t2 = point_b
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _is_small_order_point(point) -> bool:
    return _point_equal(_point_mul(point, 8), _IDENTITY)


def _decode_point(encoded: bytes):
    if len(encoded) != 32:
        raise ValueError("ed25519 point must be 32 bytes")
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return (x, y, 1, (x * y) % _P)


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        public_point = _decode_point(public_key)
        r_point = _decode_point(signature[:32])
    except ValueError:
        return False
    if _is_small_order_point(public_point):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(),
        "little",
    ) % _L
    left = _point_mul(_BASE_POINT, s)
    right = _point_add(r_point, _point_mul(public_point, h))
    return _point_equal(left, right)


def _decode_hex_bytes(value: object, *, expected_length: int) -> bytes | None:
    if not isinstance(value, str) or len(value) != expected_length * 2:
        return None
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return None
    if len(decoded) != expected_length:
        return None
    return decoded


def _verify_ed25519_against_anchors(
    *,
    signing_key_id: object,
    signature_hex: object,
    message: bytes,
    anchors: Mapping[str, str],
    wrong_key_reason: str,
    invalid_reason: str,
    malformed_reason: str,
) -> str | None:
    """Return None on a genuine signature, else one reason code. The anchor is chosen by
    the DECLARED key id and looked up in the trusted map -- never taken from the payload as
    a key itself; an id naming no trusted anchor is a wrong-key refusal."""

    if not isinstance(signing_key_id, str) or signing_key_id not in anchors:
        return wrong_key_reason
    if not isinstance(signature_hex, str) or not _SIGNATURE_HEX_RE.match(signature_hex):
        return malformed_reason
    public_key = _decode_hex_bytes(anchors[signing_key_id], expected_length=32)
    signature_bytes = _decode_hex_bytes(signature_hex, expected_length=64)
    if public_key is None or signature_bytes is None:
        return malformed_reason
    if not _ed25519_verify(public_key, message, signature_bytes):
        return invalid_reason
    return None


# --- Owner-grant v0.5 canonical signing bytes, copied from the private grant signer. -----


def _normalized_path_list(value: object) -> list[str] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return sorted(dict.fromkeys(item.strip() for item in value))


def _verify_complete_committed_binding(
    committed_binding: Mapping[str, Any],
    *,
    scope_allowed: list[str],
    materialized_by_path: Mapping[str, str],
    implementation_head_sha: str,
) -> str | None:
    """Verify the signed cargo identity, complete changeset and committed blob hashes."""

    commit_identity = committed_binding.get("commit_identity")
    if not isinstance(commit_identity, Mapping) or set(commit_identity) != {
        "parent_sha",
        "commit_sha",
    }:
        return BLOCK_COMMIT_IDENTITY_MISMATCH
    parent_sha = commit_identity.get("parent_sha")
    commit_sha = commit_identity.get("commit_sha")
    if (
        not isinstance(parent_sha, str)
        or not _HEAD_SHA_RE.match(parent_sha)
        or not isinstance(commit_sha, str)
        or not _HEAD_SHA_RE.match(commit_sha)
    ):
        return BLOCK_COMMIT_IDENTITY_MISMATCH
    if parent_sha != implementation_head_sha:
        return BLOCK_COMPLETE_CHANGESET_MISMATCH
    if commit_sha == parent_sha:
        return BLOCK_CARGO_COMMIT_EQUALS_EXECUTION_HEAD

    raw_changed_paths = committed_binding.get("changed_paths")
    changed_paths = _normalized_path_list(raw_changed_paths)
    if (
        changed_paths is None
        or raw_changed_paths != changed_paths
        or changed_paths != scope_allowed
    ):
        return BLOCK_COMPLETE_CHANGESET_MISMATCH

    committed_hashes = committed_binding.get("committed_file_hashes")
    if not isinstance(committed_hashes, Mapping) or set(committed_hashes) != set(
        changed_paths
    ):
        return BLOCK_COMMITTED_HASH_MISMATCH
    for path, committed_hash in committed_hashes.items():
        if not isinstance(committed_hash, str) or not _SHA256_RE.match(committed_hash):
            return BLOCK_COMMITTED_HASH_MISMATCH
        if committed_hash != materialized_by_path.get(path):
            return BLOCK_COMMITTED_HASH_MISMATCH
    return None


def canonical_owner_grant_v0_5_payload(grant: Mapping[str, Any]) -> bytes | None:
    """Reproduce EXACTLY the bytes owner-grant-signature-v0.5 signs, or None if the grant
    is structurally unfit to have been signed as v0.5 (which fails closed)."""

    if not isinstance(grant, Mapping):
        return None
    payload: dict[str, Any] = {"signature_version": OWNER_GRANT_SIGNATURE_VERSION_V0_5}
    for field in _OWNER_GRANT_SIGNED_FIELDS:
        value = grant.get(field)
        if not isinstance(value, str) or not value.strip():
            return None
        payload[field] = value
    for field in _OWNER_GRANT_FRESHNESS_FIELDS:
        value = grant.get(field)
        if not isinstance(value, str) or not value.strip():
            return None
        payload[field] = value
    allowed_files = _normalized_path_list(grant.get("allowed_files"))
    if allowed_files is None:
        return None
    payload["allowed_files"] = allowed_files
    task_prompt = grant.get("task_prompt")
    if not isinstance(task_prompt, str):
        return None
    payload["task_prompt"] = task_prompt
    new_files = _normalized_path_list(grant.get("new_files"))
    if new_files is None:
        return None
    payload["new_files"] = new_files
    contract = grant.get("acceptance_contract")
    if not isinstance(contract, Mapping) or set(contract) != ACCEPTANCE_CONTRACT_FIELDS:
        return None
    expected = _normalized_path_list(contract.get("expected_changed_paths"))
    markers = contract.get("markers")
    if expected is None or not isinstance(markers, Mapping):
        return None
    normalized_markers: dict[str, str] = {}
    for key, value in markers.items():
        if not isinstance(key, str):
            return None
        normalized_markers[key.strip()] = str(value)
    payload["acceptance_contract"] = {
        "expected_changed_paths": expected,
        "markers": normalized_markers,
    }
    # This envelope's authorization grants carry no `budget`; a grant that does is
    # out of contract for this passport version and fails closed.
    if grant.get("budget") is not None:
        return None
    return canonical_json(payload).encode("utf-8")


def canonical_owner_grant_v0_6_payload(grant: Mapping[str, Any]) -> bytes | None:
    """Reproduce the additive v0.6 owner bytes, including publication_class."""

    if not isinstance(grant, Mapping):
        return None
    payload: dict[str, Any] = {"signature_version": OWNER_GRANT_SIGNATURE_VERSION_V0_6}
    for field in _OWNER_GRANT_SIGNED_FIELDS:
        value = grant.get(field)
        if not isinstance(value, str) or not value.strip():
            return None
        payload[field] = value
    for field in _OWNER_GRANT_FRESHNESS_FIELDS:
        value = grant.get(field)
        if not isinstance(value, str) or not value.strip():
            return None
        payload[field] = value
    allowed_files = _normalized_path_list(grant.get("allowed_files"))
    if allowed_files is None:
        return None
    payload["allowed_files"] = allowed_files
    task_prompt = grant.get("task_prompt")
    if not isinstance(task_prompt, str):
        return None
    payload["task_prompt"] = task_prompt
    new_files = _normalized_path_list(grant.get("new_files"))
    if new_files is None:
        return None
    payload["new_files"] = new_files
    contract = grant.get("acceptance_contract")
    if not isinstance(contract, Mapping) or set(contract) != ACCEPTANCE_CONTRACT_FIELDS:
        return None
    expected = _normalized_path_list(contract.get("expected_changed_paths"))
    markers = contract.get("markers")
    if expected is None or not isinstance(markers, Mapping):
        return None
    normalized_markers: dict[str, str] = {}
    for key, value in markers.items():
        if not isinstance(key, str):
            return None
        normalized_markers[key.strip()] = str(value)
    payload["acceptance_contract"] = {
        "expected_changed_paths": expected,
        "markers": normalized_markers,
    }
    publication_class = grant.get("publication_class")
    if (
        not isinstance(publication_class, str)
        or publication_class not in OWNER_GRANT_PUBLICATION_CLASSES
    ):
        return None
    payload["publication_class"] = publication_class
    if grant.get("budget") is not None:
        return None
    return canonical_json(payload).encode("utf-8")


# --- Service-custody canonical signing bytes, copied from the private custody signer. ----


def _custody_record_fields_for_schema(schema: object) -> frozenset[str] | None:
    if schema == CUSTODY_RECORD_SCHEMA_NEUTRAL_V10:
        return CUSTODY_RECORD_FIELDS_NEUTRAL_V10
    return None


def _custody_signed_record_fields_for_schema(
    schema: object,
) -> frozenset[str] | None:
    fields = _custody_record_fields_for_schema(schema)
    return None if fields is None else fields | {"signature"}


def _valid_output_digest(value: object) -> bool:
    return value is None or (
        isinstance(value, str) and bool(_SHA256_RE.match(value))
    )


def _valid_landlock_observation(value: object, *, allowed_files: object) -> bool:
    """Check ONE applied-Landlock observation against the copied contract, offline.

    This is what makes the grant-derivation claim checkable by a recipient who holds only
    this file and one record.  The decisive check is the last one on `rules`: the observed
    rule file list must equal the SIGNED `allowed_files` exactly -- not a subset, not a
    superset -- so an applied boundary that reached one file the owner did not sign for, or
    that quietly dropped one, is refused here rather than taken on trust.

    `runtime_scratch` is checked structurally: the exact key set, the one admitted class,
    and the one pinned access list. Its root is disclosed only as a digest, and this
    verifier pins that digest's value: the recorded root must equal the constant committed
    here.
    """

    if not isinstance(value, Mapping):
        return False
    schema_version = value.get("schema_version")
    fields = (
        LANDLOCK_APPLICATION_FIELDS_BY_SCHEMA.get(schema_version)
        if isinstance(schema_version, str)
        else None
    )
    if fields is None or set(value) != fields:
        return False
    if (
        value.get("application_status") != "applied"
        or value.get("no_new_privs") is not True
        or value.get("default_for_handled_access") != "deny"
        or value.get("handled_access_fs") != list(LANDLOCK_HANDLED_ACCESS_FS)
    ):
        return False
    abi = value.get("abi")
    if type(abi) is not int or abi < 1:
        return False
    # Structural only: that this digest EQUALS the record's signed `grant_sha256` is
    # established by the custody/passport binding checks that already own that comparison.
    # Re-deciding it here would silently reorder which block reason wins for an unrelated
    # tamper, and those reason codes are part of the published contract.
    observed_grant_digest = value.get("grant_sha256")
    if not isinstance(observed_grant_digest, str) or not _SHA256_RE.match(
        observed_grant_digest
    ):
        return False
    rules = value.get("rules")
    if not isinstance(rules, list) or not rules:
        return False
    observed_files: list[str] = []
    for rule in rules:
        if not isinstance(rule, Mapping) or set(rule) != LANDLOCK_RULE_FIELDS:
            return False
        allowed_file = rule.get("allowed_file")
        if (
            not isinstance(allowed_file, str)
            or not allowed_file
            or rule.get("allowed_access_fs") != list(LANDLOCK_GRANT_RULE_ACCESS_FS)
            or type(rule.get("object_dev")) is not int
            or type(rule.get("object_ino")) is not int
            or rule["object_dev"] < 0
            or rule["object_ino"] < 0
        ):
            return False
        observed_files.append(allowed_file)
    if (
        not isinstance(allowed_files, list)
        or not allowed_files
        or not all(isinstance(item, str) for item in allowed_files)
        or len(set(allowed_files)) != len(allowed_files)
        or observed_files != sorted(allowed_files)
    ):
        return False
    scratch = value.get("runtime_scratch")
    if schema_version in LANDLOCK_SCHEMAS_WITH_RUNTIME_SCRATCH:
        scratch_root_sha256 = (
            scratch.get("scratch_root_sha256") if isinstance(scratch, Mapping) else None
        )
        if (
            not isinstance(scratch, Mapping)
            or set(scratch) != LANDLOCK_RUNTIME_SCRATCH_FIELDS
            or scratch.get("scratch_class") != LANDLOCK_RUNTIME_SCRATCH_CLASS
            or scratch.get("allowed_access_fs")
            != list(LANDLOCK_RUNTIME_SCRATCH_ACCESS_FS)
            or scratch_root_sha256 != LANDLOCK_RUNTIME_SCRATCH_ROOT_SHA256
            or type(scratch.get("object_dev")) is not int
            or type(scratch.get("object_ino")) is not int
            or scratch["object_dev"] < 0
            or scratch["object_ino"] < 0
        ):
            return False
    return True


def _custody_publication_contract_is_valid(record: Mapping[str, Any]) -> bool:
    if record.get("record_schema") != CUSTODY_RECORD_SCHEMA_NEUTRAL_V10:
        return True
    publication_class = record.get("publication_class")
    if (
        not isinstance(publication_class, str)
        or publication_class not in PUBLICATION_CLASSES
    ):
        return False
    if publication_class == PUBLICATION_CLASS_PUBLIC_FULL_RECORD:
        execution_id = record.get("execution_id")
        argv = record.get("argv")
        status = record.get("record_status")
        reason = record.get("reason_code")
        if (
            not isinstance(execution_id, str)
            or not _EXECUTION_ID_RE.match(execution_id)
            or record.get("step") != PUBLIC_RECORD_STEP
            or record.get("roadmap_step") != PUBLIC_RECORD_ROADMAP_STEP
            or record.get("evidence_ref") != PUBLIC_RECORD_ROADMAP_STEP
            or record.get("target") != PUBLIC_RECORD_TARGET
            or record.get("agent_executable") != PUBLIC_AGENT_EXECUTABLE
            or record.get("working_directory")
            != f"{PUBLIC_QUARANTINE_ROOT}/{execution_id}"
            or not isinstance(argv, list)
            or not argv
            or argv[0] != PUBLIC_AGENT_EXECUTABLE
            or status not in {"AUTHORIZED", "OUTCOME_SUCCESS", "OUTCOME_FAILED"}
            or (
                status == "OUTCOME_SUCCESS"
                and reason != PUBLIC_RECORD_SUCCESS_REASON
            )
            or (
                status == "OUTCOME_FAILED"
                and reason != PUBLIC_RECORD_FAILURE_REASON
            )
            or (status == "AUTHORIZED" and reason is not None)
        ):
            return False
    report = record.get("runner_report")
    if report is None:
        return record.get("record_status") != POSITIVE_CUSTODY_RECORD_STATUS
    if not isinstance(report, Mapping) or set(report) != NEUTRAL_RUNNER_REPORT_FIELDS:
        return False
    # `os_boundary` is None for any report that is not a completed process; a completed one
    # that succeeded MUST carry an observation, and that observation must survive the copied
    # Landlock contract above.
    #
    # The requirement is the point, not the validation. Accepting a positive record with no
    # observation at all would make the whole offline Landlock check optional in exactly the
    # case a recipient cares about: a passing passport could then be silent about the write
    # boundary, and silence would read as compliance. A successful run that cannot show its
    # applied boundary is refused instead.
    os_boundary = report.get("os_boundary")
    if (
        os_boundary is None
        and record.get("record_status") == POSITIVE_CUSTODY_RECORD_STATUS
    ):
        return False
    if os_boundary is not None and not _valid_landlock_observation(
        os_boundary, allowed_files=record.get("allowed_files")
    ):
        return False
    if (
        report.get("protocol_version") != NEUTRAL_RUNNER_PROTOCOL_VERSION
        or report.get("publication_class") != publication_class
        or not _valid_output_digest(report.get("stdout_sha256"))
        or not _valid_output_digest(report.get("stderr_sha256"))
        or not isinstance(report.get("stdout_excerpt"), str)
        or not isinstance(report.get("stderr_excerpt"), str)
    ):
        return False
    if record.get("record_status") == POSITIVE_CUSTODY_RECORD_STATUS and (
        not isinstance(report.get("stdout_sha256"), str)
        or not isinstance(report.get("stderr_sha256"), str)
    ):
        return False
    if publication_class == PUBLICATION_CLASS_PUBLIC_FULL_RECORD:
        return (
            report.get("argv") == record.get("argv")
            and report.get("stdout_excerpt") == PUBLIC_OUTPUT_REDACTION_MARKER
            and report.get("stderr_excerpt") == PUBLIC_OUTPUT_REDACTION_MARKER
        )
    return True


def canonical_custody_signing_payload(
    record: Mapping[str, Any], *, signing_key_id: str
) -> bytes | None:
    if not isinstance(record, Mapping):
        return None
    fields = _custody_record_fields_for_schema(record.get("record_schema"))
    if fields is None or fields - set(record):
        return None
    unsigned = {field: record[field] for field in sorted(fields)}
    payload = {
        "domain": CUSTODY_SIGNATURE_DOMAIN,
        "signature_version": CUSTODY_SIGNATURE_VERSION,
        "signature_algorithm": CUSTODY_SIGNATURE_ALGORITHM,
        "signing_key_id": signing_key_id,
        "record": unsigned,
    }
    try:
        return canonical_json(payload).encode("utf-8")
    except (TypeError, ValueError):
        return None


# --- Final owner-closure canonical signing bytes for this envelope. ----------------------


def canonical_closure_payload(passport: Mapping[str, Any]) -> bytes | None:
    """The bytes the owner signs to close the passport: the entire passport MINUS its own
    `closure` object, wrapped in a domain-separated envelope. The closure object is
    excluded so candidate-only closure fields (owner action, unsigned hash) never enter
    the signed subject and the signature is non-self-referential."""

    if not isinstance(passport, Mapping):
        return None
    closure_contract = closure_contract_for_passport_schema(
        passport.get("schema_version")
    )
    if closure_contract is None:
        return None
    closure_version, closure_signature_domain = closure_contract
    core = {key: value for key, value in passport.items() if key != "closure"}
    payload = {
        "domain": closure_signature_domain,
        "closure_version": closure_version,
        "passport_core": core,
    }
    try:
        return canonical_json(payload).encode("utf-8")
    except (TypeError, ValueError):
        return None


# --- Small structural helpers. -----------------------------------------------------------


def _is_str_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --- Verify. The whole answer surface: `ok` plus one bounded reason code. -----------------


def _verify_run_passport(
    passport: object,
    *,
    owner_trust_anchors: Mapping[str, str] = PRODUCTION_OWNER_TRUST_ANCHORS,
    custody_trust_anchors: Mapping[str, str] = PRODUCTION_CUSTODY_TRUST_ANCHORS,
) -> tuple[bool, str | None]:
    """Verify ONE parsed passport. Returns `(True, None)` only when every link verifies,
    else `(False, reason_code)`. Fails closed on the first broken link, closure last."""

    # 1. Envelope shape: closed field set, required present, optional tolerated.
    if not isinstance(passport, Mapping):
        return False, BLOCK_PASSPORT_NOT_OBJECT
    present = set(passport)
    unknown = present - PASSPORT_TOP_FIELDS - PASSPORT_OPTIONAL_TOP_FIELDS
    if unknown:
        return False, BLOCK_PASSPORT_UNKNOWN_FIELD
    missing = PASSPORT_TOP_FIELDS - present
    if missing:
        return False, BLOCK_PASSPORT_MISSING_FIELD
    schema_version = passport.get("schema_version")
    closure_contract = closure_contract_for_passport_schema(schema_version)
    if closure_contract is None:
        return False, BLOCK_PASSPORT_SCHEMA_UNSUPPORTED
    closure_version, _closure_signature_domain = closure_contract
    public_passport = schema_version == PUBLIC_PASSPORT_SCHEMA_VERSION_V10

    grant = passport.get("authorization")
    custody = passport.get("custody")
    scope = passport.get("scope")
    execution = passport.get("execution")
    committed_binding = passport.get("committed_binding")
    closure = passport.get("closure")
    for section in (grant, custody, scope, execution, committed_binding, closure):
        if not isinstance(section, Mapping):
            return False, BLOCK_PASSPORT_MALFORMED_SECTION
    for name, value in (
        ("run_id", passport.get("run_id")),
        ("execution_id", passport.get("execution_id")),
        ("implementation_head_sha", passport.get("implementation_head_sha")),
        ("roadmap_step", passport.get("roadmap_step")),
    ):
        if not isinstance(value, str) or not value.strip():
            return False, BLOCK_PASSPORT_MALFORMED_SECTION
    if set(scope) != SCOPE_FIELDS or set(execution) != EXECUTION_FIELDS:
        return False, BLOCK_PASSPORT_MALFORMED_SECTION
    if set(committed_binding) != COMMITTED_BINDING_FIELDS:
        return False, BLOCK_PASSPORT_MALFORMED_SECTION

    # 2. Owner authorization (grant) signature, against the pinned owner anchor.
    grant_signature = grant.get("owner_signature")
    if not isinstance(grant_signature, Mapping):
        return False, BLOCK_OWNER_AUTHORIZATION_MALFORMED
    grant_signature_version = grant_signature.get("signature_version")
    if grant_signature_version not in (
        OWNER_GRANT_SIGNATURE_VERSION_V0_5,
        OWNER_GRANT_SIGNATURE_VERSION_V0_6,
    ):
        return False, BLOCK_OWNER_AUTHORIZATION_MALFORMED
    if grant_signature.get("signature_algorithm") != OWNER_GRANT_SIGNATURE_ALGORITHM:
        return False, BLOCK_OWNER_AUTHORIZATION_MALFORMED
    grant_message = (
        canonical_owner_grant_v0_6_payload(grant)
        if grant_signature_version == OWNER_GRANT_SIGNATURE_VERSION_V0_6
        else canonical_owner_grant_v0_5_payload(grant)
    )
    if grant_message is None:
        return False, BLOCK_OWNER_AUTHORIZATION_MALFORMED
    refusal = _verify_ed25519_against_anchors(
        signing_key_id=grant_signature.get("signing_key_id"),
        signature_hex=grant_signature.get("signature_hex"),
        message=grant_message,
        anchors=owner_trust_anchors,
        wrong_key_reason=BLOCK_OWNER_AUTHORIZATION_WRONG_KEY,
        invalid_reason=BLOCK_OWNER_AUTHORIZATION_SIGNATURE_INVALID,
        malformed_reason=BLOCK_OWNER_AUTHORIZATION_MALFORMED,
    )
    if refusal is not None:
        return False, refusal
    # The verified owner identity that authorized this run. The closure (step 11) MUST be
    # signed by the SAME owner key id -- see the single-owner-identity check there.
    grant_owner_key_id = grant_signature.get("signing_key_id")

    # 3. Service-custody-record signature, against the pinned custody anchor.
    custody_schema = custody.get("record_schema")
    custody_signed_fields = _custody_signed_record_fields_for_schema(custody_schema)
    if custody_signed_fields is None:
        return False, BLOCK_CUSTODY_SCHEMA_UNSUPPORTED
    if set(custody) != custody_signed_fields:
        return False, BLOCK_CUSTODY_MALFORMED
    custody_signature = custody.get("signature")
    if not isinstance(custody_signature, Mapping):
        return False, BLOCK_CUSTODY_MALFORMED
    if set(custody_signature) != CUSTODY_SIGNATURE_FIELDS:
        return False, BLOCK_CUSTODY_MALFORMED
    if custody_signature.get("signature_version") != CUSTODY_SIGNATURE_VERSION:
        return False, BLOCK_CUSTODY_MALFORMED
    if custody_signature.get("signature_algorithm") != CUSTODY_SIGNATURE_ALGORITHM:
        return False, BLOCK_CUSTODY_MALFORMED
    custody_key_id = custody_signature.get("signing_key_id")
    if not isinstance(custody_key_id, str):
        return False, BLOCK_CUSTODY_MALFORMED
    custody_message = canonical_custody_signing_payload(
        custody, signing_key_id=custody_key_id
    )
    if custody_message is None:
        return False, BLOCK_CUSTODY_MALFORMED
    refusal = _verify_ed25519_against_anchors(
        signing_key_id=custody_key_id,
        signature_hex=custody_signature.get("signature_hex"),
        message=custody_message,
        anchors=custody_trust_anchors,
        wrong_key_reason=BLOCK_CUSTODY_WRONG_KEY,
        invalid_reason=BLOCK_CUSTODY_SIGNATURE_INVALID,
        malformed_reason=BLOCK_CUSTODY_MALFORMED,
    )
    if refusal is not None:
        return False, refusal

    if not _custody_publication_contract_is_valid(custody):
        return False, BLOCK_CUSTODY_PUBLICATION_CONTRACT_MALFORMED

    # The public-capture policy is owner authority, not an unsigned runner option.  A
    # successor custody record is therefore valid only when it echoes the exact closed
    # publication class signed in a v0.6 owner grant.  Conversely, a public v0.6 grant
    # may never be represented by the historical custody schema, whose excerpt semantics
    # intentionally remain frozen.
    if custody_schema == CUSTODY_RECORD_SCHEMA_NEUTRAL_V10:
        if (
            grant_signature_version != OWNER_GRANT_SIGNATURE_VERSION_V0_6
            or custody.get("publication_class") != grant.get("publication_class")
        ):
            return False, BLOCK_GRANT_CUSTODY_BINDING_MISMATCH
    elif grant_signature_version == OWNER_GRANT_SIGNATURE_VERSION_V0_6:
        return False, BLOCK_GRANT_CUSTODY_BINDING_MISMATCH
    if (
        custody_schema == CUSTODY_RECORD_SCHEMA_NEUTRAL_V10
        and custody.get("publication_class")
        == PUBLICATION_CLASS_PUBLIC_FULL_RECORD
        and (
            grant.get("allowed_scope") != custody.get("target")
            or grant.get("operation_class") != "agent_subprocess"
            or passport.get("roadmap_step") != custody.get("roadmap_step")
        )
    ):
        return False, BLOCK_CUSTODY_PUBLICATION_CONTRACT_MALFORMED

    # A public full-record custody cannot be wrapped in the historical RunPassport schema
    # (which would re-introduce internal envelope/closure labels), and the public schema
    # cannot be selected by an unsigned caller hint.  All three selectors are signed and
    # cross-bound: v0.6 owner grant, neutral custody successor, and public envelope.
    if public_passport and not (
        grant_signature_version == OWNER_GRANT_SIGNATURE_VERSION_V0_6
        and grant.get("publication_class")
        == OWNER_GRANT_PUBLICATION_CLASS_PUBLIC_FULL_RECORD
        and custody_schema == CUSTODY_RECORD_SCHEMA_NEUTRAL_V10
        and custody.get("publication_class")
        == PUBLICATION_CLASS_PUBLIC_FULL_RECORD
    ):
        return False, BLOCK_PUBLIC_PASSPORT_CONTRACT_MALFORMED
    if (
        not public_passport
        and custody_schema == CUSTODY_RECORD_SCHEMA_NEUTRAL_V10
        and custody.get("publication_class") == PUBLICATION_CLASS_PUBLIC_FULL_RECORD
    ):
        return False, BLOCK_PUBLIC_PASSPORT_CONTRACT_MALFORMED

    # 3b. Positive RunPassport outcome binding. `record_status` is signed inside the
    # custody record, but it is safe to read only AFTER that signature has verified.
    # A custody record that is authorized, failed, malformed, or otherwise non-success
    # can never yield a positive offline verdict.
    if custody.get("record_status") != POSITIVE_CUSTODY_RECORD_STATUS:
        return False, BLOCK_CUSTODY_OUTCOME_NOT_SUCCESS

    # 4. Exact grant<->custody binding: the custody record's grant_sha256 is the SHA-256
    # of the exact embedded grant object -- the binding the authority service itself signs.
    grant_sha256 = _sha256_hex(canonical_json(grant))
    if custody.get("grant_sha256") != grant_sha256:
        return False, BLOCK_GRANT_CUSTODY_BINDING_MISMATCH

    # 5. Identity binding across passport, grant, and custody.
    run_id = passport.get("run_id")
    execution_id = passport.get("execution_id")
    head_sha = passport.get("implementation_head_sha")
    if not (run_id == grant.get("run_id") == custody.get("run_id")):
        return False, BLOCK_RUN_ID_MISMATCH
    if execution_id != custody.get("execution_id"):
        return False, BLOCK_EXECUTION_ID_MISMATCH
    if not (
        head_sha
        == grant.get("head_sha")
        == custody.get("head_sha")
        == custody.get("observed_post_head_sha")
    ):
        return False, BLOCK_HEAD_SHA_MISMATCH
    if not isinstance(head_sha, str) or not _HEAD_SHA_RE.match(head_sha):
        return False, BLOCK_HEAD_SHA_MISMATCH
    if grant.get("grant_id") != custody.get("grant_id"):
        return False, BLOCK_GRANT_ID_MISMATCH

    # 6. allowed_files / new_files exactness across scope, grant, and custody.
    scope_allowed = _normalized_path_list(scope.get("allowed_files"))
    grant_allowed = _normalized_path_list(grant.get("allowed_files"))
    custody_allowed = _normalized_path_list(custody.get("allowed_files"))
    if scope_allowed is None or grant_allowed is None or custody_allowed is None:
        return False, BLOCK_ALLOWED_FILES_MISMATCH
    if not (scope_allowed == grant_allowed == custody_allowed):
        return False, BLOCK_ALLOWED_FILES_MISMATCH
    scope_new = _normalized_path_list(scope.get("new_files"))
    grant_new = _normalized_path_list(grant.get("new_files"))
    if scope_new is None or grant_new is None or scope_new != grant_new:
        return False, BLOCK_NEW_FILES_MISMATCH
    if any(path not in scope_allowed for path in scope_new):
        return False, BLOCK_NEW_FILES_MISMATCH

    # 7. Acceptance-contract binding: the owner-signed contract equals the
    # passport's scope contract, byte-normalized.
    scope_contract = scope.get("acceptance_contract")
    grant_contract = grant.get("acceptance_contract")
    if (
        not isinstance(scope_contract, Mapping)
        or set(scope_contract) != ACCEPTANCE_CONTRACT_FIELDS
        or not isinstance(grant_contract, Mapping)
    ):
        return False, BLOCK_ACCEPTANCE_CONTRACT_MISMATCH
    scope_expected = _normalized_path_list(scope_contract.get("expected_changed_paths"))
    grant_expected = _normalized_path_list(grant_contract.get("expected_changed_paths"))
    scope_markers = scope_contract.get("markers")
    grant_markers = grant_contract.get("markers")
    if scope_expected is None or grant_expected is None or scope_expected != grant_expected:
        return False, BLOCK_ACCEPTANCE_CONTRACT_MISMATCH
    if not isinstance(scope_markers, Mapping) or not isinstance(grant_markers, Mapping):
        return False, BLOCK_ACCEPTANCE_CONTRACT_MISMATCH
    if {str(k).strip(): str(v) for k, v in scope_markers.items()} != {
        str(k).strip(): str(v) for k, v in grant_markers.items()
    }:
        return False, BLOCK_ACCEPTANCE_CONTRACT_MISMATCH
    if scope_expected != scope_allowed:
        return False, BLOCK_ACCEPTANCE_CONTRACT_MISMATCH

    # 8. Observed changed-path exactness -- the custody-signed observations ARE the source
    # of truth; the passport's execution block must equal them, and their post-set must
    # equal the authorized scope and acceptance surface.
    observed_post = execution.get("observed_post_worktree_entries")
    observed_pre = execution.get("observed_pre_worktree_entries")
    if not _is_str_list(observed_post) or not _is_str_list(observed_pre):
        return False, BLOCK_OBSERVED_PATHS_MISMATCH
    if observed_post != custody.get("observed_post_worktree_entries"):
        return False, BLOCK_OBSERVED_PATHS_MISMATCH
    if observed_pre != custody.get("observed_pre_worktree_entries"):
        return False, BLOCK_OBSERVED_PATHS_MISMATCH
    if execution.get("observed_post_head_sha") != custody.get("observed_post_head_sha"):
        return False, BLOCK_OBSERVED_PATHS_MISMATCH
    if execution.get("observed_changed_file_count") != custody.get(
        "observed_changed_file_count"
    ):
        return False, BLOCK_OBSERVED_PATHS_MISMATCH
    if execution.get("observed_changed_file_count") != len(scope_allowed):
        return False, BLOCK_OBSERVED_PATHS_MISMATCH
    if sorted(dict.fromkeys(observed_post)) != scope_allowed:
        return False, BLOCK_OBSERVED_PATHS_MISMATCH

    # 9. seed / staged / materialized SHA-chain equality requirements.
    chain = execution.get("sha256_chain")
    if not isinstance(chain, Mapping) or set(chain) != set(scope_allowed):
        return False, BLOCK_SHA_CHAIN_MISMATCH
    materialized_by_path: dict[str, str] = {}
    new_file_set = set(scope_new)
    for path, entry in chain.items():
        if not isinstance(entry, Mapping) or set(entry) != SHA_CHAIN_ENTRY_FIELDS:
            return False, BLOCK_SHA_CHAIN_MISMATCH
        staged = entry.get("staged_sha256")
        materialized = entry.get("materialized_sha256")
        seed = entry.get("seed_sha256")
        if not isinstance(staged, str) or not _SHA256_RE.match(staged):
            return False, BLOCK_SHA_CHAIN_MISMATCH
        if not isinstance(materialized, str) or not _SHA256_RE.match(materialized):
            return False, BLOCK_SHA_CHAIN_MISMATCH
        if entry.get("stage_materialize_equal") is not True or staged != materialized:
            return False, BLOCK_SHA_CHAIN_MISMATCH
        if path in new_file_set:
            # A newly created file has no seed; it must not claim a seed differ.
            if seed is not None or entry.get("seed_staged_differ") is not None:
                return False, BLOCK_SHA_CHAIN_MISMATCH
        else:
            # An existing file's staged bytes must differ from its seed bytes.
            if not isinstance(seed, str) or not _SHA256_RE.match(seed):
                return False, BLOCK_SHA_CHAIN_MISMATCH
            if entry.get("seed_staged_differ") is not True or seed == staged:
                return False, BLOCK_SHA_CHAIN_MISMATCH
        materialized_by_path[path] = materialized

    # 10. Complete cargo changeset and committed-byte binding. The owner-signed
    # passport binds the clean execution HEAD as the cargo commit's only parent, the
    # complete canonical parent->commit path set, and the exact committed blob hash for
    # every path. A selected subset can never reach PASS.
    committed_refusal = _verify_complete_committed_binding(
        committed_binding,
        scope_allowed=scope_allowed,
        materialized_by_path=materialized_by_path,
        implementation_head_sha=head_sha,
    )
    if committed_refusal is not None:
        return False, committed_refusal

    # 11. The final owner closure signature over the complete canonical passport payload.
    # An UNSIGNED candidate is refused for its missing closure signature FIRST: it legitimately
    # carries pre-signature bookkeeping fields (`unsigned_closure_payload_sha256`,
    # `owner_action`) that the emitter writes and the owner strips at signing time, and it is
    # never a passport. The closed field set below therefore guards the SIGNED surface, which
    # is the only one whose closure bytes are excluded from the signature and thus the only
    # one where an unknown field would be both unsigned and unchecked.
    closure_signature = closure.get("signature")
    if closure_signature is None:
        return False, BLOCK_CLOSURE_SIGNATURE_MISSING
    if set(closure) != CLOSURE_FIELDS:
        return False, BLOCK_CLOSURE_UNKNOWN_FIELD
    if not isinstance(closure_signature, Mapping):
        return False, BLOCK_CLOSURE_SIGNATURE_MALFORMED
    if set(closure_signature) != CLOSURE_SIGNATURE_FIELDS:
        return False, BLOCK_CLOSURE_SIGNATURE_MALFORMED
    if closure.get("closure_version") != closure_version:
        return False, BLOCK_CLOSURE_SIGNATURE_MALFORMED
    if closure_signature.get("signature_version") != closure_version:
        return False, BLOCK_CLOSURE_SIGNATURE_MALFORMED
    if closure_signature.get("signature_algorithm") != CLOSURE_SIGNATURE_ALGORITHM:
        return False, BLOCK_CLOSURE_SIGNATURE_MALFORMED
    closure_message = canonical_closure_payload(passport)
    if closure_message is None:
        return False, BLOCK_CLOSURE_SIGNATURE_MALFORMED
    refusal = _verify_ed25519_against_anchors(
        signing_key_id=closure_signature.get("signing_key_id"),
        signature_hex=closure_signature.get("signature_hex"),
        message=closure_message,
        anchors=owner_trust_anchors,
        wrong_key_reason=BLOCK_CLOSURE_WRONG_KEY,
        invalid_reason=BLOCK_CLOSURE_SIGNATURE_INVALID,
        malformed_reason=BLOCK_CLOSURE_SIGNATURE_MALFORMED,
    )
    if refusal is not None:
        return False, refusal

    # Single-owner-identity requirement. The grant and closure verify independently against
    # the supplied closed owner-anchor map, and their key ids MUST be identical. A mismatch
    # is refused with the existing closure wrong-key reason.
    if closure_signature.get("signing_key_id") != grant_owner_key_id:
        return False, BLOCK_CLOSURE_WRONG_KEY

    # Do this only after every authenticated field and the owner closure have verified. A
    # public PASS consequently attests the complete serialized artifact, not just the
    # historical capture fields which happened to be known when the successor was added.
    return True, None


def verify_run_passport(
    passport: object,
    *,
    owner_trust_anchors: Mapping[str, str] = PRODUCTION_OWNER_TRUST_ANCHORS,
    custody_trust_anchors: Mapping[str, str] = PRODUCTION_CUSTODY_TRUST_ANCHORS,
) -> tuple[bool, str | None]:
    """Verify one parsed passport against the published envelope contract."""

    return _verify_run_passport(
        passport,
        owner_trust_anchors=owner_trust_anchors,
        custody_trust_anchors=custody_trust_anchors,
    )


def verify_run_passport_json(
    text: str,
    *,
    owner_trust_anchors: Mapping[str, str] = PRODUCTION_OWNER_TRUST_ANCHORS,
    custody_trust_anchors: Mapping[str, str] = PRODUCTION_CUSTODY_TRUST_ANCHORS,
) -> tuple[bool, str | None]:
    """Parse strictly, verify, then require the one canonical wire form.

    A passport is a publishable byte artifact, not merely a signed JSON value, so the
    serialization is checked after every proof link verifies: a whitespace-only mutation
    that leaves the parsed object identical is still a deterministic BLOCK.
    """

    try:
        parsed = parse_passport_json(text)
    except ValueError as refusal:
        return False, str(refusal)
    verified = verify_run_passport(
        parsed,
        owner_trust_anchors=owner_trust_anchors,
        custody_trust_anchors=custody_trust_anchors,
    )
    if verified == (True, None) and text != canonical_json(parsed):
        return False, BLOCK_PUBLIC_PASSPORT_NONCANONICAL_SERIALIZATION
    return verified


def passport_owner_signing_key_id(passport: Mapping[str, Any]) -> str:
    """Return the owner key identity carried by an already-verified passport."""

    authorization = passport.get("authorization")
    if not isinstance(authorization, Mapping):
        raise ValueError("verified passport authorization is not an object")
    signature = authorization.get("owner_signature")
    if not isinstance(signature, Mapping):
        raise ValueError("verified passport owner signature is not an object")
    key_id = signature.get("signing_key_id")
    if not isinstance(key_id, str):
        raise ValueError("verified passport owner signing key id is not a string")
    return key_id


# --- CLI. Exactly one positional argument. No flags, no env vars, no overrides. ----------


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0].startswith("-"):
        sys.stderr.write(
            "usage: verify_run_passport_offline.py <run-passport.json>\n"
            "Verifies one RunPassport/v1 envelope against the pinned production owner and\n"
            "service-custody Ed25519 trust anchors. Takes no other argument.\n"
        )
        return 2

    path = argv[0]
    try:
        # Read the actual artifact bytes.  Text-mode universal-newline translation would
        # otherwise turn a CRLF byte mutation into an apparent canonical LF document before
        # the public successor's exact-wire-form check sees it.
        with open(path, "rb") as handle:
            serialized = handle.read()
    except OSError as exc:
        sys.stderr.write(f"RUN_PASSPORT_VERDICT: BLOCK passport_unreadable ({exc})\n")
        return 1
    try:
        text = serialized.decode("utf-8")
    except UnicodeDecodeError:
        sys.stderr.write(
            f"RUN_PASSPORT_VERDICT: BLOCK {BLOCK_PASSPORT_UNPARSEABLE}\n"
        )
        return 1

    ok, reason_code = verify_run_passport_json(text)
    owner_key_id = "unverified"
    if ok:
        owner_key_id = passport_owner_signing_key_id(parse_passport_json(text))
    print(f"owner_trust_anchor_key_id: {owner_key_id}")
    print(f"custody_trust_anchor_key_id: {PRODUCTION_CUSTODY_KEY_ID}")
    if ok:
        print("RUN_PASSPORT_VERDICT: PASS")
        return 0
    print(f"RUN_PASSPORT_VERDICT: BLOCK {reason_code}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
