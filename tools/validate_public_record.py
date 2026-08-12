#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Validate the Deedseal public claim and evidence record without dependencies."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
LEDGER_PATH = ROOT / "evidence/ledger-v1.json"
RECORDS_ROOT = ROOT / "evidence/records"

LEDGER_VERSION = "deedseal.public-evidence-ledger/v1"
RECORD_VERSION = "deedseal.public-evidence-record/v1"
CLAIM_STATUSES = {
    "public-reproducible",
    "public-attested",
    "internally-verified",
    "experimental",
    "design-target",
    "withdrawn",
}
ASSURANCE_LEVELS = {
    "internal-ci-attestation",
    "public-attestation",
    "public-reproducible",
}
CLAIM_ASSURANCE = {
    "internally-verified": ASSURANCE_LEVELS,
    "public-attested": {"public-attestation", "public-reproducible"},
    "public-reproducible": {"public-reproducible"},
    # A claim that is not yet an engineering result may cite no evidence at all.
    "experimental": set(),
    "design-target": set(),
    "withdrawn": set(),
}
COMPONENTS = {"CORE", "OFFICE", "PUBLIC"}
REDACTION_CODES = {"R-SEC", "R-OPS", "R-PRIV", "R-IP", "R-VULN"}
PUBLICATION_STATUSES = {"review-candidate", "published", "superseded"}

CLAIM_ID_RE = re.compile(r"^CLM-[0-9]{4}$")
EVIDENCE_ID_RE = re.compile(r"^EVD-[A-Z]+-[0-9]{4}$")
SNAPSHOT_RE = re.compile(r"^DS-[0-9]{4}\.[0-9]{2}\.[0-9]+$")
SOURCE_SNAPSHOT_RE = re.compile(
    r"^(CORE|OFFICE|PUBLIC)-[0-9]{4}-[0-9]{2}-[0-9]{2}-[A-Z]$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FULL_COMMIT_RE = re.compile(r"\b[0-9a-f]{40}\b")
GITHUB_REPOSITORY_URL_RE = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[^\s)`'\"]*",
    re.IGNORECASE,
)
PUBLIC_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/deedseal/deedseal(?:[/#?]|$)"
)

# Published run passports carry commit identifiers of the private repository
# the run happened in. They are disclosed deliberately as part of the published
# record, so the commit-shaped rule is scoped out for exactly this directory
# and nowhere else.
PUBLIC_COMMIT_ID_PREFIX = "examples/verified/"

# Assemble credential-shaped prefixes without embedding a live-looking token in
# the validator source. The public scan includes this file and its tests.
_CREDENTIAL_PREFIXES = ("gh" + "p_", "github_" + "pat_", "s" + "k-")
_CREDENTIAL_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(item) for item in _CREDENTIAL_PREFIXES) + r")[A-Za-z0-9_.-]+"
)

DISCLOSURE_PATTERNS = (
    (re.compile(r"(?:^|[\s`'\"])/(?:home|root)/"), "private host path"),
    (re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"), "network address"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key material"),
    (_CREDENTIAL_RE, "credential-shaped token"),
    (re.compile(r"\bgit@github\.com:"), "private Git transport coordinate"),
    (
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        "email address",
    ),
    # The public record is English-only by policy. The range is assembled from
    # code points so this file does not itself contain the characters it bans.
    (
        re.compile(
            "["
            + chr(0x0400) + "-" + chr(0x052F)      # Cyrillic, Cyrillic Supplement
            + chr(0x1C80) + "-" + chr(0x1C8F)      # Cyrillic Extended-C
            + chr(0x2DE0) + "-" + chr(0x2DFF)      # Cyrillic Extended-A
            + chr(0xA640) + "-" + chr(0xA69F)      # Cyrillic Extended-B
            + "]"
        ),
        "non-English (Cyrillic) text",
    ),
)

MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^()\s]+)\)")

# ---------------------------------------------------------------------------
# The proof surface
#
# A claim used to be documented in exactly one place, `docs/engineering-
# properties.md`. A dated proof index under `docs/proof/` is the second, and a
# claim documented there is held to a stricter disclosure rule than the rest of
# the public tree: the sanitized records behind such a claim summarize private
# live work, so the vocabulary of that private work must not survive the
# summary. The rules below are structural, not a review of judgement -- they
# fail closed on shapes, and a human reviewer still reads the prose.
# ---------------------------------------------------------------------------

PROOF_ROOT = ROOT / "docs/proof"

PROOF_BLOCK_RE = re.compile(
    r"^###[ \t]+(CLM-[0-9]{4})\b[^\n]*\n(.*?)(?=^###[ \t]|\Z)",
    re.MULTILINE | re.DOTALL,
)
PROOF_BAND_RE = re.compile(r"^- Band: `([a-z-]+)`[ \t]*$", re.MULTILINE)
PROOF_EVIDENCE_RE = re.compile(
    r"^- Evidence: \[`(EVD-[A-Z]+-[0-9]{4})`\]\(([^()\s]+)\)[ \t]*$", re.MULTILINE
)
PROOF_DIGEST_RE = re.compile(r"^- Record digest: `([0-9a-f]{64})`[ \t]*$", re.MULTILINE)
PROOF_LIMITATION_RE = re.compile(r"^- Limitation: (\S.*)$", re.MULTILINE)

# Symbols that exist only in the private engineering source. A sanitized record
# describes a component by its role; naming the module is a source coordinate.
INTERNAL_SOURCE_MARKERS = (
    "neural_run",
    "retrieve_run",
    "shadow_run",
    "model_access",
    "check_neural_retrieval",
    "live_cell_suite",
    "cell_init",
    "run_cell",
    "bound_run",
    "build_graph",
    "execution_fabric",
    "hardware_signer",
    "appliance_host",
    "graph_memory",
)
INTERNAL_SOURCE_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(item) for item in INTERNAL_SOURCE_MARKERS) + r")\b"
)

# Anything path-shaped that carries source, configuration or unit extensions.
# A repository-relative public path resolves in this tree and is allowed; one
# that does not resolve is a coordinate of somewhere else.
SOURCE_PATH_RE = re.compile(
    r"\b[A-Za-z0-9_][A-Za-z0-9_./-]*\."
    r"(?:py|sh|bash|yml|yaml|json|toml|cfg|ini|service|socket|sock|unit)\b"
)

PROOF_SURFACE_PATTERNS = (
    (INTERNAL_SOURCE_RE, "internal source symbol"),
    (
        re.compile(r"(?:^|[\s`'\"(\[])/(?:Users|var|opt|srv|etc|tmp|usr|mnt|media|proc|sys)/"),
        "machine path",
    ),
    (re.compile(r"\b[A-Za-z]:\\"), "machine path"),
    (re.compile(r"\\\\[A-Za-z0-9_.-]+\\"), "network share path"),
    (
        re.compile(r"\b[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z0-9][A-Za-z0-9.-]*\b"),
        "kernel or build identity",
    ),
    (
        re.compile(r"\b[a-z0-9][a-z0-9-]*\.(?:local|internal|lan|corp|intranet|invalid)\b"),
        "host identity",
    ),
    (re.compile(r"\bkbp\.[a-z0-9.-]+"), "private protocol identifier"),
    (
        re.compile(r"\b(?:kbp|construction)-[a-z0-9-]+\b", re.IGNORECASE),
        "private repository name",
    ),
    (re.compile(r"\bsession_[A-Za-z0-9]{6,}\b"), "worker session identity"),
    (re.compile(r"\bclaude\.ai/code\b", re.IGNORECASE), "worker session URL"),
    (re.compile(r"\brefused_[a-z][a-z_]{2,}\b"), "exact refusal code"),
    (re.compile(r"\bcompleted_model_response\b"), "internal outcome code"),
    (re.compile(r"\b[A-Z][A-Z0-9]*_[A-Z0-9_]{2,}\b"), "internal constant name"),
)

# Words this project does not use as a positive claim. They are allowed only
# where the sentence denies them, which is exactly how an honest limitation
# reads: "not independently audited".
POSITIVE_CLAIM_TERMS = re.compile(
    r"\b(?:secure|secured|securely|certified|audited|production-ready|"
    r"customer-deployed|generally[ \t]+available)\b",
    re.IGNORECASE,
)
NEGATION_RE = re.compile(
    r"\b(?:not|never|no|none|nothing|nor|neither|without|cannot)\b", re.IGNORECASE
)
NEGATION_WINDOW = 48
# A denial only counts inside the same clause. A line break does not end one --
# public prose is wrapped -- but a sentence terminator or a JSON string boundary
# does, so a "not" from the sentence before cannot launder the next sentence.
NEGATION_BOUNDARY = ".!?;\"'"

README_CLAIM_ROW_RE = re.compile(
    r"^\|\s*`(CLM-[0-9]{4})`\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*`([a-z-]+)`\s*\|\s*$",
    re.MULTILINE,
)

SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*(\S+)")
ALLOWED_SPDX = {"CC-BY-4.0", "Apache-2.0"}

PROHIBITED_CLAIM_TERMS = re.compile(
    r"\b(?:unique|first|secure|tamper-proof|unhackable|certified|compliant|"
    r"production-ready|client-ready|commercially-ready|model-neutral|provider-neutral)\b|"
    r"formally verified",
    re.IGNORECASE,
)

LEDGER_FIELDS = {"schema_version", "snapshot", "claims", "evidence"}
SNAPSHOT_FIELDS = {"id", "prepared_on", "publication_status"}
CLAIM_FIELDS = {
    "id",
    "statement",
    "component",
    "status",
    "observed_on",
    "scope",
    "evidence_ids",
    "limitations",
}
EVIDENCE_INDEX_FIELDS = {
    "id",
    "component",
    "kind",
    "assurance",
    "observed_on",
    "source_snapshot",
    "artifact",
    "redactions",
    "limitations",
}
RECORD_FIELDS = {
    "schema_version",
    "id",
    "component",
    "source_snapshot",
    "observed_on",
    "kind",
    "assurance",
    "verification",
    "disclosure",
    "limitations",
}

SUPPORTED_SCHEMA_KEYS = {
    "$schema",
    "$id",
    "$ref",
    "$defs",
    "title",
    "type",
    "additionalProperties",
    "required",
    "properties",
    "const",
    "enum",
    "pattern",
    "format",
    "minLength",
    "maxLength",
    "minItems",
    "uniqueItems",
    "items",
}


class ValidationError(RuntimeError):
    pass


if sys.version_info < (3, 9):  # pragma: no cover - guard for old interpreters
    raise SystemExit(
        "the publication gate requires Python 3.9 or newer; "
        f"this interpreter is {sys.version.split()[0]}"
    )


def fail(message: str) -> None:
    raise ValidationError(message)


def exact_fields(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        observed = sorted(value) if isinstance(value, dict) else type(value).__name__
        fail(f"{label}: expected fields {sorted(expected)}, got {observed}")
    return value


def nonempty_string(value: object, label: str, *, max_length: int = 2000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        fail(f"{label}: expected a non-empty string up to {max_length} characters")
    return value


def string_list(value: object, label: str, *, minimum: int = 1) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum:
        fail(f"{label}: expected at least {minimum} item(s)")
    result = [
        nonempty_string(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        fail(f"{label}: duplicate items are not allowed")
    return result


def iso_date(value: object, label: str) -> str:
    text = nonempty_string(value, label, max_length=10)
    try:
        date.fromisoformat(text)
    except ValueError:
        fail(f"{label}: invalid ISO date")
    return text


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def guarded_bytes(path: Path, *, max_bytes: int = 1024 * 1024) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        fail(f"{path.relative_to(ROOT)}: unavailable: {exc}")
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1:
        fail(f"{path.relative_to(ROOT)}: expected one regular, non-symlinked file")
    if info.st_size > max_bytes:
        fail(f"{path.relative_to(ROOT)}: exceeds {max_bytes} bytes")
    try:
        return path.read_bytes()
    except OSError as exc:
        fail(f"{path.relative_to(ROOT)}: unreadable: {exc}")


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = guarded_bytes(path)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        fail(f"{path.relative_to(ROOT)}: invalid UTF-8 JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)}: root must be an object")
    return value, raw


def _schema_children(schema: dict[str, Any], label: str) -> list[tuple[dict[str, Any], str]]:
    children: list[tuple[dict[str, Any], str]] = []
    for container_name in ("properties", "$defs"):
        container = schema.get(container_name, {})
        if not isinstance(container, dict):
            fail(f"{label}.{container_name}: expected an object")
        for name, child in container.items():
            if not isinstance(child, dict):
                fail(f"{label}.{container_name}.{name}: expected an object")
            children.append((child, f"{label}.{container_name}.{name}"))
    if "items" in schema:
        child = schema["items"]
        if not isinstance(child, dict):
            fail(f"{label}.items: expected an object")
        children.append((child, f"{label}.items"))
    return children


def validate_schema_definition(schema: dict[str, Any], label: str) -> None:
    unknown = set(schema) - SUPPORTED_SCHEMA_KEYS
    if unknown:
        fail(f"{label}: unsupported schema keywords {sorted(unknown)}")
    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            fail(f"{label}.$ref: only local references are supported")
    if "type" in schema and schema["type"] not in {"object", "array", "string"}:
        fail(f"{label}.type: unsupported type")
    if "additionalProperties" in schema and schema["additionalProperties"] is not False:
        fail(f"{label}.additionalProperties: only false is supported")
    if "required" in schema and (
        not isinstance(schema["required"], list)
        or not all(isinstance(item, str) for item in schema["required"])
    ):
        fail(f"{label}.required: expected a string array")
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except (TypeError, re.error):
            fail(f"{label}.pattern: invalid regular expression")
    if schema.get("format") not in {None, "date"}:
        fail(f"{label}.format: unsupported format")
    for numeric_key in ("minLength", "maxLength", "minItems"):
        if numeric_key in schema and (
            type(schema[numeric_key]) is not int or schema[numeric_key] < 0
        ):
            fail(f"{label}.{numeric_key}: expected a non-negative integer")
    if "uniqueItems" in schema and type(schema["uniqueItems"]) is not bool:
        fail(f"{label}.uniqueItems: expected a boolean")
    for child, child_label in _schema_children(schema, label):
        validate_schema_definition(child, child_label)


def resolve_schema_ref(root_schema: dict[str, Any], ref: str, label: str) -> dict[str, Any]:
    value: Any = root_schema
    for encoded in ref.removeprefix("#/").split("/"):
        key = encoded.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or key not in value:
            fail(f"{label}: unresolved schema reference {ref}")
        value = value[key]
    if not isinstance(value, dict):
        fail(f"{label}: schema reference {ref} does not resolve to an object")
    return value


def validate_against_schema(
    value: object,
    schema: dict[str, Any],
    root_schema: dict[str, Any],
    label: str,
) -> None:
    if "$ref" in schema:
        validate_against_schema(
            value,
            resolve_schema_ref(root_schema, schema["$ref"], label),
            root_schema,
            label,
        )
        return
    if "const" in schema and value != schema["const"]:
        fail(f"{label}: does not match schema const")
    if "enum" in schema and value not in schema["enum"]:
        fail(f"{label}: value is outside schema enum")

    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            fail(f"{label}: schema expected an object")
        required = set(schema.get("required", []))
        missing = required - set(value)
        if missing:
            fail(f"{label}: schema-required fields missing {sorted(missing)}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = set(value) - set(properties)
            if unknown:
                fail(f"{label}: schema-unknown fields {sorted(unknown)}")
        for key, child_value in value.items():
            if key in properties:
                validate_against_schema(
                    child_value,
                    properties[key],
                    root_schema,
                    f"{label}.{key}",
                )
    elif expected_type == "array":
        if not isinstance(value, list):
            fail(f"{label}: schema expected an array")
        if len(value) < schema.get("minItems", 0):
            fail(f"{label}: fewer items than schema minimum")
        if schema.get("uniqueItems") is True:
            canonical = [
                json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value
            ]
            if len(canonical) != len(set(canonical)):
                fail(f"{label}: schema requires unique items")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                validate_against_schema(
                    item, item_schema, root_schema, f"{label}[{index}]"
                )
    elif expected_type == "string":
        if not isinstance(value, str):
            fail(f"{label}: schema expected a string")
        if len(value) < schema.get("minLength", 0):
            fail(f"{label}: shorter than schema minimum")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            fail(f"{label}: longer than schema maximum")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            fail(f"{label}: does not match schema pattern")
        if schema.get("format") == "date":
            iso_date(value, label)


def validate_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    paths = (
        ROOT / "schemas/evidence-ledger-v1.schema.json",
        ROOT / "schemas/evidence-record-v1.schema.json",
    )
    schemas: list[dict[str, Any]] = []
    for path in paths:
        schema, _raw = load_json(path)
        relative = path.relative_to(ROOT)
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            fail(f"{relative}: must declare JSON Schema 2020-12")
        if schema.get("additionalProperties") is not False:
            fail(f"{relative}: root must reject unknown fields")
        validate_schema_definition(schema, str(relative))
        schemas.append(schema)
    return schemas[0], schemas[1]


def validate_claim(claim_value: object, snapshot_id: str) -> dict[str, Any]:
    claim = exact_fields(claim_value, CLAIM_FIELDS, "claim")
    claim_id = nonempty_string(claim["id"], "claim.id", max_length=8)
    if CLAIM_ID_RE.fullmatch(claim_id) is None:
        fail(f"{claim_id}: invalid claim ID")
    statement = nonempty_string(claim["statement"], f"{claim_id}.statement")
    if PROHIBITED_CLAIM_TERMS.search(statement):
        fail(f"{claim_id}: statement contains a prohibited public claim term")
    if claim["component"] not in COMPONENTS:
        fail(f"{claim_id}: invalid component")
    if claim["status"] not in CLAIM_STATUSES:
        fail(f"{claim_id}: invalid status")
    iso_date(claim["observed_on"], f"{claim_id}.observed_on")
    if claim["scope"] != snapshot_id:
        fail(f"{claim_id}: scope does not match snapshot {snapshot_id}")
    evidence_ids = string_list(claim["evidence_ids"], f"{claim_id}.evidence_ids")
    for evidence_id in evidence_ids:
        if EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
            fail(f"{claim_id}: invalid evidence ID {evidence_id}")
    string_list(claim["limitations"], f"{claim_id}.limitations")
    return claim


def validate_evidence_index(value: object) -> dict[str, Any]:
    evidence = exact_fields(value, EVIDENCE_INDEX_FIELDS, "evidence index")
    evidence_id = nonempty_string(evidence["id"], "evidence.id", max_length=32)
    if EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
        fail(f"{evidence_id}: invalid evidence ID")
    if evidence["component"] not in COMPONENTS:
        fail(f"{evidence_id}: invalid component")
    if not evidence_id.startswith(f"EVD-{evidence['component']}-"):
        fail(f"{evidence_id}: ID prefix does not match component")
    nonempty_string(evidence["kind"], f"{evidence_id}.kind")
    if evidence["assurance"] not in ASSURANCE_LEVELS:
        fail(f"{evidence_id}: invalid assurance")
    iso_date(evidence["observed_on"], f"{evidence_id}.observed_on")
    source_snapshot = nonempty_string(
        evidence["source_snapshot"], f"{evidence_id}.source_snapshot"
    )
    if SOURCE_SNAPSHOT_RE.fullmatch(source_snapshot) is None:
        fail(f"{evidence_id}: invalid opaque source snapshot")
    if not source_snapshot.startswith(f"{evidence['component']}-"):
        fail(f"{evidence_id}: source snapshot prefix does not match component")

    artifact = exact_fields(
        evidence["artifact"], {"path", "sha256"}, f"{evidence_id}.artifact"
    )
    expected_path = f"evidence/records/{evidence_id}.json"
    if artifact["path"] != expected_path:
        fail(f"{evidence_id}: artifact path must be {expected_path}")
    if not isinstance(artifact["sha256"], str) or SHA256_RE.fullmatch(
        artifact["sha256"]
    ) is None:
        fail(f"{evidence_id}: invalid artifact SHA-256")

    redactions = string_list(
        evidence["redactions"], f"{evidence_id}.redactions", minimum=0
    )
    unknown_redactions = set(redactions) - REDACTION_CODES
    if unknown_redactions:
        fail(f"{evidence_id}: unknown redaction codes {sorted(unknown_redactions)}")
    string_list(evidence["limitations"], f"{evidence_id}.limitations")
    return evidence


def validate_record(
    index: dict[str, Any], record_schema: dict[str, Any]
) -> dict[str, Any]:
    evidence_id = index["id"]
    path = ROOT / index["artifact"]["path"]
    record, raw = load_json(path)
    validate_against_schema(record, record_schema, record_schema, evidence_id)
    record = exact_fields(record, RECORD_FIELDS, evidence_id)
    if record["schema_version"] != RECORD_VERSION:
        fail(f"{evidence_id}: wrong record schema version")

    for field in (
        "id",
        "component",
        "source_snapshot",
        "observed_on",
        "kind",
        "assurance",
    ):
        if record[field] != index[field]:
            fail(f"{evidence_id}: record/index mismatch for {field}")

    verification = exact_fields(
        record["verification"],
        {"verdict", "observations"},
        f"{evidence_id}.verification",
    )
    if verification["verdict"] not in {"PASS", "BLOCK", "WITHDRAWN"}:
        fail(f"{evidence_id}: invalid verdict")
    observations = verification["observations"]
    if not isinstance(observations, list) or not observations:
        fail(f"{evidence_id}: expected at least one observation")
    for position, observation_value in enumerate(observations):
        observation = exact_fields(
            observation_value,
            {"check", "result"},
            f"{evidence_id}.observations[{position}]",
        )
        nonempty_string(
            observation["check"], f"{evidence_id}.observations[{position}].check"
        )
        nonempty_string(
            observation["result"], f"{evidence_id}.observations[{position}].result"
        )

    disclosure = exact_fields(
        record["disclosure"],
        {"source_visibility", "redactions", "omitted"},
        f"{evidence_id}.disclosure",
    )
    if disclosure["source_visibility"] not in {"private", "public"}:
        fail(f"{evidence_id}: invalid source visibility")
    redactions = string_list(
        disclosure["redactions"], f"{evidence_id}.disclosure.redactions", minimum=0
    )
    if set(redactions) != set(index["redactions"]):
        fail(f"{evidence_id}: record/index redactions differ")
    if index["assurance"] == "public-reproducible" and disclosure[
        "source_visibility"
    ] != "public":
        fail(f"{evidence_id}: reproducible evidence must have public source")
    string_list(disclosure["omitted"], f"{evidence_id}.disclosure.omitted")
    string_list(record["limitations"], f"{evidence_id}.limitations")

    observed_digest = hashlib.sha256(raw).hexdigest()
    if observed_digest != index["artifact"]["sha256"]:
        fail(
            f"{evidence_id}: artifact digest mismatch; expected "
            f"{index['artifact']['sha256']}, observed {observed_digest}"
        )
    return record


def validate_evidence_graph(
    claims: list[dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
    records_by_id: dict[str, dict[str, Any]],
) -> None:
    for claim in claims:
        claim_id = claim["id"]
        for evidence_id in claim["evidence_ids"]:
            if evidence_id not in evidence_by_id:
                fail(f"{claim_id}: unknown evidence ID {evidence_id}")
            evidence = evidence_by_id[evidence_id]
            record = records_by_id[evidence_id]
            if evidence["component"] != claim["component"]:
                fail(f"{claim_id}: component differs from {evidence_id}")
            allowed_assurance = CLAIM_ASSURANCE.get(claim["status"])
            if allowed_assurance is not None and evidence["assurance"] not in allowed_assurance:
                fail(
                    f"{claim_id}: status {claim['status']} is incompatible with "
                    f"{evidence_id} assurance {evidence['assurance']}"
                )
            if claim["status"] in CLAIM_ASSURANCE and record["verification"][
                "verdict"
            ] != "PASS":
                fail(f"{claim_id}: active claim references non-PASS {evidence_id}")
            if claim["status"] == "withdrawn" and record["verification"][
                "verdict"
            ] != "WITHDRAWN":
                fail(f"{claim_id}: withdrawn claim lacks withdrawn evidence")


def validate_snapshot_dates(
    prepared_on: str,
    claims: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> None:
    prepared = date.fromisoformat(prepared_on)
    for collection in (claims, evidence):
        for item in collection:
            if date.fromisoformat(item["observed_on"]) > prepared:
                fail(f"{item['id']}: observed_on is after snapshot.prepared_on")


def all_public_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if any(part in {".git", "__pycache__"} for part in path.parts):
            continue
        if path.is_symlink():
            fail(f"{path.relative_to(ROOT)}: public tree must not contain symlinks")
        if path.is_file():
            files.append(path)
    return sorted(files)


def disclosure_violation(path: Path, text: str) -> str | None:
    for match in GITHUB_REPOSITORY_URL_RE.finditer(text):
        if PUBLIC_GITHUB_URL_RE.match(match.group(0)) is None:
            return "non-public GitHub repository URL"
    for pattern, label in DISCLOSURE_PATTERNS:
        if pattern.search(text):
            return label
    for match in FULL_COMMIT_RE.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.end())
        if line_end < 0:
            line_end = len(text)
        line = text[line_start:line_end]
        if (
            path.as_posix() == ".github/workflows/validate-public-record.yml"
            and any(
                f"{action}@{match.group(0)}" in line
                for action in ("actions/checkout", "actions/setup-go")
            )
        ):
            continue
        if path.as_posix().startswith(PUBLIC_COMMIT_ID_PREFIX):
            continue
        return "private commit identifier"
    return None


def internal_link_violations(path: Path, text: str) -> list[str]:
    """Return violations for relative Markdown links that leave the repository
    or point at files that do not exist. Absolute URLs are out of scope."""
    violations: list[str] = []
    if path.suffix.lower() != ".md":
        return violations
    for match in MARKDOWN_LINK_RE.finditer(text):
        raw_target = match.group(1)
        if raw_target.startswith(("http://", "https://", "mailto:")):
            continue
        target = raw_target.split("#", 1)[0]
        if not target:
            continue
        resolved = (ROOT / path).parent / target
        try:
            resolved = resolved.resolve()
            resolved.relative_to(ROOT.resolve())
        except (OSError, ValueError):
            violations.append(
                f"{path.as_posix()}: internal link escapes the repository: {raw_target}"
            )
            continue
        if not resolved.exists():
            violations.append(
                f"{path.as_posix()}: broken internal link: {raw_target}"
            )
    return violations


def proof_index_paths() -> list[Path]:
    """Every dated proof index, or an empty list when none is published yet."""
    if not PROOF_ROOT.is_dir():
        return []
    return sorted(path for path in PROOF_ROOT.glob("*.md") if path.is_file())


def parse_proof_blocks(text: str) -> dict[str, dict[str, Any]]:
    """Parse one proof index into {claim_id: fields}.

    The shape is fixed rather than free prose, because every field below is
    checked against the ledger. A block the reader can see but the gate cannot
    parse would be a claim nobody is holding to the record.
    """
    blocks: dict[str, dict[str, Any]] = {}
    for match in PROOF_BLOCK_RE.finditer(text):
        claim_id, body = match.group(1), match.group(2)
        statement_lines: list[str] = []
        for line in body.splitlines():
            if line.startswith("- "):
                break
            if line.strip():
                statement_lines.append(line.strip())
        band = PROOF_BAND_RE.search(body)
        evidence = PROOF_EVIDENCE_RE.search(body)
        digest = PROOF_DIGEST_RE.search(body)
        limitation = PROOF_LIMITATION_RE.search(body)
        blocks[claim_id] = {
            "statement": " ".join(statement_lines),
            "band": band.group(1) if band else None,
            "evidence_id": evidence.group(1) if evidence else None,
            "evidence_link": evidence.group(2) if evidence else None,
            "digest": digest.group(1) if digest else None,
            "limitation": limitation.group(1).strip() if limitation else None,
            "order": len(blocks),
        }
    return blocks


def proof_block_failures(
    label: str,
    block: dict[str, Any],
    claims_by_id: dict[str, dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
    base: Path,
) -> list[str]:
    """Every way one proof-index block can disagree with the ledger.

    A displayed digest is the one thing on that page a reader could carry away
    and compare, so it is not allowed to be a number someone typed: it must
    equal the digest the ledger indexes for that record. This returns failures
    rather than raising, so the negative tests can drive it directly.
    """
    claim_id = label.rsplit(":", 1)[-1]
    if claim_id not in claims_by_id:
        return [f"{label}: documents a claim the ledger does not carry"]
    claim = claims_by_id[claim_id]

    failures = [
        f"{label}: missing the {field} line"
        for field in ("band", "evidence_id", "digest", "limitation")
        if not block.get(field)
    ]
    if not block.get("statement"):
        failures.append(f"{label}: missing the claim statement")
    if failures:
        return failures

    if block["statement"] != claim["statement"]:
        failures.append(f"{label}: statement differs from the ledger statement")
    if block["band"] != claim["status"]:
        failures.append(
            f"{label}: band {block['band']} differs from ledger status {claim['status']}"
        )
    if block["evidence_id"] not in claim["evidence_ids"]:
        return failures + [
            f"{label}: {block['evidence_id']} is not evidence for this claim"
        ]

    evidence = evidence_by_id[block["evidence_id"]]
    expected_path = evidence["artifact"]["path"]
    if (base / block["evidence_link"]).resolve() != (ROOT / expected_path).resolve():
        failures.append(f"{label}: evidence link does not point at {expected_path}")
    if block["digest"] != evidence["artifact"]["sha256"]:
        failures.append(
            f"{label}: displayed digest differs from the ledger digest for "
            f"{block['evidence_id']}"
        )
    return failures


def validate_proof_indexes(
    claims: list[dict[str, Any]], evidence_by_id: dict[str, dict[str, Any]]
) -> dict[str, str]:
    """Check every proof-index block against the ledger. Returns {claim_id: doc}."""
    claims_by_id = {claim["id"]: claim for claim in claims}
    documented: dict[str, str] = {}
    for path in proof_index_paths():
        relative = path.relative_to(ROOT).as_posix()
        blocks = parse_proof_blocks(guarded_bytes(path).decode("utf-8"))
        if not blocks:
            fail(f"{relative}: a proof index must document at least one claim")
        for claim_id, block in sorted(blocks.items(), key=lambda item: item[1]["order"]):
            label = f"{relative}:{claim_id}"
            if claim_id in documented:
                fail(f"{label}: documented twice, in {documented[claim_id]} as well")
            failures = proof_block_failures(
                label, block, claims_by_id, evidence_by_id, path.parent
            )
            if failures:
                fail(failures[0])
            documented[claim_id] = relative
    return documented


def unresolved_source_paths(text: str, base: Path) -> list[str]:
    """Path-shaped tokens that name no file in this repository.

    A repository-relative public path is allowed and resolves here. One that
    does not resolve is a coordinate of somewhere else, which is exactly what
    a sanitized record must not carry.
    """
    unresolved: list[str] = []
    for match in SOURCE_PATH_RE.finditer(text):
        token = match.group(0)
        trimmed = token
        while trimmed.startswith(("./", "../")):
            trimmed = trimmed.split("/", 1)[1]
        if (ROOT / trimmed).exists() or (base / token).exists():
            continue
        unresolved.append(token)
    return unresolved


def unnegated_positive_claims(text: str) -> list[str]:
    """Banned words used as a positive claim, rather than denied."""
    offences: list[str] = []
    for match in POSITIVE_CLAIM_TERMS.finditer(text):
        window = text[max(0, match.start() - NEGATION_WINDOW) : match.start()]
        boundary = max(window.rfind(character) for character in NEGATION_BOUNDARY)
        if boundary >= 0:
            window = window[boundary + 1 :]
        if NEGATION_RE.search(window) is None:
            offences.append(match.group(0))
    return offences


def proof_surface_violation(text: str, base: Path) -> str | None:
    """The stricter scan applied to proof-documented public bytes.

    It is a superset of the tree-wide scan on purpose. A fragment is checked as
    a fragment rather than as a file, so nothing here may lean on the fact that
    the whole file gets scanned too -- the point is that these bytes fail
    closed wherever they are assembled from.
    """
    for match in GITHUB_REPOSITORY_URL_RE.finditer(text):
        if PUBLIC_GITHUB_URL_RE.match(match.group(0)) is None:
            return "non-public GitHub repository URL"
    commit = FULL_COMMIT_RE.search(text)
    if commit is not None:
        return f"private commit identifier ({commit.group(0)!r})"
    for pattern, label in (*DISCLOSURE_PATTERNS, *PROOF_SURFACE_PATTERNS):
        found = pattern.search(text)
        if found is not None:
            return f"{label} ({found.group(0).strip()!r})"
    unresolved = unresolved_source_paths(text, base)
    if unresolved:
        return f"source path that does not resolve here ({unresolved[0]!r})"
    positive = unnegated_positive_claims(text)
    if positive:
        return f"unnegated positive-claim term ({positive[0]!r})"
    return None


def proof_surface_fragments(
    documented: dict[str, str],
    claims: list[dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
) -> list[tuple[str, str, Path]]:
    """Every public byte a proof-documented claim is responsible for.

    Derived from the ledger rather than listed by hand, so a claim added to a
    proof index tomorrow is scanned tomorrow without editing this function.
    """
    fragments: list[tuple[str, str, Path]] = []
    for path in proof_index_paths():
        relative = path.relative_to(ROOT).as_posix()
        fragments.append((relative, guarded_bytes(path).decode("utf-8"), path.parent))
    if not documented:
        return fragments

    evidence_ids: set[str] = set()
    for claim in claims:
        if claim["id"] not in documented:
            continue
        fragments.append(
            (
                f"evidence/ledger-v1.json:{claim['id']}",
                json.dumps(claim, ensure_ascii=False),
                ROOT,
            )
        )
        evidence_ids.update(claim["evidence_ids"])

    for evidence_id in sorted(evidence_ids):
        evidence = evidence_by_id[evidence_id]
        fragments.append(
            (
                f"evidence/ledger-v1.json:{evidence_id}",
                json.dumps(evidence, ensure_ascii=False),
                ROOT,
            )
        )
        record_path = ROOT / evidence["artifact"]["path"]
        fragments.append(
            (
                evidence["artifact"]["path"],
                guarded_bytes(record_path).decode("utf-8"),
                record_path.parent,
            )
        )

    readme = guarded_bytes(ROOT / "README.md").decode("utf-8")
    for match in README_CLAIM_ROW_RE.finditer(readme):
        if match.group(1) in documented:
            fragments.append((f"README.md:{match.group(1)}", match.group(0), ROOT))

    status = guarded_bytes(ROOT / "docs/status.md").decode("utf-8")
    named = set(documented) | evidence_ids
    for number, line in enumerate(status.splitlines(), start=1):
        if any(identifier in line for identifier in named):
            fragments.append((f"docs/status.md:{number}", line, ROOT / "docs"))
    return fragments


def validate_proof_surface(
    documented: dict[str, str],
    claims: list[dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
) -> None:
    for label, text, base in proof_surface_fragments(documented, claims, evidence_by_id):
        violation = proof_surface_violation(text, base)
        if violation is not None:
            fail(f"{label}: contains forbidden {violation}")


REQUIRED_PUBLIC_FILES = {
    "README.md",
    "docs/proof/2026-08-12-neural-memory.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "NOTICE.md",
    "LICENSE",
    ".gitattributes",
    "docs/architecture.md",
    "docs/trust-model.md",
    "docs/passport.md",
    "docs/passport-spec-v1.md",
    "docs/method.md",
    "docs/faq.md",
    "docs/status.md",
    "docs/system-boundary.md",
    "docs/engineering-properties.md",
    "docs/publication-policy.md",
    "docs/decisions/README.md",
    "examples/passport.example.json",
    "docs/verify.md",
    "examples/verified/run-passport.json",
    "examples/verified/run-passport.tampered.json",
    "examples/verified/target-before",
    "examples/verified/target-after",
    "examples/verified/conformance/manifest.json",
    "examples/verified/conformance/README.md",
    "tools/verify_run_passport.py",
    "verifiers/README.md",
    "verifiers/go/go.mod",
    "verifiers/go/main.go",
    "verifiers/go/run_conformance.sh",
    "tools/check_conformance.py",
    "tools/check_demonstration.py",
    "tools/check_round_trip_v2_target.py",
    "tools/boundary_probe.py",
    "tools/survey_refusals.py",
    "demo/README.md",
    "demo/refusals/README.md",
    "demo/refusals/test_refusals.py",
    "demo/tests/test_demo_contract.py",
    "app/product/demo/test_demonstration_contract.py",
    "assets/README.md",
    "evidence/README.md",
    "evidence/ledger-v1.json",
    "schemas/evidence-ledger-v1.schema.json",
    "schemas/evidence-record-v1.schema.json",
    "tools/validate_public_record.py",
    "tools/test_public_record.py",
    ".github/workflows/validate-public-record.yml",
    ".github/pull_request_template.md",
    ".github/dependabot.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
}


def validate_public_text() -> None:
    public_files = all_public_files()
    observed = {path.relative_to(ROOT).as_posix() for path in public_files}
    missing = REQUIRED_PUBLIC_FILES - observed
    if missing:
        fail(f"required public files missing: {sorted(missing)}")

    for path in public_files:
        relative = path.relative_to(ROOT)
        raw = guarded_bytes(path)
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            fail(f"{relative}: public files must be UTF-8 text")
        violation = disclosure_violation(relative, text)
        if violation is not None:
            fail(f"{relative}: contains forbidden {violation}")
        for message in internal_link_violations(relative, text):
            fail(message)
        if relative.suffix == ".py":
            declared = SPDX_RE.search(text)
            if declared is None:
                fail(f"{relative}: executable files must declare an SPDX identifier")
            if declared.group(1) not in ALLOWED_SPDX:
                fail(
                    f"{relative}: SPDX identifier {declared.group(1)} is not one of "
                    f"{sorted(ALLOWED_SPDX)}"
                )


def readme_claim_rows(readme: str) -> dict[str, tuple[str, list[str], str]]:
    """Parse the README claim table into {claim_id: (statement, evidence_ids, status)}."""
    rows: dict[str, tuple[str, list[str], str]] = {}
    for match in README_CLAIM_ROW_RE.finditer(readme):
        claim_id, statement, evidence_cell, status = match.groups()
        evidence = [
            item.strip().strip("`")
            for item in evidence_cell.split(",")
            if item.strip()
        ]
        rows[claim_id] = (statement.strip(), evidence, status)
    return rows


def validate_document_links(
    claims: list[dict[str, Any]],
    evidence_ids: set[str],
    documented: dict[str, str] | None = None,
) -> None:
    """The README claim table is a restatement of the ledger, so it must match it
    exactly. A drifted statement or a flipped status is a validation failure.

    Every claim must also be written out for a human somewhere: in the engineering
    properties, or in a dated proof index. Two surfaces are allowed; none is not.
    """
    readme = guarded_bytes(ROOT / "README.md").decode("utf-8")
    properties = guarded_bytes(ROOT / "docs/engineering-properties.md").decode("utf-8")
    rows = readme_claim_rows(readme)
    documented = documented or {}

    for claim in claims:
        claim_id = claim["id"]
        if claim_id not in properties and claim_id not in documented:
            fail(f"{claim_id}: missing from engineering properties and every proof index")
        if claim_id not in rows:
            fail(f"{claim_id}: missing from the README claim table")
        statement, evidence, status = rows[claim_id]
        if statement != claim["statement"]:
            fail(f"{claim_id}: README statement differs from the ledger statement")
        if status != claim["status"]:
            fail(
                f"{claim_id}: README status {status} differs from ledger status "
                f"{claim['status']}"
            )
        if sorted(evidence) != sorted(claim["evidence_ids"]):
            fail(f"{claim_id}: README evidence identifiers differ from the ledger")

    unknown = set(rows) - {claim["id"] for claim in claims}
    if unknown:
        fail(f"README claim table lists unknown claims: {sorted(unknown)}")

    for evidence_id in sorted(evidence_ids):
        if evidence_id not in readme:
            fail(f"{evidence_id}: missing from README claim table")


def validate_repository(*, require_published: bool = False) -> tuple[str, int, int]:
    ledger_schema, record_schema = validate_schemas()
    ledger, _raw = load_json(LEDGER_PATH)
    validate_against_schema(ledger, ledger_schema, ledger_schema, "ledger")
    ledger = exact_fields(ledger, LEDGER_FIELDS, "ledger")
    if ledger["schema_version"] != LEDGER_VERSION:
        fail("ledger: wrong schema version")

    snapshot = exact_fields(ledger["snapshot"], SNAPSHOT_FIELDS, "snapshot")
    snapshot_id = nonempty_string(snapshot["id"], "snapshot.id")
    if SNAPSHOT_RE.fullmatch(snapshot_id) is None:
        fail("snapshot.id: invalid public snapshot ID")
    prepared_on = iso_date(snapshot["prepared_on"], "snapshot.prepared_on")
    if snapshot["publication_status"] not in PUBLICATION_STATUSES:
        fail("snapshot.publication_status: invalid status")
    if require_published and snapshot["publication_status"] != "published":
        fail("snapshot must be published for this validation mode")

    claims_value = ledger["claims"]
    evidence_value = ledger["evidence"]
    if not isinstance(claims_value, list) or not claims_value:
        fail("ledger.claims: expected a non-empty array")
    if not isinstance(evidence_value, list) or not evidence_value:
        fail("ledger.evidence: expected a non-empty array")

    claims = [validate_claim(value, snapshot_id) for value in claims_value]
    evidence = [validate_evidence_index(value) for value in evidence_value]
    validate_snapshot_dates(prepared_on, claims, evidence)
    claim_ids = [claim["id"] for claim in claims]
    evidence_ids = [item["id"] for item in evidence]
    if len(claim_ids) != len(set(claim_ids)):
        fail("ledger.claims: duplicate IDs")
    if len(evidence_ids) != len(set(evidence_ids)):
        fail("ledger.evidence: duplicate IDs")

    tracked_records = {
        path.name for path in RECORDS_ROOT.glob("*.json") if path.is_file()
    }
    indexed_records = {f"{item['id']}.json" for item in evidence}
    if tracked_records != indexed_records:
        fail(
            "record/index mismatch: "
            f"unindexed={sorted(tracked_records - indexed_records)} "
            f"missing={sorted(indexed_records - tracked_records)}"
        )

    evidence_by_id = {item["id"]: item for item in evidence}
    records_by_id = {
        item["id"]: validate_record(item, record_schema) for item in evidence
    }
    validate_evidence_graph(claims, evidence_by_id, records_by_id)
    documented = validate_proof_indexes(claims, evidence_by_id)
    validate_document_links(claims, set(evidence_ids), documented)
    validate_proof_surface(documented, claims, evidence_by_id)
    validate_public_text()
    return snapshot_id, len(claims), len(evidence)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-published",
        action="store_true",
        help="reject a review-candidate or superseded snapshot",
    )
    args = parser.parse_args(argv)
    try:
        snapshot_id, claim_count, evidence_count = validate_repository(
            require_published=args.require_published
        )
    except ValidationError as exc:
        print(f"PUBLIC_RECORD_VALIDATION: FAIL: {exc}", file=sys.stderr)
        return 1

    print(
        "PUBLIC_RECORD_VALIDATION: PASS "
        f"snapshot={snapshot_id} claims={claim_count} evidence={evidence_count}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
