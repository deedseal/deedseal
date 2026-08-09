#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Validate the Deedseal public claim and evidence record without dependencies."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
LEDGER_PATH = ROOT / "evidence/ledger-v1.json"
RECORDS_ROOT = ROOT / "evidence/records"
LANDING_PATH = ROOT / "index.html"
LANDING_CLAIMS_MAP_PATH = ROOT / "docs/landing-claims-map-v0.1.md"
STATUS_PATH = ROOT / "docs/status.md"
VERIFY_PATH = ROOT / "docs/verify.md"
CHECK_RUNS_PATH = ROOT / "tools/check_runs.py"

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

README_CLAIM_ROW_RE = re.compile(
    r"^\|\s*`(CLM-[0-9]{4})`\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*`([a-z-]+)`\s*\|\s*$",
    re.MULTILINE,
)

LANDING_MAP_OPEN = "<!-- landing-claims-map:start -->"
LANDING_MAP_CLOSE = "<!-- /landing-claims-map:end -->"
LANDING_MAP_HEADER = (
    "Key",
    "Kind",
    "CLM IDs",
    "Status",
    "Evidence or status source",
    "Exact page sentence",
)
LANDING_KEY_RE = re.compile(r"^LND-[A-Z0-9-]+$")
LANDING_MAP_KINDS = {"claim", "design-target", "status", "boundary"}
LANDING_STATUS_LABELS = {
    "engineering-reported",
    "active-build",
    "active-development",
    "record-compatibility",
    "required-boundary",
}
NO_LANDING_CLAIM = "—"
HONEST_BOUNDARY_KEY = "LND-INDEPENDENT-REVIEW"
GRAPH_MEMORY_KEY = "LND-GRAPH-MEMORY"
REQUIRED_LANDING_KEYS = {
    "LND-TWO-BOXES",
    "LND-GITHUB-SPINE",
    "LND-GITHUB-OWNER",
    "LND-LINUX-CELLS",
    "LND-LINUX-DIRECTION",
    "LND-LINUX-BOUNDARY",
    "LND-PASSPORT-RECORD",
    "LND-PASSPORT-PROOF",
    "LND-ENVELOPE-COMMITMENT",
    "LND-COCKPIT",
    GRAPH_MEMORY_KEY,
    "LND-HYBRID-MODEL",
    "LND-HUMAN-CONTROL",
    "LND-VERIFY-YOURSELF",
    "LND-REFUSAL-COVERAGE",
    "LND-VERIFY-BOUNDARY",
    HONEST_BOUNDARY_KEY,
    "LND-COMMERCIAL-STATUS",
}
HTML_VOID_ELEMENTS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}
LANDING_COPY_SCOPE_ATTRIBUTE = "data-landing-copy-scope"
LANDING_SUPPORT_ATTRIBUTE = "data-landing-support"
LANDING_PRODUCT_TEXT_TAGS = {"h1", "h2", "h3", "p"}
LANDING_SUPPORT_COPY = {
    "hero-kicker": "Product direction / public evidence",
    "hero-title": "Proof you can inspect. Limits you can read.",
    "status-heading": "Each part carries its present status.",
    "status-introduction": "Every item below carries a status label.",
    "github-title": "GitHub spine",
    "linux-title": "Linux-native execution cells",
    "passport-title": "Seal / passport",
    "passport-pointer": "The verification section below states the public proof and its limits.",
    "cockpit-title": "Owner cockpit",
    "graph-title": "Graph memory",
    "hybrid-heading": "The hybrid operating model.",
    "human-title": "Human as governing element",
    "control-title": "Bounded current control",
    "proof-heading": "One byte, flipped.",
    "proof-cardfoot": "The walkthrough gives file paths, commands, expected verdicts, and limits.",
    "refusal-title": "Beyond one broken signature.",
    "refusal-link": "Inspect every case and the explicit boundary.",
    "record-heading": "Current record. Current limits.",
    "status-link": "Current dated status: docs/status.md.",
}

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


REQUIRED_PUBLIC_FILES = {
    "README.md",
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
    "docs/landing-claims-map-v0.1.md",
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


def validate_document_links(claims: list[dict[str, Any]], evidence_ids: set[str]) -> None:
    """The README claim table is a restatement of the ledger, so it must match it
    exactly. A drifted statement or a flipped status is a validation failure."""
    readme = guarded_bytes(ROOT / "README.md").decode("utf-8")
    properties = guarded_bytes(ROOT / "docs/engineering-properties.md").decode("utf-8")
    rows = readme_claim_rows(readme)

    for claim in claims:
        claim_id = claim["id"]
        if claim_id not in properties:
            fail(f"{claim_id}: missing from engineering properties")
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


def normalize_landing_text(text: str) -> str:
    """Make HTML and Markdown whitespace irrelevant, never the words themselves."""
    return " ".join(text.split())


def split_map_ids(value: str, pattern: re.Pattern[str], label: str) -> list[str]:
    """Read a comma-separated cell without accepting an empty or malformed ID."""
    values = [item.strip().strip("`") for item in value.split(",") if item.strip()]
    if not values:
        fail(f"landing claims map {label}: expected at least one identifier")
    if len(values) != len(set(values)):
        fail(f"landing claims map {label}: duplicate identifiers")
    for item in values:
        if pattern.fullmatch(item) is None:
            fail(f"landing claims map {label}: invalid identifier {item}")
    return values


def parse_landing_claim_map(text: str) -> dict[str, dict[str, Any]]:
    """Parse the deliberately small, reviewable landing sentence map."""
    start = text.find(LANDING_MAP_OPEN)
    end = text.find(LANDING_MAP_CLOSE)
    if start < 0 or end < 0 or end < start:
        fail("landing claims map: missing or malformed map markers")
    if text.find(LANDING_MAP_OPEN, start + 1) >= 0 or text.find(
        LANDING_MAP_CLOSE, end + 1
    ) >= 0:
        fail("landing claims map: repeated map markers")

    lines = text[start + len(LANDING_MAP_OPEN) : end].strip().splitlines()
    if len(lines) < 3:
        fail("landing claims map: missing table rows")

    def cells(line: str, label: str) -> list[str]:
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            fail(f"landing claims map {label}: expected a Markdown table row")
        values = [item.strip() for item in stripped[1:-1].split("|")]
        if len(values) != len(LANDING_MAP_HEADER):
            fail(
                f"landing claims map {label}: expected {len(LANDING_MAP_HEADER)} cells, "
                f"got {len(values)}"
            )
        return values

    if tuple(cells(lines[0], "header")) != LANDING_MAP_HEADER:
        fail("landing claims map: header differs from the required contract")
    separator = cells(lines[1], "separator")
    if any(not re.fullmatch(r":?-{3,}:?", item) for item in separator):
        fail("landing claims map: malformed table separator")

    rows: dict[str, dict[str, Any]] = {}
    for position, line in enumerate(lines[2:], start=3):
        key, kind, claim_cell, status, source, statement = cells(line, f"row {position}")
        if LANDING_KEY_RE.fullmatch(key) is None:
            fail(f"landing claims map row {position}: invalid key {key}")
        if key in rows:
            fail(f"landing claims map: duplicate key {key}")
        if kind not in LANDING_MAP_KINDS:
            fail(f"landing claims map {key}: invalid kind {kind}")
        if not statement or statement != normalize_landing_text(statement):
            fail(f"landing claims map {key}: statement must be one normalized sentence")
        if not source:
            fail(f"landing claims map {key}: missing evidence or status source")

        claims: list[str] = []
        sources: list[str] = []
        if kind == "claim":
            claims = split_map_ids(claim_cell, CLAIM_ID_RE, f"{key}.CLM IDs")
            sources = split_map_ids(source, EVIDENCE_ID_RE, f"{key}.source")
            if status not in CLAIM_STATUSES:
                fail(f"landing claims map {key}: invalid recorded claim status {status}")
        elif kind == "design-target":
            if claim_cell != NO_LANDING_CLAIM or status != "design-target":
                fail(f"landing claims map {key}: design target must carry no CLM ID")
            if not source.startswith("docs/status.md#"):
                fail(f"landing claims map {key}: design target needs a status source")
            wording = statement.lower()
            if "design target" not in wording or "not shipped" not in wording:
                fail(f"landing claims map {key}: design target wording is incomplete")
        elif kind == "status":
            if claim_cell != NO_LANDING_CLAIM:
                fail(f"landing claims map {key}: status rows may not carry CLM IDs")
            if status not in LANDING_STATUS_LABELS:
                fail(f"landing claims map {key}: invalid public status {status}")
            if not source.startswith("docs/status.md#"):
                fail(f"landing claims map {key}: status needs a docs/status.md source")
        else:
            if claim_cell != NO_LANDING_CLAIM or status != "required":
                fail(f"landing claims map {key}: boundary row is malformed")
            if not source.startswith("docs/verify.md#"):
                fail(f"landing claims map {key}: boundary needs a docs/verify.md source")

        rows[key] = {
            "kind": kind,
            "claims": claims,
            "status": status,
            "sources": sources,
            "source": source,
            "statement": statement,
        }
    return rows


class LandingStatementParser(HTMLParser):
    """Collect the visible text of each explicitly mapped landing statement."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.statements: dict[str, str] = {}
        self.errors: list[str] = []
        self._key: str | None = None
        self._tag: str | None = None
        self._depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes: dict[str, str | None] = {}
        for name, value in attrs:
            if name in attributes:
                self.errors.append(f"landing HTML repeats attribute {name}")
            attributes[name] = value
        key = attributes.get("data-landing-statement")
        if self._key is not None:
            if key is not None:
                self.errors.append("landing statements may not be nested")
            if tag not in HTML_VOID_ELEMENTS:
                self._depth += 1
            return
        if key is None:
            return
        if not key or LANDING_KEY_RE.fullmatch(key) is None:
            self.errors.append(f"landing HTML has invalid statement key {key!r}")
            return
        if tag in HTML_VOID_ELEMENTS:
            self.errors.append(f"landing statement {key} cannot use void tag {tag}")
            return
        self._key = key
        self._tag = tag
        self._depth = 1
        self._parts = []

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if any(name == "data-landing-statement" for name, _value in attrs):
            self.errors.append(f"landing statement cannot use self-closing tag {tag}")

    def handle_data(self, data: str) -> None:
        if self._key is not None:
            self._parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._key is None or tag in HTML_VOID_ELEMENTS:
            return
        self._depth -= 1
        if self._depth > 0:
            return
        if self._depth < 0 or tag != self._tag:
            self.errors.append("landing statement HTML is not properly nested")
        elif self._key in self.statements:
            self.errors.append(f"landing HTML repeats statement key {self._key}")
        else:
            self.statements[self._key] = normalize_landing_text("".join(self._parts))
        self._key = None
        self._tag = None
        self._parts = []
        self._depth = 0

    def parsed(self) -> dict[str, str]:
        if self._key is not None:
            self.errors.append(f"landing statement {self._key} is not closed")
        if self.errors:
            fail(self.errors[0])
        return self.statements


def parse_landing_statements(text: str) -> dict[str, str]:
    parser = LandingStatementParser()
    parser.feed(text)
    parser.close()
    return parser.parsed()


class LandingCopyScopeParser(HTMLParser):
    """Require mapped or fixed support copy for each product-facing sentence."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.errors: list[str] = []
        self.support: dict[str, str] = {}
        self._scope_seen = False
        self._scope_depth = 0
        self._support_key: str | None = None
        self._support_tag: str | None = None
        self._support_depth = 0
        self._support_parts: list[str] = []

    def _attributes(
        self, attrs: list[tuple[str, str | None]]
    ) -> dict[str, str | None]:
        attributes: dict[str, str | None] = {}
        for name, value in attrs:
            if name in attributes:
                self.errors.append(f"landing HTML repeats attribute {name}")
            attributes[name] = value
        return attributes

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = self._attributes(attrs)
        starts_scope = LANDING_COPY_SCOPE_ATTRIBUTE in attributes
        has_statement = "data-landing-statement" in attributes
        has_support = LANDING_SUPPORT_ATTRIBUTE in attributes

        if starts_scope:
            if tag != "main" or self._scope_seen or self._scope_depth:
                self.errors.append("landing product copy must have one main scope")
                return
            if attributes[LANDING_COPY_SCOPE_ATTRIBUTE] not in (None, ""):
                self.errors.append("landing product copy scope may not have a value")
            self._scope_seen = True
            self._scope_depth = 1
            return

        if not self._scope_depth:
            if has_statement or has_support:
                self.errors.append("landing mapped copy must stay inside the product scope")
            return

        if self._support_key is not None:
            if has_statement or has_support or tag in LANDING_PRODUCT_TEXT_TAGS:
                self.errors.append("landing support copy may not nest product text")
            if tag not in HTML_VOID_ELEMENTS:
                self._support_depth += 1
                self._scope_depth += 1
            return

        if tag in LANDING_PRODUCT_TEXT_TAGS:
            if has_statement == has_support:
                self.errors.append(
                    "landing product statement is not mapped or fixed support copy"
                )
            elif has_support:
                support_key = attributes[LANDING_SUPPORT_ATTRIBUTE]
                if support_key is None or support_key not in LANDING_SUPPORT_COPY:
                    self.errors.append("landing support copy has an unknown key")
                elif support_key in self.support:
                    self.errors.append(f"landing support copy repeats {support_key}")
                else:
                    self._support_key = support_key
                    self._support_tag = tag
                    self._support_depth = 1
                    self._support_parts = []
        elif has_statement or has_support:
            self.errors.append("landing copy marker must label a product text element")

        if tag not in HTML_VOID_ELEMENTS:
            self._scope_depth += 1

    def handle_data(self, data: str) -> None:
        if self._support_key is not None:
            self._support_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if not self._scope_depth or tag in HTML_VOID_ELEMENTS:
            return

        if self._support_key is not None:
            self._support_depth -= 1
            if self._support_depth == 0:
                key = self._support_key
                if tag != self._support_tag:
                    self.errors.append("landing support copy HTML is not properly nested")
                elif normalize_landing_text("".join(self._support_parts)) != LANDING_SUPPORT_COPY[key]:
                    self.errors.append(f"landing support copy {key} differs from the contract")
                else:
                    self.support[key] = LANDING_SUPPORT_COPY[key]
                self._support_key = None
                self._support_tag = None
                self._support_parts = []
            elif self._support_depth < 0:
                self.errors.append("landing support copy HTML is not properly nested")

        self._scope_depth -= 1
        if self._scope_depth == 0 and tag != "main":
            self.errors.append("landing product copy scope HTML is not properly nested")
        elif self._scope_depth < 0:
            self.errors.append("landing product copy scope HTML is not properly nested")
            self._scope_depth = 0

    def parsed(self) -> dict[str, str]:
        if not self._scope_seen:
            self.errors.append("landing product copy scope is missing")
        if self._scope_depth:
            self.errors.append("landing product copy scope is not closed")
        if self._support_key is not None:
            self.errors.append("landing support copy is not closed")
        if set(self.support) != set(LANDING_SUPPORT_COPY):
            self.errors.append(
                "landing support copy keys differ from the contract: "
                f"missing={sorted(set(LANDING_SUPPORT_COPY) - set(self.support))} "
                f"unexpected={sorted(set(self.support) - set(LANDING_SUPPORT_COPY))}"
            )
        if self.errors:
            fail(self.errors[0])
        return self.support


def parse_landing_copy_scope(text: str) -> dict[str, str]:
    parser = LandingCopyScopeParser()
    parser.feed(text)
    parser.close()
    return parser.parsed()


def check_runs_count() -> int:
    """Use the public counter itself; a count is trusted only after it verifies runs."""
    completed = subprocess.run(
        [sys.executable, str(CHECK_RUNS_PATH)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if completed.returncode != 0 or len(lines) != 1:
        fail("landing run count: tools/check_runs.py did not produce one successful count")
    match = re.fullmatch(r"verified runs: ([1-9][0-9]*)", lines[0])
    if match is None:
        fail("landing run count: tools/check_runs.py output is malformed")
    return int(match.group(1))


def validate_landing_controls(landing: str) -> None:
    """A static proof exhibit may use its two radio inputs, never a commercial form."""
    if re.search(r"<\s*(?:script|iframe|embed|object|form|select|textarea|button)\b", landing, re.I):
        fail("landing controls: scripts, embeds, forms, and commercial controls are forbidden")
    inputs = re.findall(r"<\s*input\b[^>]*>", landing, re.I)
    if len(inputs) != 2 or any(
        re.search(r"\btype\s*=\s*['\"]?radio\b", item, re.I) is None for item in inputs
    ):
        fail("landing controls: only the two static proof radio inputs are allowed")
    if re.search(r"\b(?:buy now|checkout|pre-?order|add to cart)\b|\$\s*[0-9]|\b(?:USD|EUR)\b", landing, re.I):
        fail("landing controls: pricing, sales, or order controls are forbidden")
    if re.search(r"\b(?:src|srcset)\s*=\s*['\"](?!data:)", landing, re.I):
        fail("landing controls: external resources are forbidden")
    if re.search(r"<\s*link\b|@\s*import\b|url\(\s*(?!['\"]?data:)", landing, re.I):
        fail("landing controls: external resources are forbidden")


def validate_landing_claims(
    claims: list[dict[str, Any]],
    *,
    landing_text: str | None = None,
    map_text: str | None = None,
    status_text: str | None = None,
    verified_run_count: int | None = None,
) -> None:
    """Bind the landing's declared product sentences to claim/status evidence."""
    landing = landing_text if landing_text is not None else guarded_bytes(LANDING_PATH).decode("utf-8")
    mapping = parse_landing_claim_map(
        map_text
        if map_text is not None
        else guarded_bytes(LANDING_CLAIMS_MAP_PATH).decode("utf-8")
    )
    status = status_text if status_text is not None else guarded_bytes(STATUS_PATH).decode("utf-8")
    parse_landing_copy_scope(landing)
    statements = parse_landing_statements(landing)
    validate_landing_controls(landing)

    if HONEST_BOUNDARY_KEY not in statements:
        fail("landing honest-boundary line is missing")
    if HONEST_BOUNDARY_KEY not in mapping:
        fail("landing claims map: honest-boundary entry is missing")
    if set(mapping) != REQUIRED_LANDING_KEYS:
        fail(
            "landing claims map keys differ from the required contract: "
            f"missing={sorted(REQUIRED_LANDING_KEYS - set(mapping))} "
            f"unexpected={sorted(set(mapping) - REQUIRED_LANDING_KEYS)}"
        )
    unknown_statements = set(statements) - set(mapping)
    if unknown_statements:
        fail(f"landing statement {sorted(unknown_statements)[0]} is absent from claims map")
    missing_statements = set(mapping) - set(statements)
    if missing_statements:
        fail(f"landing claims map statement missing from landing: {sorted(missing_statements)[0]}")

    count = verified_run_count if verified_run_count is not None else check_runs_count()
    region_match = re.search(
        r"<!-- generated:verified-runs -->(.*?)<!-- /generated:verified-runs -->",
        landing,
        re.DOTALL,
    )
    if region_match is None:
        fail("landing run count: generated verified-runs region is missing")
    expected_count_text = "one supervised run" if count == 1 else f"{count} supervised runs"
    if expected_count_text not in normalize_landing_text(region_match.group(1)):
        fail(
            "landing run count differs from tools/check_runs.py: "
            f"expected {count} verified run(s)"
        )

    claims_by_id = {claim["id"]: claim for claim in claims}
    for key, row in mapping.items():
        actual = statements[key]
        if actual != row["statement"]:
            fail(f"landing statement {key} differs from claims map")
        if row["kind"] == "claim":
            expected_evidence: set[str] = set()
            claim_statuses: set[str] = set()
            for claim_id in row["claims"]:
                claim = claims_by_id.get(claim_id)
                if claim is None:
                    fail(f"landing claims map {key}: unknown {claim_id}")
                claim_statuses.add(claim["status"])
                expected_evidence.update(claim["evidence_ids"])
            if claim_statuses != {row["status"]}:
                fail(f"landing claims map {key}: recorded status disagrees with ledger")
            if set(row["sources"]) != expected_evidence:
                fail(f"landing claims map {key}: evidence differs from ledger")
        elif row["kind"] in {"design-target", "status"}:
            if normalize_landing_text(row["statement"]) not in normalize_landing_text(status):
                fail(f"landing claims map {key}: status sentence is absent from docs/status.md")
        elif row["kind"] == "boundary":
            source_path = ROOT / row["source"].split("#", 1)[0]
            if source_path != VERIFY_PATH or not source_path.is_file():
                fail(f"landing claims map {key}: boundary source is unavailable")

    visible_landing = normalize_landing_text(landing).lower()
    for term in ("stranger", "re-runnable"):
        mapped_occurrences = 0
        for key, row in mapping.items():
            occurrences = row["statement"].lower().count(term)
            mapped_occurrences += occurrences
            if occurrences and (
                row["kind"] != "claim" or row["status"] != "public-reproducible"
            ):
                fail(
                    f"landing claims map {key}: {term} wording requires a "
                    "public-reproducible claim"
                )
        if visible_landing.count(term) != mapped_occurrences:
            fail(
                f"landing {term} wording must appear only in a mapped "
                "public-reproducible claim"
            )

    graph = mapping[GRAPH_MEMORY_KEY]
    graph_text = statements[GRAPH_MEMORY_KEY].lower()
    if graph["kind"] != "design-target" or "graph memory" not in graph_text:
        fail("landing graph memory must remain a design target")
    if any(term in graph_text for term in ("deployed", "is live", "available now", "operates")):
        fail("landing graph memory uses implemented tense")

    boundary = statements[HONEST_BOUNDARY_KEY].lower()
    if "no part of this work has had independent human review" not in boundary:
        fail("landing honest-boundary line is incomplete")
    verify_boundary = statements["LND-VERIFY-BOUNDARY"].lower()
    for required in ("does not", "reproduce a run", "semantic correctness"):
        if required not in verify_boundary:
            fail("landing verification boundary is incomplete")

    for claim_id in ("CLM-0008", "CLM-0010"):
        if not any(claim_id in row["claims"] for row in mapping.values()):
            fail(f"landing claims map: required positive control {claim_id} is missing")


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
    validate_document_links(claims, set(evidence_ids))
    validate_landing_claims(claims)
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
