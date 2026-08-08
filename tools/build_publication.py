#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish a run, and prove that what is published was derived and not typed.

Publishing a supervised run used to be eight hand operations: copy the passport,
hand-craft its one-byte twin, copy the target's before and after bytes, write an
evidence record, compute that record's digest into the ledger, add the claim, and
mirror the claim row into the README byte-equal or continuous integration fails.
Every one of those steps is a place where a human types a number, and a typed
number is a number that can be wrong.

This tool derives all of it. `add-run` writes the artifacts for one run; `check`
regenerates every derived thing in memory and refuses if the tree disagrees. The
second is the one that matters: once it runs in continuous integration, a
hand-edited claim row or a stale digest fails the build, and the published record
cannot drift from the artifacts it describes.

Three properties are load-bearing:

* The twin is deterministic. It is derived from the passport by a stated rule, so
  a reader can regenerate it and confirm the difference is the single byte we say
  it is -- not a byte we chose after seeing which one produced a pleasing verdict.
* The digest is computed after the bytes are final, never before. That ordering
  is the whole reason the ledger can be trusted to describe the file it names.
* `add-run` is idempotent. Running it twice leaves the tree byte-identical, so a
  retry after an interrupted publication cannot append a duplicate claim.

Standard library only. No network.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import html
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType

from survey_refusals import RefusalCoverage, evaluate_coverage


REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "tools" / "verify_run_passport.py"
LEDGER_PATH = REPO_ROOT / "evidence" / "ledger-v1.json"
RECORDS_DIR = REPO_ROOT / "evidence" / "records"
PUBLISHED_ROOT = REPO_ROOT / "examples" / "verified"
README_PATH = REPO_ROOT / "README.md"
RUNS_INDEX = PUBLISHED_ROOT / "runs.md"
LANDING_PATH = REPO_ROOT / "index.html"
PASSPORT_SPEC_PATH = REPO_ROOT / "docs" / "passport-spec-v1.md"
STATUS_PATH = REPO_ROOT / "docs" / "status.md"
CONFORMANCE_ROOT = PUBLISHED_ROOT / "conformance"
CONFORMANCE_VECTORS = CONFORMANCE_ROOT / "vectors"
CONFORMANCE_MANIFEST = CONFORMANCE_ROOT / "manifest.json"
REFUSAL_CORPUS_PATH = REPO_ROOT / "demo" / "refusals" / "test_refusals.py"

PASS_VERDICT = "RUN_PASSPORT_VERDICT: PASS"
BLOCK_PREFIX = "RUN_PASSPORT_VERDICT: BLOCK"

# The gate parses claim rows with exactly this shape; the generator below must
# produce rows it accepts, so the two are pinned to one pattern.
CLAIM_ROW_RE = re.compile(
    r"^\|\s*`(CLM-[0-9]{4})`\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*`([a-z-]+)`\s*\|\s*$",
    re.MULTILINE,
)
CLAIM_TABLE_HEADER = "| Claim | Statement | Evidence | Status |\n|---|---|---|---|\n"

RECORD_SCHEMA_VERSION = "deedseal.public-evidence-record/v1"
PUBLISHED_RUN_KIND = "published-verification-artifact"
PUBLIC_REPRODUCIBLE = "public-reproducible"
REFUSAL_CLAIM_ID = "CLM-0010"
REFUSAL_EVIDENCE_ID = "EVD-PUBLIC-0001"
SPEC_REFUSAL_OPEN = "<!-- generated:passport-refusal-reasons -->"
SPEC_REFUSAL_CLOSE = "<!-- /generated:passport-refusal-reasons -->"
CONFORMANCE_SCHEMA_VERSION = "deedseal.passport-conformance/v1"
CONFORMANCE_INPUT_KINDS = frozenset({"file", "absent", "directory"})


class PublicationError(Exception):
    """A derivation failed. The message says which, and what was observed."""


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(value: dict) -> str:
    """The repository's committed JSON shape: two-space indent, trailing newline."""
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def run_verifier(passport: Path) -> tuple[int, str]:
    completed = subprocess.run(
        [sys.executable, str(VERIFIER), str(passport)],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    return completed.returncode, lines[-1] if lines else "(no verdict printed)"


def single_byte_difference(original: bytes, twin: bytes) -> int:
    """The one differing offset, or raise. Equal length is part of the claim."""
    if len(original) != len(twin):
        raise PublicationError(
            f"twin length {len(twin)} differs from passport length {len(original)}"
        )
    offsets = [i for i, (a, b) in enumerate(zip(original, twin)) if a != b]
    if len(offsets) != 1:
        raise PublicationError(f"twin differs at {len(offsets)} bytes, expected exactly 1")
    return offsets[0]


# --------------------------------------------------------------------------
# the deterministic twin
# --------------------------------------------------------------------------


def derive_twin(passport_bytes: bytes) -> tuple[bytes, int]:
    """The passport's one-byte twin, derived by a stated rule.

    The rule: find the passport's own `run_id` value in the serialized bytes and
    increment its last decimal digit, wrapping 9 to 0. `run_id` is signed, so any
    change to it must break a signature -- which is the point of the twin, and
    which the caller re-proves with the verifier before anything is written.

    The rule is fixed rather than chosen per passport, so nobody can suspect the
    byte was picked after seeing which choice produced a convenient verdict.
    """
    document = json.loads(passport_bytes.decode("utf-8"))
    run_id = document.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise PublicationError("passport has no top-level string run_id to derive a twin from")

    needle = f'"run_id":"{run_id}"'.encode()
    spaced = f'"run_id": "{run_id}"'.encode()
    if needle in passport_bytes:
        start = passport_bytes.index(needle) + len(b'"run_id":"')
    elif spaced in passport_bytes:
        start = passport_bytes.index(spaced) + len(b'"run_id": "')
    else:
        raise PublicationError("could not locate the run_id value in the passport bytes")

    value = passport_bytes[start : start + len(run_id.encode())]
    digit_positions = [i for i, byte in enumerate(value) if 0x30 <= byte <= 0x39]
    if not digit_positions:
        raise PublicationError("run_id carries no decimal digit to flip")
    offset = start + digit_positions[-1]

    original_digit = passport_bytes[offset]
    flipped = 0x30 if original_digit == 0x39 else original_digit + 1
    twin = bytearray(passport_bytes)
    twin[offset] = flipped
    return bytes(twin), offset


# --------------------------------------------------------------------------
# the README claim table, regenerated from the ledger
# --------------------------------------------------------------------------


def claim_rows_from_ledger(ledger: dict) -> str:
    rows = []
    for claim in ledger["claims"]:
        evidence = ", ".join(f"`{value}`" for value in claim["evidence_ids"])
        rows.append(
            "| `{id}` | {statement} | {evidence} | `{status}` |".format(
                id=claim["id"],
                statement=claim["statement"],
                evidence=evidence,
                status=claim["status"],
            )
        )
    return "\n".join(rows)


def readme_with_regenerated_table(readme: str, ledger: dict) -> str:
    """`readme` with its claim table replaced by the ledger's, header preserved.

    The span replaced is exactly the run of claim rows: from the start of the
    first row to the end of the last row's LINE. The match's own `end()` is not
    usable here -- the gate's row pattern ends in `\\s*$`, which is greedy and
    swallows the blank line that follows the table, so slicing on it would delete
    the paragraph break. Everything from that newline onward is the README's.
    """
    matches = list(CLAIM_ROW_RE.finditer(readme))
    if not matches:
        raise PublicationError("README has no claim table to regenerate")
    last_line_end = readme.index("\n", matches[-1].start())
    return (
        readme[: matches[0].start()]
        + claim_rows_from_ledger(ledger)
        + readme[last_line_end:]
    )


# --------------------------------------------------------------------------
# the run index
# --------------------------------------------------------------------------


def runs_index_text() -> str:
    """One row per published run, walkable by commit ancestry.

    Derived entirely from the passports themselves, so the index cannot claim a
    lineage the records do not carry.
    """
    lines = [
        "# Published runs",
        "",
        "Generated by `tools/build_publication.py`. Do not edit by hand.",
        "",
        "Each row is one supervised run whose passport is published here and",
        "verifies with `tools/verify_run_passport.py`. The commit identifiers are",
        "those of the private engineering repository the run happened in; they do",
        "not resolve in this repository, by design.",
        "",
        "| Run | Parent commit | Resulting commit | Artifacts |",
        "|---|---|---|---|",
    ]
    for passport_path in sorted(PUBLISHED_ROOT.rglob("run-passport.json")):
        document = load_json(passport_path)
        identity = (
            document.get("committed_binding", {}).get("commit_identity", {})
            if isinstance(document.get("committed_binding"), dict)
            else {}
        )
        directory = passport_path.parent.relative_to(REPO_ROOT).as_posix()
        lines.append(
            "| `{run}` | `{parent}` | `{commit}` | [`{dir}`]({rel}) |".format(
                run=document.get("run_id", "(none)"),
                parent=identity.get("parent_sha", "(none)"),
                commit=identity.get("commit_sha", "(none)"),
                dir=directory,
                rel=passport_path.parent.relative_to(PUBLISHED_ROOT).as_posix() or ".",
            )
        )
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# the evidence record
# --------------------------------------------------------------------------


def next_identifier(existing: list[str], prefix: str) -> str:
    numbers = [int(value.rsplit("-", 1)[1]) for value in existing if value.startswith(prefix)]
    return f"{prefix}{max(numbers, default=0) + 1:04d}"


def build_record(
    *,
    record_id: str,
    source_snapshot: str,
    observed_on: str,
    passport: Path,
    twin: Path,
    offset: int,
    target_after: Path,
) -> dict:
    """The evidence record for one published run, every observation derived."""
    document = load_json(passport)
    committed = (
        document.get("committed_binding", {}).get("committed_file_hashes", {})
        if isinstance(document.get("committed_binding"), dict)
        else {}
    )
    after_digest = sha256_of(target_after)
    binding_holds = after_digest in set(committed.values())
    _, twin_verdict = run_verifier(twin)

    return {
        "schema_version": RECORD_SCHEMA_VERSION,
        "id": record_id,
        "component": "CORE",
        "source_snapshot": source_snapshot,
        "observed_on": observed_on,
        "kind": PUBLISHED_RUN_KIND,
        "assurance": PUBLIC_REPRODUCIBLE,
        "verification": {
            "verdict": "PASS",
            "observations": [
                {
                    "check": "published-passport-digest",
                    "result": f"sha256 {sha256_of(passport)}",
                },
                {"check": "published-passport-verdict", "result": "PASS, exit code 0"},
                {"check": "tampered-twin-digest", "result": f"sha256 {sha256_of(twin)}"},
                {
                    "check": "tampered-twin-verdict",
                    "result": "{0}, exit code 1".format(
                        twin_verdict.replace("RUN_PASSPORT_VERDICT: ", "")
                    ),
                },
                {
                    "check": "twin-byte-distance",
                    "result": f"same length; exactly 1 differing byte at offset {offset}",
                },
                {
                    "check": "committed-bytes-match-signed-digest",
                    "result": (
                        "sha256 of the published post-run file equals the passport's "
                        "signed committed_file_hashes entry"
                        if binding_holds
                        else "MISMATCH: published post-run bytes are not the signed bytes"
                    ),
                },
            ],
        },
        "disclosure": {
            "source_visibility": "public",
            "redactions": [],
            "omitted": [
                "the private system that produced the run, and its signing keys",
                "the agent's captured output, which the signed record carries only as digests",
                "implementation detail of the controlled-execution path",
            ],
        },
        "limitations": [
            "The verdicts are reproducible from this repository; the run that produced the "
            "passport is not. New passports require the private system and its signing keys.",
            "A PASS attests authorization, bounded scope, applied boundary, and committed-byte "
            "provenance for one run. It does not attest the semantic quality of the change.",
            "Signing-key secrecy is a trusted prerequisite. An attacker holding the private "
            "keys could mint records the published verifier would accept.",
        ],
    }


# --------------------------------------------------------------------------
# planning: every write goes through one plan, so --dry-run and check agree
# --------------------------------------------------------------------------


def verified_run_sentence(count: int) -> str:
    """The landing page's run clause, correct English at any count.

    A door that says "1 runs are published" is worse than the typed number it
    replaced, so the singular is spelt out rather than rendered as a digit.
    """
    tail = "with its passport, its tampered twin,\n      and the verifier"
    if count == 1:
        return f"one supervised run is\n      published, {tail}"
    return f"{count} supervised runs are\n      published, each {tail}"


def frozen_envelope_version(status: str) -> str | None:
    """The envelope version `docs/status.md` declares frozen, or None.

    Status is written for humans and dated by hand, so it is parsed rather than
    trusted: the workstream row must exist, and the version it names is read out
    of it. A row that does not say `frozen at` returns None -- that is a real
    state this repository was in until today, not a parse failure.
    """
    row = re.search(
        r"^\|\s*Run passport format\s*\|[^|]*\|\s*(.+?)\s*\|\s*$", status, re.MULTILINE
    )
    if row is None:
        raise PublicationError(
            "docs/status.md has no 'Run passport format' workstream row"
        )
    named = re.search(r"frozen at `([^`]+)`", row.group(1))
    return None if named is None else named.group(1)


def published_envelope_version() -> str:
    """The `schema_version` every published passport carries.

    The landing may not name a format the published bytes do not carry, so the
    bytes are the authority here and disagreement between them is fatal.
    """
    passports = published_passports()
    if not passports:
        raise PublicationError("no published passport to read an envelope version from")
    versions = {load_json(path)["schema_version"] for path in passports}
    if len(versions) > 1:
        raise PublicationError(
            "published passports disagree on schema_version: "
            + ", ".join(sorted(versions))
        )
    return versions.pop()


def envelope_commitment(status: str, published_version: str) -> str:
    """The landing's durability clause, or a refusal to make one.

    A promise about the format is the one thing on that page a reader could act
    on later -- download the verifier now, verify a passport next year. So it is
    derived from two sources that have to agree: what status declares, and what
    the published passports actually carry. If they diverge, the page says
    nothing rather than something convenient.
    """
    declared = frozen_envelope_version(status)
    if declared is None:
        return (
            "not frozen yet — the published envelope\n"
            "      may still change, so treat a passport you verify today as a\n"
            "      demonstration rather than a commitment"
        )
    if declared != published_version:
        raise PublicationError(
            f"docs/status.md declares {declared} frozen, but the published "
            f"passports carry {published_version}"
        )
    return (
        f'frozen at <span class="mono">{declared}</span> —\n'
        "      a passport that verifies today keeps verifying, and new capability\n"
        "      arrives as a new version, never as a silent change to this one"
    )


def product_target_capabilities(
    status: str,
) -> list[tuple[str, str, str, str, str]]:
    """The seven Product 1 capability rows owned by ``docs/status.md``.

    The landing is a projection of status, not a second status ledger. The
    parser therefore accepts one deliberately small Markdown shape and refuses
    a missing, duplicated, or reordered row rather than rendering a plausible
    but stale finish line.
    """
    section = re.search(
        r"^## Product 1 target\s*$\n(.*?)(?=^##\s|\Z)",
        status,
        re.MULTILINE | re.DOTALL,
    )
    if section is None:
        raise PublicationError("docs/status.md has no 'Product 1 target' section")
    rows = re.findall(
        r"^\|\s*([1-7])\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$",
        section.group(1),
        re.MULTILINE,
    )
    observed = [row[0] for row in rows]
    expected = [str(number) for number in range(1, 8)]
    if observed != expected:
        raise PublicationError(
            "Product 1 capability rows must appear exactly once in order 1..7; "
            f"observed {observed}"
        )
    return rows


def product_target_rows_html(status: str) -> str:
    """Render the status-owned Product 1 table as accessible landing rows."""
    rendered: list[str] = []
    for number, capability, target, today, public_gate in product_target_capabilities(
        status
    ):
        if today.startswith("engineering-reported"):
            tone = "reported"
        elif today.startswith(("not started", "no repository")):
            tone = "absent"
        else:
            tone = "pending"
        state = re.split(r"\s*(?:—|;)\s*", today, maxsplit=1)[0]
        rendered.append(
            "\n".join(
                (
                    f'          <tr class="capability-row {tone}">',
                    f'            <td class="capability-number mono" data-label="Gate">{html.escape(number)}</td>',
                    "            <th scope=\"row\">",
                    f'              <span class="capability-name display">{html.escape(capability)}</span>',
                    f'              <span class="capability-state mono">{html.escape(state)}</span>',
                    "            </th>",
                    f'            <td data-label="Being built toward">{html.escape(target)}</td>',
                    f'            <td data-label="Today">{html.escape(today)}</td>',
                    f'            <td data-label="Public gate">{html.escape(public_gate)}</td>',
                    "          </tr>",
                )
            )
        )
    return "\n" + "\n".join(rendered) + "\n          "


def refusal_coverage() -> RefusalCoverage:
    """Return measured refusal coverage, or fail the publication closed."""

    coverage = evaluate_coverage()
    if coverage.errors:
        raise PublicationError(
            "refusal coverage is not publishable: " + "; ".join(coverage.errors)
        )
    return coverage


def refusal_claim_statement(coverage: RefusalCoverage) -> str:
    declared, demonstrated, not_reachable = coverage.counts
    return (
        f"The published verifier declares {declared} refusal reasons; the published "
        f"mutation corpus demonstrates {demonstrated} exact refusal verdicts and "
        f"classifies {not_reachable} as not reachable by mutation of the published bytes."
    )


def passport_spec_with_refusal_reasons(specification: str) -> str:
    """Replace the specification's refusal vocabulary from verifier declarations."""

    coverage = refusal_coverage()
    lines = [
        f"- `{reason}` — Refuses {reason.removeprefix('block_').replace('_', ' ')}."
        for reason in sorted(coverage.declared)
    ]
    start = specification.find(SPEC_REFUSAL_OPEN)
    end = specification.find(SPEC_REFUSAL_CLOSE)
    if start < 0 or end < 0 or end < start:
        raise PublicationError("passport specification has no refusal-reason markers")
    if specification.find(SPEC_REFUSAL_OPEN, start + 1) >= 0:
        raise PublicationError("passport specification repeats refusal-reason markers")
    replacement = SPEC_REFUSAL_OPEN + "\n" + "\n".join(lines) + "\n"
    return specification[:start] + replacement + specification[end:]


def refusal_claim_failures(ledger: dict, coverage: RefusalCoverage) -> list[str]:
    """Refuse drift between measured coverage, the claim, and its evidence record."""

    failures: list[str] = []
    claims = [item for item in ledger["claims"] if item["id"] == REFUSAL_CLAIM_ID]
    evidence = [
        item for item in ledger["evidence"] if item["id"] == REFUSAL_EVIDENCE_ID
    ]
    if len(claims) != 1:
        return [f"ledger must carry exactly one {REFUSAL_CLAIM_ID}"]
    if len(evidence) != 1:
        return [f"ledger must carry exactly one {REFUSAL_EVIDENCE_ID}"]

    claim = claims[0]
    expected_claim = {
        "statement": refusal_claim_statement(coverage),
        "component": "PUBLIC",
        "status": PUBLIC_REPRODUCIBLE,
        "evidence_ids": [REFUSAL_EVIDENCE_ID],
    }
    for field, expected in expected_claim.items():
        if claim.get(field) != expected:
            failures.append(
                f"{REFUSAL_CLAIM_ID}.{field} differs from measured refusal coverage"
            )

    record_path = REPO_ROOT / evidence[0]["artifact"]["path"]
    if not record_path.is_file():
        return failures + [f"{REFUSAL_EVIDENCE_ID} record is missing"]
    record = load_json(record_path)
    observations = {
        item.get("check"): item.get("result")
        for item in record.get("verification", {}).get("observations", [])
        if isinstance(item, dict)
    }
    declared, demonstrated, not_reachable = coverage.counts
    expected_observations = {
        "declared-refusal-reasons": (
            f"{declared} distinct block_* strings parsed from the published verifier"
        ),
        "demonstrated-refusal-reasons": (
            f"{demonstrated} distinct exact BLOCK verdicts produced by the published corpus"
        ),
        "not-reachable-by-published-mutation": (
            f"{not_reachable} declared reasons classified outside published-byte mutation"
        ),
    }
    for check, expected in expected_observations.items():
        if observations.get(check) != expected:
            failures.append(
                f"{REFUSAL_EVIDENCE_ID} observation {check} differs from the survey"
            )
    return failures


def landing_with_generated_regions(landing: str) -> str:
    """`landing` with each generated region replaced by what the tree derives.

    Only the text between a marker pair changes; everything else on the page is
    hand-written and judged, and the generator must not touch it. A missing or
    malformed marker pair is an error, never a silent skip -- a region quietly
    left alone is exactly the drift this machinery exists to prevent.
    """
    coverage = refusal_coverage()
    declared, demonstrated, not_reachable = coverage.counts
    status = STATUS_PATH.read_text(encoding="utf-8")
    regions = {
        "verified-runs": verified_run_sentence(len(published_passports())),
        "envelope-commitment": envelope_commitment(
            status, published_envelope_version()
        ),
        "product-target-capabilities": product_target_rows_html(status),
        "refusal-declared": str(declared),
        "refusal-demonstrated": str(demonstrated),
        "refusal-not-reachable": str(not_reachable),
    }
    result = landing
    for name, replacement in regions.items():
        opening = f"<!-- generated:{name} -->"
        closing = f"<!-- /generated:{name} -->"
        start = result.find(opening)
        end = result.find(closing)
        if start < 0 or end < 0 or end < start:
            raise PublicationError(
                f"landing page has no well-formed region markers for '{name}'"
            )
        if result.find(opening, start + 1) >= 0 or result.find(closing, end + 1) >= 0:
            raise PublicationError(f"landing page repeats the markers for '{name}'")
        result = result[: start + len(opening)] + replacement + result[end:]
    return result


def published_passports() -> list[Path]:
    """Every published run passport, counted the same way the counter counts."""
    return sorted(PUBLISHED_ROOT.rglob("run-passport.json"))


def load_refusal_corpus() -> ModuleType:
    """Load mutation definitions without making the demo directory a package."""

    spec = importlib.util.spec_from_file_location(
        "deedseal_conformance_refusal_corpus", REFUSAL_CORPUS_PATH
    )
    if spec is None or spec.loader is None:
        raise PublicationError("could not load refusal corpus")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def conformance_suite() -> tuple[dict, dict[str, tuple[str, bytes | None]]]:
    """Derive the relocatable manifest and exact vector filesystem states."""

    corpus = load_refusal_corpus()
    base = load_json(PUBLISHED_ROOT / "run-passport.json")
    vectors: list[dict[str, object]] = []
    states: dict[str, tuple[str, bytes | None]] = {}

    pass_name = "vectors/vector-001.json"
    pass_bytes = (PUBLISHED_ROOT / "run-passport.json").read_bytes()
    vectors.append(
        {
            "id": "valid-published-passport",
            "why": "The unchanged published passport must be accepted.",
            "input": pass_name,
            "input_kind": "file",
            "expect_verdict": "PASS",
            "expect_exit_code": 0,
        }
    )
    states[pass_name] = ("file", pass_bytes)

    with tempfile.TemporaryDirectory(prefix="deedseal-conformance-") as temporary:
        temporary_root = Path(temporary)
        for index, case in enumerate(corpus.CASES, start=2):
            relative = f"vectors/vector-{index:03d}.json"
            source = corpus._materialize_case(case, base, temporary_root, index)
            path_kind = str(case.get("path_kind", "file"))
            input_kind = {"file": "file", "missing": "absent", "directory": "directory"}.get(
                path_kind
            )
            if input_kind not in CONFORMANCE_INPUT_KINDS:
                raise PublicationError(
                    f"{case.get('name')}: unknown corpus path kind {path_kind!r}"
                )
            reason = str(case["expect"])
            vector: dict[str, object] = {
                "id": str(case["name"]),
                "why": str(case["why"]),
                "input": relative,
                "input_kind": input_kind,
                "expect_verdict": "BLOCK",
                "expect_exit_code": 1,
            }
            if reason.startswith("block_"):
                vector["expect_reason"] = reason
            vectors.append(vector)
            payload = source.read_bytes() if input_kind == "file" else None
            states[relative] = (input_kind, payload)

    manifest = {
        "schema_version": CONFORMANCE_SCHEMA_VERSION,
        "specification": "docs/passport-spec-v1.md",
        "vectors": vectors,
    }
    return manifest, states


def conformance_manifest_text() -> str:
    manifest, _states = conformance_suite()
    return dump_json(manifest)


def conformance_state_failures() -> list[str]:
    """Refuse changed bytes, wrong path kinds, stale files, and absent-path drift."""

    _manifest, states = conformance_suite()
    failures: list[str] = []
    expected_entries = {Path(relative).relative_to("vectors") for relative in states}
    observed_entries = {
        path.relative_to(CONFORMANCE_VECTORS)
        for path in CONFORMANCE_VECTORS.rglob("*")
        if path.name != ".gitkeep"
    } if CONFORMANCE_VECTORS.exists() else set()

    for relative, (kind, payload) in states.items():
        path = CONFORMANCE_ROOT / relative
        if kind == "file":
            if not path.is_file():
                failures.append(f"{relative}: expected a file")
            elif path.read_bytes() != payload:
                failures.append(f"{relative}: bytes differ from corpus derivation")
        elif kind == "absent":
            if path.exists():
                failures.append(f"{relative}: expected no filesystem entry")
        elif kind == "directory":
            if not path.is_dir():
                failures.append(f"{relative}: expected a directory")
            elif not (path / ".gitkeep").is_file():
                failures.append(f"{relative}: directory lacks .gitkeep")
        else:
            failures.append(f"{relative}: unknown input kind {kind!r}")

    allowed = expected_entries | {
        Path(relative).relative_to("vectors") / ".gitkeep"
        for relative, (kind, _payload) in states.items()
        if kind == "directory"
    }
    for extra in sorted(observed_entries - allowed):
        failures.append(f"vectors/{extra.as_posix()}: unexpected generated entry")
    return failures


def derived_plan() -> dict[Path, str]:
    """Everything this tool derives from the current tree, as {path: text}."""
    ledger = load_json(LEDGER_PATH)
    plan: dict[Path, str] = {
        README_PATH: readme_with_regenerated_table(
            README_PATH.read_text(encoding="utf-8"), ledger
        ),
        RUNS_INDEX: runs_index_text(),
        LANDING_PATH: landing_with_generated_regions(
            LANDING_PATH.read_text(encoding="utf-8")
        ),
        PASSPORT_SPEC_PATH: passport_spec_with_refusal_reasons(
            PASSPORT_SPEC_PATH.read_text(encoding="utf-8")
        ),
        CONFORMANCE_MANIFEST: conformance_manifest_text(),
    }
    return plan


def ledger_digest_failures() -> list[str]:
    """Evidence entries whose recorded digest is not the digest of the file."""
    ledger = load_json(LEDGER_PATH)
    failures = []
    for entry in ledger["evidence"]:
        artifact = entry["artifact"]
        path = REPO_ROOT / artifact["path"]
        if not path.exists():
            failures.append(f"{artifact['path']}: missing")
            continue
        observed = sha256_of(path)
        if observed != artifact["sha256"]:
            failures.append(
                f"{artifact['path']}: ledger says {artifact['sha256'][:12]}…, "
                f"file is {observed[:12]}…"
            )
    return failures


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------


def command_check(_: argparse.Namespace) -> int:
    ledger = load_json(LEDGER_PATH)
    coverage = refusal_coverage()
    problems = (
        ledger_digest_failures()
        + refusal_claim_failures(ledger, coverage)
        + conformance_state_failures()
    )
    for path, expected in derived_plan().items():
        actual = path.read_text(encoding="utf-8") if path.exists() else ""
        if actual != expected:
            relative = path.relative_to(REPO_ROOT).as_posix()
            problems.append(f"{relative}: differs from what the ledger derives")
            diff = difflib.unified_diff(
                actual.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile=f"{relative} (on disk)",
                tofile=f"{relative} (derived)",
                n=1,
            )
            problems.extend(line.rstrip("\n") for line in list(diff)[:20])
    if problems:
        for problem in problems:
            print(problem)
        print("PUBLICATION_PACKAGER: FAIL")
        return 1
    print("PUBLICATION_PACKAGER: PASS")
    return 0


def command_generate_conformance(_: argparse.Namespace) -> int:
    """Replace only the generated vectors and manifest with their derivation."""

    manifest, states = conformance_suite()
    if CONFORMANCE_VECTORS.exists():
        shutil.rmtree(CONFORMANCE_VECTORS)
    CONFORMANCE_VECTORS.mkdir(parents=True)
    for relative, (kind, payload) in states.items():
        path = CONFORMANCE_ROOT / relative
        if kind == "file":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload if payload is not None else b"")
        elif kind == "directory":
            path.mkdir(parents=True)
            (path / ".gitkeep").write_bytes(b"")
        elif kind != "absent":
            raise PublicationError(f"unknown input kind {kind!r}")
    CONFORMANCE_MANIFEST.write_text(dump_json(manifest), encoding="utf-8")
    print(f"CONFORMANCE_GENERATOR: PASS {len(manifest['vectors'])} vectors")
    return 0


def command_add_run(args: argparse.Namespace) -> int:
    passport_source = Path(args.passport).resolve()
    before_source = Path(args.target_before).resolve()
    after_source = Path(args.target_after).resolve()
    for path in (passport_source, before_source, after_source):
        if not path.is_file():
            raise PublicationError(f"input missing: {path}")

    run_dir = PUBLISHED_ROOT / f"run-{int(args.run_number):03d}"
    passport_bytes = passport_source.read_bytes()
    twin_bytes, offset = derive_twin(passport_bytes)
    single_byte_difference(passport_bytes, twin_bytes)

    writes: dict[Path, bytes] = {
        run_dir / "run-passport.json": passport_bytes,
        run_dir / "run-passport.tampered.json": twin_bytes,
        run_dir / "target-before": before_source.read_bytes(),
        run_dir / "target-after": after_source.read_bytes(),
    }

    # Prove the pair BEFORE anything is written: a twin that does not flip the
    # verdict is not evidence, and must never reach the tree.
    staging = run_dir.with_name(run_dir.name + ".staging")
    staging.mkdir(parents=True, exist_ok=True)
    try:
        (staging / "p.json").write_bytes(passport_bytes)
        (staging / "t.json").write_bytes(twin_bytes)
        code_pass, verdict_pass = run_verifier(staging / "p.json")
        code_block, verdict_block = run_verifier(staging / "t.json")
        if code_pass != 0 or verdict_pass != PASS_VERDICT:
            raise PublicationError(f"passport does not verify: {verdict_pass}")
        if code_block == 0 or not verdict_block.startswith(BLOCK_PREFIX):
            raise PublicationError(f"twin was not refused: {verdict_block}")
    finally:
        for leftover in staging.glob("*"):
            leftover.unlink()
        staging.rmdir()

    ledger = load_json(LEDGER_PATH)
    record_id = next_identifier([item["id"] for item in ledger["evidence"]], "EVD-CORE-")
    claim_id = next_identifier([item["id"] for item in ledger["claims"]], "CLM-")

    if args.dry_run:
        print(f"would write {len(writes)} artifacts under {run_dir.relative_to(REPO_ROOT)}")
        print(f"would add {record_id} and {claim_id}")
        print(f"twin differs at byte offset {offset}")
        return 0

    for path, payload in writes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    record = build_record(
        record_id=record_id,
        source_snapshot=args.source_snapshot,
        observed_on=args.observed_on,
        passport=run_dir / "run-passport.json",
        twin=run_dir / "run-passport.tampered.json",
        offset=offset,
        target_after=run_dir / "target-after",
    )
    record_path = RECORDS_DIR / f"{record_id}.json"
    record_path.write_text(dump_json(record), encoding="utf-8")

    # The digest is computed only now, from the bytes as written. Computing it
    # from an in-memory value would describe a file that may never have existed.
    ledger["evidence"].append(
        {
            "id": record_id,
            "component": "CORE",
            "kind": PUBLISHED_RUN_KIND,
            "assurance": PUBLIC_REPRODUCIBLE,
            "observed_on": args.observed_on,
            "source_snapshot": args.source_snapshot,
            "artifact": {
                "path": record_path.relative_to(REPO_ROOT).as_posix(),
                "sha256": sha256_of(record_path),
            },
            "redactions": [],
            "limitations": [
                "The private source of the system that produced the run is identified only "
                "by its opaque snapshot identifier.",
                "Public reproducibility applies to checking the published passport and its "
                "tampered twin, not to producing new passports.",
            ],
        }
    )
    ledger["claims"].append(
        {
            "id": claim_id,
            "statement": args.claim_statement,
            "component": "CORE",
            "status": PUBLIC_REPRODUCIBLE,
            "observed_on": args.observed_on,
            "scope": ledger["snapshot"]["id"],
            "evidence_ids": [record_id],
            "limitations": [
                "The verdict attests integrity and provenance of the recorded run against "
                "the trust anchors pinned in the published verifier; it does not attest "
                "semantic quality of the change the run produced.",
                "Reproducing the verdict does not reproduce the run; producing new passports "
                "requires the private system and its signing keys.",
            ],
        }
    )
    LEDGER_PATH.write_text(dump_json(ledger), encoding="utf-8")

    for path, text in derived_plan().items():
        path.write_text(text, encoding="utf-8")

    print(f"published run {args.run_number}: {record_id}, {claim_id}, twin offset {offset}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add-run", help="publish one supervised run")
    add.add_argument("--passport", required=True)
    add.add_argument("--target-before", required=True)
    add.add_argument("--target-after", required=True)
    add.add_argument("--run-number", required=True, type=int)
    add.add_argument("--observed-on", required=True, help="YYYY-MM-DD")
    add.add_argument("--source-snapshot", required=True)
    add.add_argument("--claim-statement", required=True)
    add.add_argument("--dry-run", action="store_true")
    add.set_defaults(handler=command_add_run)

    check = sub.add_parser("check", help="refuse if any derived file was hand-edited")
    check.set_defaults(handler=command_check)

    conformance = sub.add_parser(
        "generate-conformance", help="regenerate the language-neutral vector suite"
    )
    conformance.set_defaults(handler=command_generate_conformance)

    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except PublicationError as error:
        print(f"PUBLICATION_PACKAGER: FAIL {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
