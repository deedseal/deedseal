#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Validate the public build journal, its views, and hostile refusals."""

from __future__ import annotations

import argparse
import copy
from datetime import date, datetime
import json
from pathlib import Path
import re
import sys
from typing import Any
from urllib import error, parse, request

import validate_public_record as public_gate


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/deedseal-public-build-journal-v1.schema.json"
JOURNAL_PATH = ROOT / "docs/build-journal/index.v1.json"
HUMAN_VIEWS = (
    ROOT / "docs/build-journal/README.md",
    ROOT / "docs/product-roadmap.md",
)

STATUSES = (
    "PROVED",
    "IN_REVIEW",
    "IN_DEVELOPMENT",
    "BLOCKED",
    "FAILED",
    "PLANNED",
    "UNKNOWN",
)
EVIDENCE_GRADES = (
    "PUBLIC_REPRODUCIBLE",
    "PUBLIC_OBSERVED",
    "PUBLIC_PROPOSAL",
    "UNKNOWN",
)
ALLOWED_GRADES = {
    "PROVED": {"PUBLIC_REPRODUCIBLE", "PUBLIC_OBSERVED"},
    "IN_REVIEW": {"PUBLIC_OBSERVED", "PUBLIC_PROPOSAL"},
    "IN_DEVELOPMENT": {"PUBLIC_OBSERVED", "PUBLIC_PROPOSAL"},
    "BLOCKED": {"PUBLIC_OBSERVED"},
    "FAILED": {"PUBLIC_REPRODUCIBLE", "PUBLIC_OBSERVED"},
    "PLANNED": {"PUBLIC_PROPOSAL"},
    "UNKNOWN": {"UNKNOWN"},
}

TAG_COORDINATE_RE = re.compile(
    r"^deedseal/deedseal@refs/tags/"
    r"(?P<tag>v[0-9]+\.[0-9]+\.[0-9]+)"
    r"(?::(?P<path>[A-Za-z0-9._/-]+))?$"
)
ISSUE_COORDINATE_RE = re.compile(
    r"^github-issue:deedseal/deedseal#(?P<number>[1-9][0-9]*)$"
)
RUN_COORDINATE_RE = re.compile(
    r"^github-actions-run:deedseal/deedseal#(?P<number>[1-9][0-9]*)$"
)
MUTABLE_SOURCE_RE = re.compile(
    r"^/deedseal/deedseal/(?:blob|tree|commits)/(?:main|master|HEAD)(?:/|$)"
)
ENTRY_MARKER_RE = re.compile(
    r"<!-- journal-entry: (PBJ-[0-9]{4}) \| ([A-Z_]+) \| ([A-Z_]+) -->"
)
STATUS_VOCABULARY_LINE = (
    "<!-- journal-status-vocabulary: " + " | ".join(STATUSES) + " -->"
)
EVIDENCE_VOCABULARY_LINE = (
    "<!-- journal-evidence-vocabulary: "
    + " | ".join(EVIDENCE_GRADES)
    + " -->"
)


class JournalError(RuntimeError):
    """One journal invariant did not hold."""


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JournalError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise JournalError(f"{path.relative_to(ROOT)}: unreadable JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise JournalError(f"{path.relative_to(ROOT)}: root must be an object")
    return value


def parse_observed_at(value: str, label: str) -> None:
    try:
        if "T" in value:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        else:
            date.fromisoformat(value)
    except ValueError as exc:
        raise JournalError(f"{label}: invalid observed_at") from exc


def public_source_parts(url: str, label: str) -> parse.ParseResult:
    parsed = parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or not parsed.path.startswith("/deedseal/deedseal/")
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise JournalError(f"{label}: source URL is not in the public repository")
    if MUTABLE_SOURCE_RE.match(parsed.path):
        raise JournalError(f"{label}: mutable branch URL cannot be evidence")
    return parsed


def validate_coordinate(entry: dict[str, Any]) -> None:
    label = entry["entry_id"]
    coordinate = entry["immutable_coordinate"]
    parsed = public_source_parts(entry["source_url"], label)

    tag_match = TAG_COORDINATE_RE.fullmatch(coordinate)
    issue_match = ISSUE_COORDINATE_RE.fullmatch(coordinate)
    run_match = RUN_COORDINATE_RE.fullmatch(coordinate)
    if tag_match:
        tag = tag_match.group("tag")
        coordinate_path = tag_match.group("path")
        if coordinate_path is not None:
            expected = f"/deedseal/deedseal/blob/{tag}/{coordinate_path}"
            if parsed.path != expected:
                raise JournalError(
                    f"{label}: tag path and source URL do not identify the same object"
                )
        else:
            accepted_roots = {
                f"/deedseal/deedseal/tree/{tag}",
                f"/deedseal/deedseal/commits/{tag}",
                f"/deedseal/deedseal/releases/tag/{tag}",
            }
            if parsed.path not in accepted_roots:
                raise JournalError(
                    f"{label}: tag coordinate and source URL do not identify the same object"
                )
    elif issue_match:
        expected = f"/deedseal/deedseal/issues/{issue_match.group('number')}"
        if parsed.path.rstrip("/") != expected:
            raise JournalError(f"{label}: Issue coordinate and source URL differ")
        if entry["status"] == "PROVED":
            raise JournalError(f"{label}: a mutable Issue cannot support PROVED")
    elif run_match:
        expected = f"/deedseal/deedseal/actions/runs/{run_match.group('number')}"
        if parsed.path.rstrip("/") != expected:
            raise JournalError(f"{label}: Actions-run coordinate and source URL differ")
        if entry["status"] == "PROVED":
            raise JournalError(
                f"{label}: a workflow run alone cannot promote an entry to PROVED"
            )
    else:  # The schema should make this unreachable; retain a fail-closed check.
        raise JournalError(f"{label}: unrecognized immutable coordinate")

    if entry["status"] == "PROVED" and tag_match is None:
        raise JournalError(f"{label}: PROVED requires a protected immutable tag coordinate")


def validate_supersession(entries: list[dict[str, Any]]) -> None:
    identifiers = {entry["entry_id"] for entry in entries}
    graph: dict[str, list[str]] = {}
    for entry in entries:
        entry_id = entry["entry_id"]
        targets = entry["supersedes"]
        for target in targets:
            if target not in identifiers:
                raise JournalError(f"{entry_id}: supersedes unknown entry {target}")
            if target == entry_id:
                raise JournalError(f"{entry_id}: cannot supersede itself")
        graph[entry_id] = targets

    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(entry_id: str) -> None:
        if entry_id in visiting:
            raise JournalError(f"{entry_id}: supersession cycle")
        if entry_id in visited:
            return
        visiting.add(entry_id)
        for target in graph[entry_id]:
            walk(target)
        visiting.remove(entry_id)
        visited.add(entry_id)

    for entry_id in graph:
        walk(entry_id)


def markers_for_view(path: Path, entries: list[dict[str, Any]]) -> None:
    text = path.read_text(encoding="utf-8")
    relative = path.relative_to(ROOT)
    if text.count(STATUS_VOCABULARY_LINE) != 1:
        raise JournalError(f"{relative}: status vocabulary marker differs from schema")
    if text.count(EVIDENCE_VOCABULARY_LINE) != 1:
        raise JournalError(f"{relative}: evidence vocabulary marker differs from schema")

    markers = ENTRY_MARKER_RE.findall(text)
    observed: dict[str, tuple[str, str]] = {}
    for entry_id, status, grade in markers:
        if entry_id in observed:
            raise JournalError(f"{relative}: duplicate marker for {entry_id}")
        observed[entry_id] = (status, grade)

    expected = {
        entry["entry_id"]: (entry["status"], entry["evidence_grade"])
        for entry in entries
    }
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        changed = sorted(
            entry_id
            for entry_id in set(expected) & set(observed)
            if expected[entry_id] != observed[entry_id]
        )
        raise JournalError(
            f"{relative}: journal markers differ: missing={missing} "
            f"extra={extra} changed={changed}"
        )
    for entry in entries:
        if entry["title"] not in text:
            raise JournalError(
                f"{relative}: title missing for {entry['entry_id']}"
            )


def check_source_url(url: str) -> None:
    headers = {
        "Accept": "text/html,application/xhtml+xml",
        "User-Agent": "deedseal-public-build-journal-check/1",
    }
    head = request.Request(url, headers=headers, method="HEAD")
    try:
        with request.urlopen(head, timeout=20) as response:
            if not 200 <= response.status < 400:
                raise JournalError(f"source URL returned HTTP {response.status}: {url}")
            return
    except error.HTTPError as exc:
        if exc.code != 405:
            raise JournalError(f"source URL returned HTTP {exc.code}: {url}") from exc
    except error.URLError as exc:
        raise JournalError(f"source URL is unreachable: {url}: {exc.reason}") from exc

    get = request.Request(url, headers=headers, method="GET")
    try:
        with request.urlopen(get, timeout=20) as response:
            if not 200 <= response.status < 400:
                raise JournalError(f"source URL returned HTTP {response.status}: {url}")
    except (error.HTTPError, error.URLError) as exc:
        raise JournalError(f"source URL is unreachable: {url}: {exc}") from exc


def validate_journal(
    schema: dict[str, Any],
    journal: dict[str, Any],
    *,
    check_docs: bool,
    check_urls: bool,
) -> list[dict[str, Any]]:
    public_gate.validate_against_schema(journal, schema, schema, "journal")
    entries_value = journal["entries"]
    if not isinstance(entries_value, list):  # Schema already checks; helps typing.
        raise JournalError("journal.entries: expected an array")
    entries = entries_value

    identifiers = [entry["entry_id"] for entry in entries]
    if len(identifiers) != len(set(identifiers)):
        raise JournalError("journal.entries: duplicate entry_id")

    for entry in entries:
        entry_id = entry["entry_id"]
        status = entry["status"]
        grade = entry["evidence_grade"]
        if grade not in ALLOWED_GRADES[status]:
            raise JournalError(
                f"{entry_id}: status {status} is incompatible with evidence grade {grade}"
            )
        parse_observed_at(entry["observed_at"], entry_id)
        validate_coordinate(entry)

    validate_supersession(entries)
    if check_docs:
        for path in HUMAN_VIEWS:
            markers_for_view(path, entries)
    if check_urls:
        for url in sorted({entry["source_url"] for entry in entries}):
            check_source_url(url)
    return entries


def expect_refusal(
    name: str,
    schema: dict[str, Any],
    candidate: dict[str, Any],
    expected: str,
) -> None:
    try:
        validate_journal(schema, candidate, check_docs=False, check_urls=False)
    except (JournalError, public_gate.ValidationError) as exc:
        message = str(exc)
        if expected not in message:
            raise JournalError(
                f"hostile {name}: refused for the wrong reason: {message}"
            ) from exc
        print(f"HOSTILE_REFUSAL: PASS {name}: {message}")
        return
    raise JournalError(f"hostile {name}: accepted")


def run_hostile_tests(schema: dict[str, Any], journal: dict[str, Any]) -> None:
    missing_source = copy.deepcopy(journal)
    missing_source["entries"][0].pop("source_url")
    expect_refusal("missing-source", schema, missing_source, "schema-required")

    mutable_coordinate = copy.deepcopy(journal)
    mutable_coordinate["entries"][0]["source_url"] = (
        "https://github.com/deedseal/deedseal/blob/main/evidence/README.md"
    )
    expect_refusal(
        "mutable-coordinate", schema, mutable_coordinate, "mutable branch URL"
    )

    promoted_proposal = copy.deepcopy(journal)
    proposal = next(
        entry
        for entry in promoted_proposal["entries"]
        if entry["evidence_grade"] == "PUBLIC_PROPOSAL"
    )
    proposal["status"] = "PROVED"
    expect_refusal(
        "illegal-proved-promotion", schema, promoted_proposal, "incompatible"
    )

    unknown_status = copy.deepcopy(journal)
    unknown_status["entries"][0]["status"] = "SHIPPED"
    expect_refusal("unknown-status", schema, unknown_status, "outside schema enum")

    duplicate_id = copy.deepcopy(journal)
    duplicate_id["entries"].append(copy.deepcopy(duplicate_id["entries"][0]))
    expect_refusal("duplicate-id", schema, duplicate_id, "duplicate entry_id")

    private_url = copy.deepcopy(journal)
    private_url["entries"][0]["source_url"] = (
        "https://github." + "com/" + "private-owner/private-repository/issues/1"
    )
    expect_refusal(
        "private-url", schema, private_url, "does not match schema pattern"
    )
    print("PUBLIC_BUILD_JOURNAL_HOSTILE: PASS 6/6")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check-urls",
        action="store_true",
        help="perform anonymous reachability checks for every unique source URL",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="also require all six hostile fixtures to be refused",
    )
    args = parser.parse_args(argv)

    try:
        schema = load_json(SCHEMA_PATH)
        public_gate.validate_schema_definition(schema, str(SCHEMA_PATH.relative_to(ROOT)))
        journal = load_json(JOURNAL_PATH)
        entries = validate_journal(
            schema,
            journal,
            check_docs=True,
            check_urls=args.check_urls,
        )
        if args.self_test:
            run_hostile_tests(schema, journal)
    except (JournalError, public_gate.ValidationError, OSError) as exc:
        print(f"PUBLIC_BUILD_JOURNAL: FAIL: {exc}", file=sys.stderr)
        return 1

    counts = {status: 0 for status in STATUSES}
    for entry in entries:
        counts[entry["status"]] += 1
    rendered_counts = ",".join(f"{status}:{counts[status]}" for status in STATUSES)
    print(
        f"PUBLIC_BUILD_JOURNAL: PASS entries={len(entries)} statuses={rendered_counts}"
    )
    if args.check_urls:
        print(
            "PUBLIC_BUILD_JOURNAL_URLS: PASS "
            f"checked={len({entry['source_url'] for entry in entries})}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
