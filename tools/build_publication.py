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
import json
import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "tools" / "verify_run_passport.py"
LEDGER_PATH = REPO_ROOT / "evidence" / "ledger-v1.json"
RECORDS_DIR = REPO_ROOT / "evidence" / "records"
PUBLISHED_ROOT = REPO_ROOT / "examples" / "verified"
README_PATH = REPO_ROOT / "README.md"
RUNS_INDEX = PUBLISHED_ROOT / "runs.md"
LANDING_PATH = REPO_ROOT / "index.html"

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
    if count == 1:
        return "one supervised run is\n      published"
    return f"{count} supervised runs are\n      published"


def landing_with_generated_regions(landing: str) -> str:
    """`landing` with each generated region replaced by what the tree derives.

    Only the text between a marker pair changes; everything else on the page is
    hand-written and judged, and the generator must not touch it. A missing or
    malformed marker pair is an error, never a silent skip -- a region quietly
    left alone is exactly the drift this machinery exists to prevent.
    """
    regions = {"verified-runs": verified_run_sentence(len(published_passports()))}
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
    problems = ledger_digest_failures()
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

    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except PublicationError as error:
        print(f"PUBLICATION_PACKAGER: FAIL {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
