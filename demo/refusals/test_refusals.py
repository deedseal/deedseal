#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproduce the public verifier's reachable refusal verdicts.

Every structured case begins with a fresh copy of the published passport. The
copy is written under a temporary directory; the published artifact is never
modified. No network or third-party package is used.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPO_ROOT / "tools" / "verify_run_passport.py"
PASSPORT = REPO_ROOT / "examples" / "verified" / "run-passport.json"
MANIFEST = REPO_ROOT / "examples" / "verified" / "conformance" / "manifest.json"
VERDICT_PREFIX = "RUN_PASSPORT_VERDICT: BLOCK "
sys.path.insert(0, str(REPO_ROOT / "tools"))

import check_conformance

Mutation = Callable[[dict[str, Any]], object]


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def unchanged(passport: dict[str, Any]) -> object:
    return passport


def non_json(_passport: dict[str, Any]) -> object:
    return b"this is not json"


def empty_file(_passport: dict[str, Any]) -> object:
    return b""


def truncated(passport: dict[str, Any]) -> object:
    return canonical_bytes(passport)[:-1]


def duplicate_json_key(passport: dict[str, Any]) -> object:
    serialized = canonical_bytes(passport)
    return b'{"run_id":"duplicate",' + serialized[1:]


def trailing_json(passport: dict[str, Any]) -> object:
    return canonical_bytes(passport) + b"{}"


def whitespace_only_reserialization(passport: dict[str, Any]) -> object:
    return canonical_bytes(passport) + b"\n"


def not_an_object(_passport: dict[str, Any]) -> object:
    return []


def unknown_top_level_field(passport: dict[str, Any]) -> object:
    passport["unexpected"] = True
    return passport


def missing_top_level_field(passport: dict[str, Any]) -> object:
    del passport["roadmap_step"]
    return passport


def unsupported_schema(passport: dict[str, Any]) -> object:
    passport["schema_version"] = "deedseal-run-passport/unknown"
    return passport


def malformed_section(passport: dict[str, Any]) -> object:
    passport["scope"] = []
    return passport


def missing_owner_signature(passport: dict[str, Any]) -> object:
    del passport["authorization"]["owner_signature"]
    return passport


def swapped_owner_key(passport: dict[str, Any]) -> object:
    passport["authorization"]["owner_signature"]["signing_key_id"] = "unknown-owner"
    return passport


def altered_owner_signature(passport: dict[str, Any]) -> object:
    passport["authorization"]["owner_signature"]["signature_hex"] = "0" * 128
    return passport


def widened_signed_allowed_files(passport: dict[str, Any]) -> object:
    passport["authorization"]["allowed_files"].append("second-file.txt")
    return passport


def unsupported_custody_schema(passport: dict[str, Any]) -> object:
    passport["custody"]["record_schema"] = "deedseal-custody/unknown"
    return passport


def malformed_custody_signature(passport: dict[str, Any]) -> object:
    passport["custody"]["signature"]["unexpected"] = True
    return passport


def swapped_custody_key(passport: dict[str, Any]) -> object:
    passport["custody"]["signature"]["signing_key_id"] = "unknown-custody"
    return passport


def altered_custody_signature(passport: dict[str, Any]) -> object:
    passport["custody"]["signature"]["signature_hex"] = "0" * 128
    return passport


def changed_roadmap_step(passport: dict[str, Any]) -> object:
    passport["roadmap_step"] = "deedseal-public-run/other"
    return passport


def unknown_owner_signature_field(passport: dict[str, Any]) -> object:
    passport["authorization"]["owner_signature"]["unexpected"] = True
    return passport


def changed_run_id(passport: dict[str, Any]) -> object:
    passport["run_id"] = "different-run"
    return passport


def changed_execution_id(passport: dict[str, Any]) -> object:
    passport["execution_id"] = "0" * 32
    return passport


def changed_implementation_head(passport: dict[str, Any]) -> object:
    passport["implementation_head_sha"] = "0" * 40
    return passport


def second_file_added_to_scope(passport: dict[str, Any]) -> object:
    passport["scope"]["allowed_files"].append("second-file.txt")
    return passport


def changed_new_files(passport: dict[str, Any]) -> object:
    passport["scope"]["new_files"].append("second-file.txt")
    return passport


def changed_acceptance_contract(passport: dict[str, Any]) -> object:
    passport["scope"]["acceptance_contract"]["expected_changed_paths"].append(
        "second-file.txt"
    )
    return passport


def changed_observed_paths(passport: dict[str, Any]) -> object:
    passport["execution"]["observed_post_worktree_entries"].append("second-file.txt")
    return passport


def changed_sha_chain(passport: dict[str, Any]) -> object:
    passport["execution"]["sha256_chain"]["second-file.txt"] = {}
    return passport


def changed_committed_digest(passport: dict[str, Any]) -> object:
    hashes = passport["committed_binding"]["committed_file_hashes"]
    only_path = next(iter(hashes))
    hashes[only_path] = "0" * 64
    return passport


def malformed_commit_sha(passport: dict[str, Any]) -> object:
    passport["committed_binding"]["commit_identity"]["commit_sha"] = "not-a-sha"
    return passport


def changed_parent_sha(passport: dict[str, Any]) -> object:
    passport["committed_binding"]["commit_identity"]["parent_sha"] = "0" * 40
    return passport


def widened_changed_paths(passport: dict[str, Any]) -> object:
    passport["committed_binding"]["changed_paths"].append("second-file.txt")
    return passport


def cargo_commit_equals_parent(passport: dict[str, Any]) -> object:
    identity = passport["committed_binding"]["commit_identity"]
    identity["commit_sha"] = identity["parent_sha"]
    return passport


def changed_commit_sha(passport: dict[str, Any]) -> object:
    passport["committed_binding"]["commit_identity"]["commit_sha"] = "0" * 40
    return passport


def stripped_closure_signature(passport: dict[str, Any]) -> object:
    del passport["closure"]["signature"]
    return passport


def unknown_closure_field(passport: dict[str, Any]) -> object:
    passport["closure"]["unexpected"] = True
    return passport


def malformed_closure_signature(passport: dict[str, Any]) -> object:
    passport["closure"]["signature"]["signature_hex"] = "not-a-signature"
    return passport


def swapped_closure_key(passport: dict[str, Any]) -> object:
    passport["closure"]["signature"]["signing_key_id"] = "unknown-owner"
    return passport


def altered_closure_signature(passport: dict[str, Any]) -> object:
    passport["closure"]["signature"]["signature_hex"] = "0" * 128
    return passport


def removed_os_boundary(passport: dict[str, Any]) -> object:
    del passport["custody"]["runner_report"]["os_boundary"]
    return passport


def emptied_boundary_rules(passport: dict[str, Any]) -> object:
    passport["custody"]["runner_report"]["os_boundary"]["rules"] = []
    return passport


def extra_boundary_rule(passport: dict[str, Any]) -> object:
    rules = passport["custody"]["runner_report"]["os_boundary"]["rules"]
    rules.append(copy.deepcopy(rules[0]))
    return passport


def widened_runtime_scratch_rights(passport: dict[str, Any]) -> object:
    scratch = passport["custody"]["runner_report"]["os_boundary"]["runtime_scratch"]
    scratch["allowed_access_fs"].append("remove_file")
    return passport


def changed_scratch_root_digest(passport: dict[str, Any]) -> object:
    scratch = passport["custody"]["runner_report"]["os_boundary"]["runtime_scratch"]
    scratch["scratch_root_sha256"] = "0" * 64
    return passport


CASES: list[dict[str, object]] = [
    {
        "name": "non-json-input",
        "why": "Text that is not JSON cannot be a passport.",
        "mutate": non_json,
        "expect": "block_run_passport_unparseable",
    },
    {
        "name": "empty-file",
        "why": "An empty file contains no passport object.",
        "mutate": empty_file,
        "expect": "block_run_passport_unparseable",
    },
    {
        "name": "truncated-file",
        "why": "A passport cut off before its closing brace is incomplete JSON.",
        "mutate": truncated,
        "expect": "block_run_passport_unparseable",
    },
    {
        "name": "duplicate-json-key",
        "why": "A duplicate key would make the passport ambiguous.",
        "mutate": duplicate_json_key,
        "expect": "block_run_passport_duplicate_key",
    },
    {
        "name": "trailing-json-value",
        "why": "A second JSON value after the passport is trailing content.",
        "mutate": trailing_json,
        "expect": "block_run_passport_trailing_content",
    },
    {
        "name": "array-instead-of-object",
        "why": "The passport envelope must be a JSON object.",
        "mutate": not_an_object,
        "expect": "block_run_passport_not_object",
    },
    {
        "name": "unknown-top-level-field",
        "why": "An undeclared envelope field has no defined meaning.",
        "mutate": unknown_top_level_field,
        "expect": "block_run_passport_unknown_field",
    },
    {
        "name": "missing-top-level-field",
        "why": "A required envelope field cannot be omitted.",
        "mutate": missing_top_level_field,
        "expect": "block_run_passport_missing_field",
    },
    {
        "name": "unsupported-schema",
        "why": "The verifier only interprets its declared passport schema.",
        "mutate": unsupported_schema,
        "expect": "block_run_passport_schema_unsupported",
    },
    {
        "name": "malformed-section",
        "why": "A passport section cannot be replaced by a value of another type.",
        "mutate": malformed_section,
        "expect": "block_run_passport_malformed_section",
    },
    {
        "name": "whitespace-only-reserialization",
        "why": "Equivalent JSON text is still different from the required canonical bytes.",
        "mutate": whitespace_only_reserialization,
        "expect": "block_public_run_passport_noncanonical_serialization",
    },
    {
        "name": "missing-owner-signature",
        "why": "An authorization without an owner signature is not an authorization.",
        "mutate": missing_owner_signature,
        "expect": "block_owner_authorization_malformed",
    },
    {
        "name": "swapped-owner-signing-key-id",
        "why": "The authorization must name a pinned owner key.",
        "mutate": swapped_owner_key,
        "expect": "block_owner_authorization_wrong_key",
    },
    {
        "name": "altered-owner-signature",
        "why": "An altered authorization signature no longer authenticates its fields.",
        "mutate": altered_owner_signature,
        "expect": "block_owner_authorization_signature_invalid",
    },
    {
        "name": "widened-allowed-files",
        "why": "Adding a file to the signed grant changes what the owner authorized.",
        "mutate": widened_signed_allowed_files,
        "expect": "block_owner_authorization_signature_invalid",
    },
    {
        "name": "unsupported-custody-schema",
        "why": "The verifier cannot interpret an undeclared custody schema.",
        "mutate": unsupported_custody_schema,
        "expect": "block_custody_record_schema_unsupported",
    },
    {
        "name": "unknown-custody-signature-field",
        "why": "The custody signature object has a closed field set.",
        "mutate": malformed_custody_signature,
        "expect": "block_custody_record_malformed",
    },
    {
        "name": "swapped-custody-signing-key-id",
        "why": "The custody record must name the pinned custody key.",
        "mutate": swapped_custody_key,
        "expect": "block_custody_record_wrong_key",
    },
    {
        "name": "altered-custody-signature",
        "why": "An altered custody signature no longer authenticates the record.",
        "mutate": altered_custody_signature,
        "expect": "block_custody_record_signature_invalid",
    },
    {
        "name": "changed-roadmap-step",
        "why": "The envelope roadmap step must equal the signed custody step.",
        "mutate": changed_roadmap_step,
        "expect": "block_custody_publication_contract_malformed",
    },
    {
        "name": "unknown-field-inside-signed-sub-object",
        "why": "An extra owner-signature field changes the grant digest bound by custody.",
        "mutate": unknown_owner_signature_field,
        "expect": "block_grant_custody_binding_mismatch",
    },
    {
        "name": "changed-run-id",
        "why": "The envelope run identifier must equal the signed identifiers.",
        "mutate": changed_run_id,
        "expect": "block_run_id_binding_mismatch",
    },
    {
        "name": "changed-execution-id",
        "why": "The envelope execution identifier must equal the custody identifier.",
        "mutate": changed_execution_id,
        "expect": "block_execution_id_binding_mismatch",
    },
    {
        "name": "changed-implementation-head",
        "why": "The envelope head must equal every signed head observation.",
        "mutate": changed_implementation_head,
        "expect": "block_implementation_head_binding_mismatch",
    },
    {
        "name": "second-file-added-to-scope",
        "why": "The visible scope cannot be wider than the signed file lists.",
        "mutate": second_file_added_to_scope,
        "expect": "block_allowed_files_binding_mismatch",
    },
    {
        "name": "changed-new-files",
        "why": "The new-file list must equal the owner-signed list.",
        "mutate": changed_new_files,
        "expect": "block_new_files_binding_mismatch",
    },
    {
        "name": "changed-acceptance-contract",
        "why": "The visible acceptance surface must equal the owner-signed contract.",
        "mutate": changed_acceptance_contract,
        "expect": "block_acceptance_contract_binding_mismatch",
    },
    {
        "name": "changed-observed-paths",
        "why": "Observed paths must equal the signed custody observations and scope.",
        "mutate": changed_observed_paths,
        "expect": "block_observed_paths_binding_mismatch",
    },
    {
        "name": "changed-sha-chain",
        "why": "The digest chain must cover exactly the authorized file set.",
        "mutate": changed_sha_chain,
        "expect": "block_sha256_chain_binding_mismatch",
    },
    {
        "name": "changed-committed-digest",
        "why": "The committed digest must equal the materialized file digest.",
        "mutate": changed_committed_digest,
        "expect": "block_committed_hash_binding_mismatch",
    },
    {
        "name": "malformed-commit-sha",
        "why": "A commit identity must contain correctly shaped commit identifiers.",
        "mutate": malformed_commit_sha,
        "expect": "block_commit_identity_binding_mismatch",
    },
    {
        "name": "changed-parent-sha",
        "why": "The cargo parent must equal the execution head.",
        "mutate": changed_parent_sha,
        "expect": "block_complete_cargo_changeset_binding_mismatch",
    },
    {
        "name": "widened-changed-path-set",
        "why": "The complete changed-path set cannot contain an unauthorized file.",
        "mutate": widened_changed_paths,
        "expect": "block_complete_cargo_changeset_binding_mismatch",
    },
    {
        "name": "cargo-commit-equals-parent",
        "why": "A claimed cargo commit must differ from its parent execution head.",
        "mutate": cargo_commit_equals_parent,
        "expect": "block_cargo_commit_equals_execution_head",
    },
    {
        "name": "changed-commit-sha",
        "why": "Changing a well-formed cargo commit changes the owner-closed passport.",
        "mutate": changed_commit_sha,
        "expect": "block_owner_closure_signature_invalid",
    },
    {
        "name": "stripped-closure-signature",
        "why": "A passport without its final owner signature is not closed.",
        "mutate": stripped_closure_signature,
        "expect": "block_owner_closure_signature_missing",
    },
    {
        "name": "unknown-closure-field",
        "why": "The owner closure has a closed field set.",
        "mutate": unknown_closure_field,
        "expect": "block_owner_closure_unknown_field",
    },
    {
        "name": "malformed-closure-signature",
        "why": "The closure signature must have the declared hexadecimal shape.",
        "mutate": malformed_closure_signature,
        "expect": "block_owner_closure_signature_malformed",
    },
    {
        "name": "swapped-closure-signing-key-id",
        "why": "The final closure must name the same pinned owner key as the grant.",
        "mutate": swapped_closure_key,
        "expect": "block_owner_closure_signature_wrong_key",
    },
    {
        "name": "altered-closure-signature",
        "why": "An altered closure signature no longer authenticates the assembled record.",
        "mutate": altered_closure_signature,
        "expect": "block_owner_closure_signature_invalid",
    },
    {
        "name": "removed-os-boundary",
        "why": "Removing the applied boundary changes the custody-signed record.",
        "mutate": removed_os_boundary,
        "expect": "block_custody_record_signature_invalid",
    },
    {
        "name": "emptied-boundary-rules",
        "why": "Removing every boundary rule changes the custody-signed record.",
        "mutate": emptied_boundary_rules,
        "expect": "block_custody_record_signature_invalid",
    },
    {
        "name": "extra-boundary-rule",
        "why": "Adding a boundary rule changes the custody-signed record.",
        "mutate": extra_boundary_rule,
        "expect": "block_custody_record_signature_invalid",
    },
    {
        "name": "widened-runtime-scratch-rights",
        "why": "Adding a scratch right changes the custody-signed boundary.",
        "mutate": widened_runtime_scratch_rights,
        "expect": "block_custody_record_signature_invalid",
    },
    {
        "name": "changed-scratch-root-digest",
        "why": "Changing the scratch root identity changes the custody-signed boundary.",
        "mutate": changed_scratch_root_digest,
        "expect": "block_custody_record_signature_invalid",
    },
    {
        "name": "directory-instead-of-file",
        "why": "A directory cannot supply passport bytes.",
        "mutate": unchanged,
        "expect": "passport_unreadable",
        "path_kind": "directory",
    },
    {
        "name": "path-does-not-exist",
        "why": "A missing path cannot supply passport bytes.",
        "mutate": unchanged,
        "expect": "passport_unreadable",
        "path_kind": "missing",
    },
]


def _materialize_case(
    case: dict[str, object], base: dict[str, Any], directory: Path, index: int
) -> Path:
    path = directory / f"case-{index}.json"
    path_kind = case.get("path_kind", "file")
    if path_kind == "directory":
        path.mkdir()
        return path
    if path_kind == "missing":
        return path
    if path_kind != "file":
        raise ValueError(f"unknown path kind {path_kind!r}")

    mutate = case["mutate"]
    if not callable(mutate):
        raise TypeError("case mutation is not callable")
    mutated = mutate(copy.deepcopy(base))
    serialized = mutated if isinstance(mutated, bytes) else canonical_bytes(mutated)
    path.write_bytes(serialized)
    return path


def _expected_verdict(case: dict[str, object], path: Path) -> str:
    reason = case["expect"]
    if reason != "passport_unreadable":
        return VERDICT_PREFIX + str(reason)
    try:
        with open(path, "rb") as handle:
            handle.read()
    except OSError as exc:
        return VERDICT_PREFIX + f"passport_unreadable ({exc})"
    raise AssertionError("unreadable-path case was readable")


def _verdict_lines(completed: subprocess.CompletedProcess[str]) -> list[str]:
    return [
        line.strip()
        for stream in (completed.stdout, completed.stderr)
        for line in stream.splitlines()
        if line.strip().startswith("RUN_PASSPORT_VERDICT:")
    ]


def evaluate_cases() -> list[dict[str, object]]:
    """Read the generated manifest; do not maintain a second expectation list."""

    manifest = check_conformance.load_manifest(MANIFEST)
    by_id = {str(vector["id"]): vector for vector in manifest["vectors"]}
    expected_ids = {str(case["name"]) for case in CASES}
    if set(by_id) - {"valid-published-passport"} != expected_ids:
        raise check_conformance.ConformanceError(
            "manifest refusal vector ids differ from corpus case ids"
        )
    evaluated = {
        str(result["id"]): result
        for result in check_conformance.evaluate_manifest(MANIFEST)
    }
    results: list[dict[str, object]] = []
    for case in CASES:
        name = str(case["name"])
        vector = by_id[name]
        observed = evaluated[name]
        results.append(
            {
                "name": name,
                "expect_reason": vector.get("expect_reason", "passport_unreadable"),
                "expected": vector.get("expect_reason", "passport_unreadable"),
                "observed": observed["observed"],
                "returncode": observed["returncode"],
                "passed": observed["passed"],
            }
        )
    return results


def main() -> int:
    if not VERIFIER.is_file() or not PASSPORT.is_file() or not MANIFEST.is_file():
        print("REFUSAL_CORPUS: FAIL required verifier, passport, or manifest is missing")
        return 1
    try:
        results = evaluate_cases()
    except check_conformance.ConformanceError as exc:
        print(f"REFUSAL_CORPUS: FAIL {exc}")
        return 1
    failures = 0
    for result in results:
        status = "PASS" if result["passed"] else "FAIL"
        print(
            f"{result['name']}: {status} exit {result['returncode']} "
            f"{result['observed']}"
        )
        if not result["passed"]:
            failures += 1
            print(f"  expected: exit 1 {result['expected']}")
    if failures:
        print(f"REFUSAL_CORPUS: FAIL {failures} of {len(results)} cases failed")
        return 1
    demonstrated = {
        str(result["expect_reason"])
        for result in results
        if str(result["expect_reason"]).startswith("block_")
    }
    print(
        f"REFUSAL_CORPUS: PASS {len(results)} cases; "
        f"{len(demonstrated)} declared reasons demonstrated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
