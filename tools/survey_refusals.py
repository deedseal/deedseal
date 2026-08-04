#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare declared verifier refusals with the public mutation corpus."""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "tools" / "verify_run_passport.py"
CORPUS = REPO_ROOT / "demo" / "refusals" / "test_refusals.py"

# These paths need a differently signed owner grant or custody record. The last
# value is a signed custody failure reason declared by the source but is not a
# verdict returned by the passport verifier.
NOT_REACHABLE_BY_PUBLISHED_MUTATION = {
    "block_custody_outcome_not_success",
    "block_grant_id_binding_mismatch",
    "block_public_run_passport_contract_malformed",
    "block_supervised_agent_capture_failed",
}


def declared_reasons() -> set[str]:
    tree = ast.parse(VERIFIER.read_text(encoding="utf-8"), filename=str(VERIFIER))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("block_")
    }


def load_corpus() -> ModuleType:
    spec = importlib.util.spec_from_file_location("deedseal_refusal_corpus", CORPUS)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the refusal corpus")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if not VERIFIER.is_file() or not CORPUS.is_file():
        print("REFUSAL_SURVEY: FAIL required verifier or corpus is missing")
        return 1

    declared = declared_reasons()
    corpus = load_corpus()
    results = corpus.evaluate_cases()
    claimed = {
        str(case["expect"])
        for case in corpus.CASES
        if str(case["expect"]).startswith("block_")
    }
    produced = {
        str(result["expect_reason"])
        for result in results
        if result["passed"]
        and result["observed"]
        == "RUN_PASSPORT_VERDICT: BLOCK " + str(result["expect_reason"])
    }

    errors: list[str] = []
    failed_cases = [str(result["name"]) for result in results if not result["passed"]]
    if failed_cases:
        errors.append(f"corpus cases failed: {failed_cases}")
    missing_proof = claimed - produced
    if missing_proof:
        errors.append(f"claimed reasons not produced: {sorted(missing_proof)}")
    undeclared_claims = claimed - declared
    if undeclared_claims:
        errors.append(f"corpus claims undeclared reasons: {sorted(undeclared_claims)}")
    classification = claimed | NOT_REACHABLE_BY_PUBLISHED_MUTATION
    if classification != declared:
        errors.append(
            "classification does not equal parsed declarations: "
            f"missing {sorted(declared - classification)}, "
            f"extra {sorted(classification - declared)}"
        )

    for reason in sorted(declared):
        status = (
            "demonstrated"
            if reason in produced
            else "not reachable by published-byte mutation"
        )
        print(f"{reason}: {status}")

    if errors:
        for error in errors:
            print(f"REFUSAL_SURVEY_ERROR: {error}")
        print("REFUSAL_SURVEY: FAIL")
        return 1

    print(f"declared refusal reasons: {len(declared)}")
    print(f"demonstrated refusal reasons: {len(produced)}")
    print(
        "not reachable by published-byte mutation: "
        f"{len(NOT_REACHABLE_BY_PUBLISHED_MUTATION)}"
    )
    print(
        f"REFUSAL_SURVEY: PASS {len(declared)} declared; {len(produced)} demonstrated; "
        f"{len(NOT_REACHABLE_BY_PUBLISHED_MUTATION)} not reachable by mutation"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
