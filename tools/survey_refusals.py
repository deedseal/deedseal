#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare declared verifier refusals with the public mutation corpus."""

from __future__ import annotations

import ast
import importlib.util
import sys
from dataclasses import dataclass
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


@dataclass(frozen=True)
class RefusalCoverage:
    """One mechanically evaluated view of declared and demonstrated refusals."""

    declared: frozenset[str]
    demonstrated: frozenset[str]
    not_reachable: frozenset[str]
    failed_cases: tuple[str, ...]
    errors: tuple[str, ...]

    @property
    def counts(self) -> tuple[int, int, int]:
        return (
            len(self.declared),
            len(self.demonstrated),
            len(self.not_reachable),
        )


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


def evaluate_coverage() -> RefusalCoverage:
    """Evaluate the corpus once and return the exact refusal classification."""

    declared = declared_reasons()
    corpus = load_corpus()
    results = corpus.evaluate_cases()
    manifest = corpus.check_conformance.load_manifest(corpus.MANIFEST)
    claimed = {
        str(vector["expect_reason"])
        for vector in manifest["vectors"]
        if isinstance(vector, dict) and "expect_reason" in vector
    }
    demonstrated = {
        str(result["expect_reason"])
        for result in results
        if result["passed"]
        and result["observed"]
        == "RUN_PASSPORT_VERDICT: BLOCK " + str(result["expect_reason"])
    }

    errors: list[str] = []
    failed_cases = tuple(
        str(result["name"]) for result in results if not result["passed"]
    )
    if failed_cases:
        errors.append(f"corpus cases failed: {list(failed_cases)}")
    missing_proof = claimed - demonstrated
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

    return RefusalCoverage(
        declared=frozenset(declared),
        demonstrated=frozenset(demonstrated),
        not_reachable=frozenset(NOT_REACHABLE_BY_PUBLISHED_MUTATION),
        failed_cases=failed_cases,
        errors=tuple(errors),
    )


def main() -> int:
    if not VERIFIER.is_file() or not CORPUS.is_file():
        print("REFUSAL_SURVEY: FAIL required verifier or corpus is missing")
        return 1

    coverage = evaluate_coverage()

    for reason in sorted(coverage.declared):
        status = (
            "demonstrated"
            if reason in coverage.demonstrated
            else "not reachable by published-byte mutation"
        )
        print(f"{reason}: {status}")

    if coverage.errors:
        for error in coverage.errors:
            print(f"REFUSAL_SURVEY_ERROR: {error}")
        print("REFUSAL_SURVEY: FAIL")
        return 1

    declared_count, demonstrated_count, not_reachable_count = coverage.counts
    print(f"declared refusal reasons: {declared_count}")
    print(f"demonstrated refusal reasons: {demonstrated_count}")
    print(
        "not reachable by published-byte mutation: "
        f"{not_reachable_count}"
    )
    print(
        f"REFUSAL_SURVEY: PASS {declared_count} declared; "
        f"{demonstrated_count} demonstrated; "
        f"{not_reachable_count} not reachable by mutation"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
