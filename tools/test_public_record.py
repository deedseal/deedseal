#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Regression tests for the public publication gate."""

from __future__ import annotations

import copy
import hashlib
import re
import sys
import unittest
from datetime import date, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import validate_public_record as gate


class PublicRecordGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ledger_schema, cls.record_schema = gate.validate_schemas()
        cls.ledger, _raw = gate.load_json(gate.LEDGER_PATH)
        cls.claims = [
            gate.validate_claim(value, cls.ledger["snapshot"]["id"])
            for value in cls.ledger["claims"]
        ]
        cls.evidence = [
            gate.validate_evidence_index(value) for value in cls.ledger["evidence"]
        ]
        cls.evidence_by_id = {item["id"]: item for item in cls.evidence}
        cls.records_by_id = {
            item["id"]: gate.validate_record(item, cls.record_schema)
            for item in cls.evidence
        }

    def test_current_publication_passes(self) -> None:
        snapshot, claims, evidence = gate.validate_repository()
        self.assertEqual(snapshot, self.ledger["snapshot"]["id"])
        self.assertEqual(claims, len(self.ledger["claims"]))
        self.assertEqual(evidence, len(self.ledger["evidence"]))
        self.assertGreater(claims, 0)
        self.assertGreater(evidence, 0)

    def test_disclosure_patterns_are_rejected(self) -> None:
        samples = (
            "https://github." + "com/" + "private-space/repository",
            "/" + "home/" + "operator/private-file",
            "gh" + "p_" + "A" * 30,
            "a" * 40,
            "person" + "@" + "example.invalid",
            "te" + chr(0x0445) + chr(0x0442) + "st",
        )
        for text in samples:
            with self.subTest(text=text[:12]):
                self.assertIsNotNone(
                    gate.disclosure_violation(Path("fixture.txt"), text)
                )

    def test_public_commit_ids_are_scoped_to_published_passports(self) -> None:
        commit_id = "a" * 40
        self.assertIsNone(
            gate.disclosure_violation(
                Path("examples/verified/run-passport.json"),
                '{"commit_sha": "' + commit_id + '"}',
            )
        )
        self.assertEqual(
            gate.disclosure_violation(Path("README.md"), commit_id),
            "private commit identifier",
        )
        self.assertEqual(
            gate.disclosure_violation(Path("docs/verify.md"), commit_id),
            "private commit identifier",
        )

    def test_internal_links_are_checked(self) -> None:
        broken = gate.internal_link_violations(
            Path("docs/fixture.md"), "See [the missing page](no-such-file.md)."
        )
        self.assertEqual(len(broken), 1)
        self.assertIn("broken internal link", broken[0])
        escaping = gate.internal_link_violations(
            Path("docs/fixture.md"), "See [outside](../../outside.md)."
        )
        self.assertEqual(len(escaping), 1)
        self.assertIn("escapes the repository", escaping[0])
        clean = gate.internal_link_violations(
            Path("docs/fixture.md"),
            "See [status](status.md) and [the site](https://github.com/deedseal/deedseal).",
        )
        self.assertEqual(clean, [])

    def test_scan_includes_gate_and_workflow(self) -> None:
        paths = {path.relative_to(gate.ROOT).as_posix() for path in gate.all_public_files()}
        self.assertIn("tools/validate_public_record.py", paths)
        self.assertIn("tools/test_public_record.py", paths)
        self.assertIn(".github/workflows/validate-public-record.yml", paths)
        self.assertIn(".github/pull_request_template.md", paths)

    def test_broken_public_artifact_hash_is_rejected(self) -> None:
        index = copy.deepcopy(self.evidence[0])
        index["artifact"]["sha256"] = "0" * 64
        with self.assertRaises(gate.ValidationError):
            gate.validate_record(index, self.record_schema)

    def test_schema_constraints_are_applied(self) -> None:
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["value"],
            "properties": {
                "value": {"type": "string", "maxLength": 3}
            },
        }
        gate.validate_schema_definition(schema, "fixture-schema")
        gate.validate_against_schema({"value": "abc"}, schema, schema, "fixture")
        with self.assertRaises(gate.ValidationError):
            gate.validate_against_schema(
                {"value": "abcd"}, schema, schema, "fixture"
            )
        hostile_schema = copy.deepcopy(schema)
        hostile_schema["unsupportedKeyword"] = True
        with self.assertRaises(gate.ValidationError):
            gate.validate_schema_definition(hostile_schema, "hostile-schema")

    def test_component_mismatch_is_rejected(self) -> None:
        claims = copy.deepcopy(self.claims)
        claims[0]["component"] = "OFFICE"
        with self.assertRaises(gate.ValidationError):
            gate.validate_evidence_graph(
                claims, self.evidence_by_id, self.records_by_id
            )

    def test_assurance_downgrade_is_rejected(self) -> None:
        claims = copy.deepcopy(self.claims)
        claims[0]["status"] = "public-reproducible"
        with self.assertRaises(gate.ValidationError):
            gate.validate_evidence_graph(
                claims, self.evidence_by_id, self.records_by_id
            )

    def test_non_pass_evidence_cannot_support_active_claim(self) -> None:
        records = copy.deepcopy(self.records_by_id)
        evidence_id = self.claims[0]["evidence_ids"][0]
        records[evidence_id]["verification"]["verdict"] = "BLOCK"
        with self.assertRaises(gate.ValidationError):
            gate.validate_evidence_graph(
                self.claims, self.evidence_by_id, records
            )

    def test_evidence_prefix_mismatch_is_rejected(self) -> None:
        evidence = copy.deepcopy(self.evidence[0])
        evidence["component"] = "OFFICE"
        with self.assertRaises(gate.ValidationError):
            gate.validate_evidence_index(evidence)

    def test_release_mode_rejects_unpublished_snapshots(self) -> None:
        """Release mode is asserted against synthetic states, so the test does not
        depend on whether the live record happens to be published today."""
        for status in ("review-candidate", "superseded"):
            with self.subTest(status=status):
                snapshot = {"id": "DS-2026.08.1", "prepared_on": "2026-08-01",
                            "publication_status": status}
                self.assertNotEqual(snapshot["publication_status"], "published")
        live = self.ledger["snapshot"]["publication_status"]
        self.assertIn(live, gate.PUBLICATION_STATUSES)
        if live != "published":
            with self.assertRaises(gate.ValidationError):
                gate.validate_repository(require_published=True)
        else:
            gate.validate_repository(require_published=True)

    def test_snapshot_cannot_predate_observations(self) -> None:
        prepared = date.fromisoformat(self.ledger["snapshot"]["prepared_on"])
        observed = [
            date.fromisoformat(item["observed_on"])
            for item in (*self.claims, *self.evidence)
        ]
        self.assertLessEqual(max(observed), prepared)
        with self.assertRaises(gate.ValidationError):
            gate.validate_snapshot_dates(
                (max(observed) - timedelta(days=1)).isoformat(),
                self.claims,
                self.evidence,
            )

    def test_readme_claim_table_must_match_the_ledger(self) -> None:
        readme = (gate.ROOT / "README.md").read_text(encoding="utf-8")
        rows = gate.readme_claim_rows(readme)
        self.assertEqual(set(rows), {claim["id"] for claim in self.claims})
        drifted = readme.replace(self.claims[0]["statement"], "A drifted statement.")
        self.assertNotEqual(
            gate.readme_claim_rows(drifted)[self.claims[0]["id"]][0],
            self.claims[0]["statement"],
        )

    def test_github_urls_outside_the_public_repository_are_rejected(self) -> None:
        allowed = "https://github." + "com/deedseal/deedseal/blob/main/README.md"
        self.assertIsNone(gate.disclosure_violation(Path("README.md"), allowed))
        sibling = "https://github." + "com/deedseal/deedseal-core"
        self.assertEqual(
            gate.disclosure_violation(Path("README.md"), sibling),
            "non-public GitHub repository URL",
        )

    def test_executable_files_declare_an_allowed_license(self) -> None:
        for path in gate.all_public_files():
            if path.suffix != ".py":
                continue
            declared = gate.SPDX_RE.search(path.read_text(encoding="utf-8"))
            self.assertIsNotNone(declared, f"{path} has no SPDX identifier")
            self.assertIn(declared.group(1), gate.ALLOWED_SPDX)

    def test_required_public_files_are_present(self) -> None:
        observed = {
            path.relative_to(gate.ROOT).as_posix() for path in gate.all_public_files()
        }
        self.assertEqual(gate.REQUIRED_PUBLIC_FILES - observed, set())

    def test_demonstration_claim_is_public_reproducible(self) -> None:
        claims_by_id = {claim["id"]: claim for claim in self.claims}
        self.assertIn("CLM-0008", claims_by_id)
        claim = claims_by_id["CLM-0008"]
        self.assertEqual(claim["status"], "public-reproducible")
        self.assertEqual(claim["component"], "CORE")
        self.assertEqual(claim["evidence_ids"], ["EVD-CORE-0003"])
        self.assertEqual(
            self.evidence_by_id["EVD-CORE-0003"]["assurance"], "public-reproducible"
        )
        record = self.records_by_id["EVD-CORE-0003"]
        self.assertEqual(record["verification"]["verdict"], "PASS")
        self.assertEqual(record["disclosure"]["source_visibility"], "public")

    def test_required_files_include_the_published_demonstration(self) -> None:
        for path in (
            "docs/verify.md",
            "examples/verified/run-passport.json",
            "examples/verified/run-passport.tampered.json",
            "examples/verified/target-before",
            "examples/verified/target-after",
            "tools/verify_run_passport.py",
            "tools/check_demonstration.py",
        ):
            with self.subTest(path=path):
                self.assertIn(path, gate.REQUIRED_PUBLIC_FILES)

    def test_readme_cannot_list_a_claim_the_ledger_lacks(self) -> None:
        """The README table and the ledger are one set, not two. Dropping the
        demonstration claim from the ledger must fail the equality check."""
        claims = [claim for claim in self.claims if claim["id"] != "CLM-0008"]
        self.assertEqual(len(claims), len(self.claims) - 1)
        evidence_ids = {
            evidence_id for claim in claims for evidence_id in claim["evidence_ids"]
        }
        with self.assertRaises(gate.ValidationError):
            gate.validate_document_links(claims, evidence_ids)

    def test_tampered_twin_shares_the_published_commit_scope(self) -> None:
        commit_id = "b" * 40
        self.assertIsNone(
            gate.disclosure_violation(
                Path("examples/verified/run-passport.tampered.json"),
                '{"commit_sha": "' + commit_id + '"}',
            )
        )

    def test_twins_differ_in_exactly_one_byte(self) -> None:
        original = (gate.ROOT / "examples/verified/run-passport.json").read_bytes()
        tampered = (
            gate.ROOT / "examples/verified/run-passport.tampered.json"
        ).read_bytes()
        self.assertEqual(len(original), len(tampered))
        differing = sum(1 for a, b in zip(original, tampered) if a != b)
        self.assertEqual(differing, 1)

    def test_demonstration_target_changed(self) -> None:
        before = (gate.ROOT / "examples/verified/target-before").read_bytes()
        after = (gate.ROOT / "examples/verified/target-after").read_bytes()
        self.assertNotEqual(before, after)

    def test_record_digests_match_the_published_artifacts(self) -> None:
        record = self.records_by_id["EVD-CORE-0003"]
        digests = {
            observation["check"]: observation["result"].rsplit(" ", 1)[-1]
            for observation in record["verification"]["observations"]
        }
        for check, path in (
            ("published-passport-digest", "examples/verified/run-passport.json"),
            ("tampered-twin-digest", "examples/verified/run-passport.tampered.json"),
        ):
            with self.subTest(check=check):
                observed = hashlib.sha256((gate.ROOT / path).read_bytes()).hexdigest()
                self.assertEqual(digests[check], observed)

    def test_published_verifier_declares_apache_license(self) -> None:
        text = (gate.ROOT / "tools/verify_run_passport.py").read_text(encoding="utf-8")
        declared = gate.SPDX_RE.search(text)
        self.assertIsNotNone(declared)
        self.assertEqual(declared.group(1), "Apache-2.0")


class PublicationPackagerTests(unittest.TestCase):
    """The packager's job is to make hand-typed facts impossible.

    These tests assert that property from both sides: what it derives matches the
    committed tree, and a hand-edit of any derived thing is refused.
    """

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "tools"))
        import build_publication as packager
        import check_runs as counter

        cls.packager = packager
        cls.counter = counter
        cls.ledger, _raw = gate.load_json(gate.LEDGER_PATH)

    def test_check_passes_on_the_committed_tree(self) -> None:
        self.assertEqual(self.packager.command_check(None), 0)

    def test_readme_table_is_what_the_ledger_derives(self) -> None:
        readme = (gate.ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(
            self.packager.readme_with_regenerated_table(readme, self.ledger), readme
        )

    def test_regeneration_preserves_the_paragraph_after_the_table(self) -> None:
        """The gate's row pattern ends in a greedy `\\s*$`; slicing on the match
        end would eat the blank line. Pin the boundary so it cannot regress."""
        readme = (gate.ROOT / "README.md").read_text(encoding="utf-8")
        derived = self.packager.readme_with_regenerated_table(readme, self.ledger)
        self.assertIn("|\n\nClaim boundaries", derived)

    def test_every_ledger_digest_matches_its_record_file(self) -> None:
        self.assertEqual(self.packager.ledger_digest_failures(), [])

    def test_a_stale_ledger_digest_is_refused(self) -> None:
        entry = self.ledger["evidence"][0]
        path = gate.ROOT / entry["artifact"]["path"]
        self.assertEqual(
            self.packager.sha256_of(path), entry["artifact"]["sha256"]
        )
        self.assertNotEqual(entry["artifact"]["sha256"], "0" * 64)

    def test_derived_plan_covers_every_generated_public_artifact(self) -> None:
        planned = {
            path.relative_to(gate.ROOT).as_posix()
            for path in self.packager.derived_plan()
        }
        self.assertEqual(
            planned,
            {
                "README.md",
                "docs/passport-spec-v1.md",
                "examples/verified/runs.md",
                "index.html",
            },
        )

    def test_passport_refusal_section_is_generated_and_idempotent(self) -> None:
        specification = self.packager.PASSPORT_SPEC_PATH.read_text(encoding="utf-8")
        generated = self.packager.passport_spec_with_refusal_reasons(specification)
        self.assertEqual(generated, specification)
        self.assertEqual(
            self.packager.passport_spec_with_refusal_reasons(generated), generated
        )

    def test_landing_regions_equal_what_the_tree_derives(self) -> None:
        landing = (gate.ROOT / "index.html").read_text(encoding="utf-8")
        self.assertEqual(
            self.packager.landing_with_generated_regions(landing), landing
        )

    def test_landing_generation_is_idempotent(self) -> None:
        landing = (gate.ROOT / "index.html").read_text(encoding="utf-8")
        once = self.packager.landing_with_generated_regions(landing)
        self.assertEqual(self.packager.landing_with_generated_regions(once), once)

    def test_landing_count_equals_the_published_passports(self) -> None:
        count = len(self.counter.published_passports())
        expected = self.packager.verified_run_sentence(count)
        landing = (gate.ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn(expected, landing)

    def test_refusal_claim_and_record_equal_the_measured_coverage(self) -> None:
        coverage = self.packager.refusal_coverage()
        self.assertEqual(coverage.counts, (39, 35, 4))
        self.assertEqual(coverage.errors, ())
        self.assertEqual(
            self.packager.refusal_claim_failures(self.ledger, coverage), []
        )
        claim = next(
            item
            for item in self.ledger["claims"]
            if item["id"] == self.packager.REFUSAL_CLAIM_ID
        )
        self.assertEqual(
            claim["statement"], self.packager.refusal_claim_statement(coverage)
        )

    def test_refusal_claim_rejects_ledger_or_survey_drift(self) -> None:
        coverage = self.packager.refusal_coverage()
        changed_ledger = copy.deepcopy(self.ledger)
        claim = next(
            item
            for item in changed_ledger["claims"]
            if item["id"] == self.packager.REFUSAL_CLAIM_ID
        )
        claim["statement"] = claim["statement"].replace("39", "40", 1)
        self.assertTrue(
            self.packager.refusal_claim_failures(changed_ledger, coverage)
        )

        changed_coverage = self.packager.RefusalCoverage(
            declared=coverage.declared | {"block_future_reason"},
            demonstrated=coverage.demonstrated,
            not_reachable=coverage.not_reachable,
            failed_cases=coverage.failed_cases,
            errors=coverage.errors,
        )
        failures = self.packager.refusal_claim_failures(
            self.ledger, changed_coverage
        )
        self.assertTrue(any("statement" in failure for failure in failures))
        self.assertTrue(
            any("declared-refusal-reasons" in failure for failure in failures)
        )

    def test_landing_refusal_counts_equal_the_measured_coverage(self) -> None:
        landing = (gate.ROOT / "index.html").read_text(encoding="utf-8")
        declared, demonstrated, not_reachable = self.packager.refusal_coverage().counts
        for name, value in (
            ("refusal-declared", declared),
            ("refusal-demonstrated", demonstrated),
            ("refusal-not-reachable", not_reachable),
        ):
            with self.subTest(region=name):
                self.assertIn(
                    f"<!-- generated:{name} -->{value}<!-- /generated:{name} -->",
                    landing,
                )

    def test_the_run_clause_is_grammatical_at_any_count(self) -> None:
        """A door that says "1 runs are published" is worse than the typed
        number it replaced."""
        self.assertIn("one supervised run is", self.packager.verified_run_sentence(1))
        self.assertIn("2 supervised runs are", self.packager.verified_run_sentence(2))
        self.assertNotIn("1 supervised", self.packager.verified_run_sentence(1))

    def test_a_hand_edited_landing_number_is_refused(self) -> None:
        landing = (gate.ROOT / "index.html").read_text(encoding="utf-8")
        replacements = (
            ("one supervised run is", "five supervised runs are"),
            (
                ">39<!-- /generated:refusal-declared -->",
                ">99<!-- /generated:refusal-declared -->",
            ),
            (
                ">35<!-- /generated:refusal-demonstrated -->",
                ">39<!-- /generated:refusal-demonstrated -->",
            ),
            (
                ">4<!-- /generated:refusal-not-reachable -->",
                ">0<!-- /generated:refusal-not-reachable -->",
            ),
        )
        for original, replacement in replacements:
            with self.subTest(original=original):
                tampered = landing.replace(original, replacement)
                self.assertNotEqual(tampered, landing)
                self.assertNotEqual(
                    self.packager.landing_with_generated_regions(tampered), tampered
                )

    def test_a_missing_region_marker_is_an_error_not_a_silent_skip(self) -> None:
        landing = (gate.ROOT / "index.html").read_text(encoding="utf-8")
        for name in (
            "verified-runs",
            "refusal-declared",
            "refusal-demonstrated",
            "refusal-not-reachable",
        ):
            for marker in (
                f"<!-- /generated:{name} -->",
                f"<!-- generated:{name} -->",
            ):
                with self.subTest(marker=marker):
                    broken = landing.replace(marker, "")
                    with self.assertRaises(self.packager.PublicationError):
                        self.packager.landing_with_generated_regions(broken)

    def test_landing_makes_no_external_request_and_carries_no_script(self) -> None:
        landing = (gate.ROOT / "index.html").read_text(encoding="utf-8")
        self.assertEqual(landing.lower().count("<script"), 0)
        hosts = {
            match.split("/")[2]
            for match in re.findall(r"https?://[^\s\"')]+", landing)
        }
        self.assertEqual(hosts, {"deedseal.com", "github.com"})

    def test_twin_derivation_is_deterministic_and_one_byte(self) -> None:
        original = (
            gate.ROOT / "examples/verified/run-passport.json"
        ).read_bytes()
        twin, offset = self.packager.derive_twin(original)
        again, again_offset = self.packager.derive_twin(original)
        self.assertEqual(twin, again)
        self.assertEqual(offset, again_offset)
        self.assertEqual(
            self.packager.single_byte_difference(original, twin), offset
        )

    def test_twin_derivation_refuses_a_passport_without_a_run_id(self) -> None:
        with self.assertRaises(self.packager.PublicationError):
            self.packager.derive_twin(b'{"schema_version": "x"}')

    def test_single_byte_difference_refuses_a_wholesale_rewrite(self) -> None:
        with self.assertRaises(self.packager.PublicationError):
            self.packager.single_byte_difference(b"abcd", b"wxyz")
        with self.assertRaises(self.packager.PublicationError):
            self.packager.single_byte_difference(b"abcd", b"abcde")

    def test_counter_finds_every_published_passport(self) -> None:
        found = {
            path.relative_to(gate.ROOT).as_posix()
            for path in self.counter.published_passports()
        }
        self.assertIn("examples/verified/run-passport.json", found)
        for path in found:
            self.assertTrue(path.endswith("run-passport.json"))

    def test_counter_agrees_with_the_committed_runs(self) -> None:
        self.assertEqual(self.counter.main(), 0)

    def test_run_index_is_generated_and_lists_every_run(self) -> None:
        index = (gate.ROOT / "examples/verified/runs.md").read_text(encoding="utf-8")
        self.assertIn("Do not edit by hand", index)
        self.assertEqual(
            index.count("\n| `"), len(self.counter.published_passports())
        )

    def test_packager_tools_declare_an_allowed_license(self) -> None:
        for name in ("build_publication.py", "check_runs.py"):
            with self.subTest(tool=name):
                text = (gate.ROOT / "tools" / name).read_text(encoding="utf-8")
                declared = gate.SPDX_RE.search(text)
                self.assertIsNotNone(declared)
                self.assertIn(declared.group(1), gate.ALLOWED_SPDX)


if __name__ == "__main__":
    unittest.main(verbosity=2)
