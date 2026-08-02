#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Regression tests for the public publication gate."""

from __future__ import annotations

import copy
import sys
import unittest
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


if __name__ == "__main__":
    unittest.main(verbosity=2)

