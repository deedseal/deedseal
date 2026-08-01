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
        self.assertEqual(snapshot, "DS-2026.08.1")
        self.assertEqual(claims, 7)
        self.assertEqual(evidence, 3)

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

    def test_review_candidate_fails_release_mode(self) -> None:
        with self.assertRaises(gate.ValidationError):
            gate.validate_repository(require_published=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

