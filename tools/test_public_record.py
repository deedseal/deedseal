#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Regression tests for the public publication gate."""

from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import validate_public_record as gate
import check_brand_identity as brand


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


class ProofSurfaceTests(unittest.TestCase):
    """The proof surface carries sanitized summaries of private live work.

    These tests hold two lines. The first is structural: what a proof index
    displays about a claim -- its statement, its band, its evidence link and
    that record's digest -- must equal what the ledger carries, so a reader can
    never be shown a number nobody derived. The second is the disclosure gate:
    a recognizable private marker injected into any of the new public bytes has
    to fail the build, not slip through because that particular file was not on
    somebody's list.
    """

    # Recognizable markers of the private engineering source and of host
    # identity. None of these is real; each is the *shape* the gate refuses.
    NEGATIVE_CORPUS = (
        ("internal source symbol", "the retrieve_run leg was corrected"),
        ("internal source path", "see tools/neural/shadow_run.py for the ask"),
        ("machine path", "written to /var/lib/fixture/output.txt"),
        ("windows machine path", "copied from C:\\Fixture\\run.json"),
        ("network share path", "staged on \\\\fixture-box\\share"),
        ("kernel identity", "observed on kernel 9.99.1-fx-v42"),
        ("host identity", "reached the broker on fixture-box.internal"),
        ("private protocol identifier", "the envelope declared kbp.fixture/v0.9"),
        ("private repository name", "recorded in kbp-fixture-office"),
        ("worker session identity", "session_01FIXTUREabcdefghij"),
        ("exact refusal code", "the broker answered refused_fixture_bound"),
        ("internal outcome code", "the journal recorded completed_model_response"),
        ("internal constant name", "the ceiling constant MAX_FIXTURE_BYTES moved"),
        ("service unit", "started by fixture-runner.service"),
        # Assembled rather than spelt out: the tree-wide scan reads this file
        # too, and a literal address here would fail the gate it is testing.
        ("network address", "the broker listened on " + "203.0." + "113.7"),
        ("unnegated positive claim", "this path is production-ready today"),
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.ledger, _raw = gate.load_json(gate.LEDGER_PATH)
        cls.claims = [
            gate.validate_claim(value, cls.ledger["snapshot"]["id"])
            for value in cls.ledger["claims"]
        ]
        cls.evidence_by_id = {
            item["id"]: gate.validate_evidence_index(item)
            for item in cls.ledger["evidence"]
        }
        cls.claims_by_id = {claim["id"]: claim for claim in cls.claims}
        cls.documented = gate.validate_proof_indexes(cls.claims, cls.evidence_by_id)
        cls.fragments = gate.proof_surface_fragments(
            cls.documented, cls.claims, cls.evidence_by_id
        )

    def _block_for(self, claim_id: str) -> tuple[dict, Path]:
        path = gate.ROOT / self.documented[claim_id]
        blocks = gate.parse_proof_blocks(path.read_text(encoding="utf-8"))
        return blocks[claim_id], path.parent

    # ------------------------------------------------------------------
    # the structural line: the page may not say what the ledger does not
    # ------------------------------------------------------------------

    def test_the_committed_proof_indexes_agree_with_the_ledger(self) -> None:
        self.assertTrue(self.documented, "no claim is documented by a proof index")
        for claim_id, document in self.documented.items():
            with self.subTest(claim=claim_id):
                block, base = self._block_for(claim_id)
                self.assertEqual(
                    gate.proof_block_failures(
                        f"{document}:{claim_id}",
                        block,
                        self.claims_by_id,
                        self.evidence_by_id,
                        base,
                    ),
                    [],
                )

    def test_a_typed_digest_statement_or_band_is_refused(self) -> None:
        """The three ways a proof index could quietly stop describing the record."""
        claim_id = sorted(self.documented)[0]
        block, base = self._block_for(claim_id)
        label = f"{self.documented[claim_id]}:{claim_id}"
        drifts = {
            "digest": "0" * 64,
            "statement": "A statement the ledger does not carry.",
            "band": "public-reproducible",
            "evidence_link": "../../README.md",
        }
        for field, value in drifts.items():
            with self.subTest(field=field):
                tampered = dict(block)
                tampered[field] = value
                self.assertTrue(
                    gate.proof_block_failures(
                        label, tampered, self.claims_by_id, self.evidence_by_id, base
                    )
                )

    def test_a_block_missing_a_required_line_is_refused(self) -> None:
        claim_id = sorted(self.documented)[0]
        block, base = self._block_for(claim_id)
        label = f"{self.documented[claim_id]}:{claim_id}"
        for field in ("band", "evidence_id", "digest", "limitation", "statement"):
            with self.subTest(field=field):
                tampered = dict(block)
                tampered[field] = None
                self.assertTrue(
                    gate.proof_block_failures(
                        label, tampered, self.claims_by_id, self.evidence_by_id, base
                    )
                )

    def test_every_claim_is_written_out_for_a_human_somewhere(self) -> None:
        """Two documentation surfaces are allowed. None is not."""
        gate.validate_document_links(
            self.claims,
            {item for claim in self.claims for item in claim["evidence_ids"]},
            self.documented,
        )
        with self.assertRaises(gate.ValidationError):
            gate.validate_document_links(
                self.claims,
                {item for claim in self.claims for item in claim["evidence_ids"]},
                {},
            )

    # ------------------------------------------------------------------
    # the disclosure line: the corpus, and the surfaces it is injected into
    # ------------------------------------------------------------------

    def test_the_committed_proof_surface_is_clean(self) -> None:
        for label, text, base in self.fragments:
            with self.subTest(fragment=label):
                self.assertIsNone(gate.proof_surface_violation(text, base))

    def test_every_negative_marker_is_refused(self) -> None:
        for name, sample in self.NEGATIVE_CORPUS:
            with self.subTest(marker=name):
                self.assertIsNotNone(
                    gate.proof_surface_violation(sample, gate.ROOT),
                    f"{name} was not refused",
                )

    def test_injection_into_every_new_public_surface_fails_closed(self) -> None:
        """One real fragment per surface, each carrying each marker.

        This is the property the packet asks for: it is not enough that the
        scanner recognizes a marker, the marker has to be refused in the exact
        files the new claims are published through.
        """
        surfaces = {
            "proof index": lambda label: label.startswith("docs/proof/"),
            "evidence record": lambda label: label.startswith("evidence/records/"),
            "ledger claim row": lambda label: ":CLM-" in label,
            "ledger evidence row": lambda label: ":EVD-" in label,
            "README row": lambda label: label.startswith("README.md:"),
            "status update": lambda label: label.startswith("docs/status.md:"),
        }
        for surface, matches in surfaces.items():
            fragment = next(
                (item for item in self.fragments if matches(item[0])), None
            )
            self.assertIsNotNone(fragment, f"no fragment covers the {surface}")
            label, text, base = fragment
            self.assertIsNone(gate.proof_surface_violation(text, base), label)
            for name, sample in self.NEGATIVE_CORPUS:
                with self.subTest(surface=surface, marker=name):
                    self.assertIsNotNone(
                        gate.proof_surface_violation(f"{text}\n{sample}\n", base),
                        f"{name} survived injection into the {surface}",
                    )

    def test_public_paths_resolve_and_private_ones_do_not(self) -> None:
        """The rule is not a word list: a path is allowed because it exists."""
        self.assertEqual(
            gate.unresolved_source_paths(
                "see tools/validate_public_record.py and evidence/ledger-v1.json",
                gate.ROOT,
            ),
            [],
        )
        self.assertEqual(
            gate.unresolved_source_paths("../../evidence/ledger-v1.json", gate.ROOT),
            [],
        )
        self.assertEqual(
            gate.unresolved_source_paths("tools/broker/model_access.py", gate.ROOT),
            ["tools/broker/model_access.py"],
        )

    def test_banned_words_are_allowed_only_where_they_are_denied(self) -> None:
        self.assertEqual(
            gate.unnegated_positive_claims(
                "It is not independently audited and not production-ready."
            ),
            [],
        )
        self.assertEqual(
            gate.unnegated_positive_claims("none of it is customer-deployed"), []
        )
        for positive in (
            "the path is secure",
            "the record is certified",
            "this build is production-ready",
            "the appliance is generally available",
        ):
            with self.subTest(text=positive):
                self.assertTrue(gate.unnegated_positive_claims(positive))

    def test_the_scan_covers_the_records_and_rows_of_every_documented_claim(self) -> None:
        labels = {label for label, _text, _base in self.fragments}
        for claim_id, document in self.documented.items():
            with self.subTest(claim=claim_id):
                self.assertIn(document, labels)
                self.assertIn(f"evidence/ledger-v1.json:{claim_id}", labels)
                self.assertIn(f"README.md:{claim_id}", labels)
                for evidence_id in self.claims_by_id[claim_id]["evidence_ids"]:
                    self.assertIn(f"evidence/ledger-v1.json:{evidence_id}", labels)
                    self.assertIn(
                        self.evidence_by_id[evidence_id]["artifact"]["path"], labels
                    )

    def test_the_night_publishes_seven_office_facts_and_no_eighth(self) -> None:
        """The count is part of the claim: seven, all in the weakest band."""
        documented = sorted(self.documented)
        self.assertEqual(
            documented, [f"CLM-{number:04d}" for number in range(14, 21)]
        )
        records = []
        for claim_id in documented:
            claim = self.claims_by_id[claim_id]
            self.assertEqual(claim["status"], "internally-verified")
            self.assertEqual(claim["component"], "OFFICE")
            self.assertEqual(len(claim["evidence_ids"]), 1)
            records.extend(claim["evidence_ids"])
        self.assertEqual(
            records, [f"EVD-OFFICE-{number:04d}" for number in range(2, 9)]
        )
        for evidence_id in records:
            evidence = self.evidence_by_id[evidence_id]
            self.assertEqual(evidence["assurance"], "internal-ci-attestation")
            self.assertEqual(evidence["source_snapshot"], "OFFICE-2026-08-12-A")
            self.assertLessEqual(
                {"R-IP", "R-OPS", "R-PRIV", "R-SEC"}, set(evidence["redactions"])
            )
            digest = hashlib.sha256(
                (gate.ROOT / evidence["artifact"]["path"]).read_bytes()
            ).hexdigest()
            self.assertEqual(digest, evidence["artifact"]["sha256"])


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

    def test_packager_check_passes_without_retired_root_claimants(self) -> None:
        self.assertEqual(self.packager.command_check(None), 0)
        planned = set(self.packager.derived_plan())
        self.assertNotIn(gate.ROOT / "index.html", planned)
        self.assertNotIn(gate.ROOT / "CNAME", planned)

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

    def test_derived_plan_covers_only_active_generated_public_artifacts(self) -> None:
        planned = {
            path.relative_to(gate.ROOT).as_posix()
            for path in self.packager.derived_plan()
        }
        self.assertEqual(
            planned,
            {
                "README.md",
                "docs/passport-spec-v1.md",
                "examples/verified/conformance/manifest.json",
                "examples/verified/runs.md",
            },
        )
        self.assertTrue({"index.html", "CNAME"}.isdisjoint(planned))

    def test_passport_refusal_section_is_generated_and_idempotent(self) -> None:
        specification = self.packager.PASSPORT_SPEC_PATH.read_text(encoding="utf-8")
        generated = self.packager.passport_spec_with_refusal_reasons(specification)
        self.assertEqual(generated, specification)
        self.assertEqual(
            self.packager.passport_spec_with_refusal_reasons(generated), generated
        )

    def test_retired_root_landing_must_remain_absent(self) -> None:
        self.assertFalse((gate.ROOT / "index.html").exists())

    def test_retired_root_domain_claimant_must_remain_absent(self) -> None:
        self.assertFalse((gate.ROOT / "CNAME").exists())

    def test_publication_plan_excludes_retired_root_claimants(self) -> None:
        planned = {
            path.relative_to(gate.ROOT).as_posix()
            for path in self.packager.derived_plan()
        }
        self.assertNotIn("index.html", planned)
        self.assertNotIn("CNAME", planned)

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

    def test_readme_remains_an_active_publication_input(self) -> None:
        plan = self.packager.derived_plan()
        self.assertIn(self.packager.README_PATH, plan)
        self.assertIn("README.md", gate.REQUIRED_PUBLIC_FILES)
        self.assertIn(
            gate.ROOT / "README.md",
            gate.all_public_files(),
        )

    def test_the_run_clause_is_grammatical_at_any_count(self) -> None:
        """A door that says "1 runs are published" is worse than the typed
        number it replaced."""
        self.assertIn("one supervised run is", self.packager.verified_run_sentence(1))
        self.assertIn("2 supervised runs are", self.packager.verified_run_sentence(2))
        self.assertNotIn("1 supervised", self.packager.verified_run_sentence(1))

    def test_the_run_clause_agrees_with_its_own_possessive(self) -> None:
        """The generated region has to cover the whole clause, not just the
        count.

        It once covered only the number, which left a plural subject in front
        of a singular possessive: "2 supervised runs are published with its
        passport". Subject-verb agreement alone did not catch it, because the
        half that disagreed was outside the region the generator owned.
        """
        singular = self.packager.verified_run_sentence(1)
        self.assertIn("with its passport", singular)
        self.assertNotIn("each with its", singular)
        for count in (2, 3, 11):
            with self.subTest(count=count):
                clause = self.packager.verified_run_sentence(count)
                self.assertIn("each with its passport", clause)
                self.assertNotIn("published, with its", clause)

    def test_published_passports_name_one_version_the_bytes_carry(self) -> None:
        version = self.packager.published_envelope_version()
        for passport in self.counter.published_passports():
            with self.subTest(passport=passport.name):
                self.assertEqual(
                    json.loads(passport.read_text(encoding="utf-8"))["schema_version"],
                    version,
                )
        self.assertEqual(version, "deedseal-run-passport/1.0")

    def test_a_status_freeze_the_bytes_do_not_carry_is_refused(self) -> None:
        """Status is hand-written and dated. It does not get the last word on
        what format the published passports are in."""
        status = (gate.ROOT / "docs" / "status.md").read_text(encoding="utf-8")
        with self.assertRaises(self.packager.PublicationError):
            self.packager.envelope_commitment(status, "deedseal-run-passport/9.9")

    def test_an_unfrozen_status_makes_no_promise(self) -> None:
        """The state this repository was in until the envelope froze.

        The generator has to render it honestly rather than raise, or the page
        could never walk the commitment back.
        """
        version = self.packager.published_envelope_version()
        unfrozen = (
            "| Workstream | Scope | State |\n"
            "| --- | --- | --- |\n"
            "| Run passport format | The evidence record | draft — not frozen |\n"
        )
        clause = self.packager.envelope_commitment(unfrozen, version)
        self.assertIn("not frozen yet", clause)
        self.assertNotIn("frozen at", clause)
        self.assertNotIn("keeps verifying", clause)

    def test_a_missing_workstream_row_is_refused(self) -> None:
        with self.assertRaises(self.packager.PublicationError):
            self.packager.frozen_envelope_version("# Status\n\nNo table here.\n")

    def test_the_page_names_no_format_it_cannot_read_off_the_bytes(self) -> None:
        """No passports, or passports in two envelopes: either way the clause
        is unwritable and the publication has to stop rather than pick one."""
        real = self.packager.published_passports
        with tempfile.TemporaryDirectory() as tmp:
            pair = []
            for index, version in enumerate(("1.0", "2.0")):
                path = Path(tmp) / f"run-{index}.json"
                path.write_text(
                    json.dumps({"schema_version": f"deedseal-run-passport/{version}"}),
                    encoding="utf-8",
                )
                pair.append(path)
            for label, listing in (("none", lambda: []), ("mixed", lambda: pair)):
                with self.subTest(published=label):
                    try:
                        self.packager.published_passports = listing
                        with self.assertRaises(self.packager.PublicationError):
                            self.packager.published_envelope_version()
                    finally:
                        self.packager.published_passports = real

    def test_proof_indexes_remain_active_public_record_inputs(self) -> None:
        proof = "docs/proof/2026-08-12-neural-memory.md"
        public_paths = {
            path.relative_to(gate.ROOT).as_posix()
            for path in gate.all_public_files()
        }
        self.assertIn(proof, gate.REQUIRED_PUBLIC_FILES)
        self.assertIn(proof, public_paths)
        self.assertIn(gate.ROOT / proof, gate.proof_index_paths())

    def test_verifier_and_examples_remain_active_public_record_inputs(self) -> None:
        active = {
            "tools/verify_run_passport.py",
            "examples/passport.example.json",
            "examples/verified/run-passport.json",
            "examples/verified/run-passport.tampered.json",
            "examples/verified/conformance/manifest.json",
        }
        public_paths = {
            path.relative_to(gate.ROOT).as_posix()
            for path in gate.all_public_files()
        }
        self.assertLessEqual(active, gate.REQUIRED_PUBLIC_FILES)
        self.assertLessEqual(active, public_paths)

    def test_publication_records_remain_active_public_record_inputs(self) -> None:
        public_paths = {
            path.relative_to(gate.ROOT).as_posix()
            for path in gate.all_public_files()
        }
        records = {
            entry["artifact"]["path"]
            for entry in self.ledger["evidence"]
        }
        self.assertIn("evidence/ledger-v1.json", gate.REQUIRED_PUBLIC_FILES)
        self.assertIn("evidence/ledger-v1.json", public_paths)
        self.assertGreater(len(records), 0)
        self.assertLessEqual(records, public_paths)

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
        for name in ("build_publication.py", "check_conformance.py", "check_runs.py"):
            with self.subTest(tool=name):
                text = (gate.ROOT / "tools" / name).read_text(encoding="utf-8")
                declared = gate.SPDX_RE.search(text)
                self.assertIsNotNone(declared)
                self.assertIn(declared.group(1), gate.ALLOWED_SPDX)


class ConformanceSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "tools"))
        import build_publication as packager
        import check_conformance as runner
        import check_runs as counter
        import survey_refusals as survey

        cls.packager = packager
        cls.runner = runner
        cls.counter = counter
        cls.survey = survey
        cls.manifest_path = packager.CONFORMANCE_MANIFEST
        cls.manifest = runner.load_manifest(cls.manifest_path)

    def _copied_suite(self, temporary: str) -> Path:
        destination = Path(temporary) / "conformance"
        shutil.copytree(self.manifest_path.parent, destination)
        return destination / "manifest.json"

    def _quiet_main(self, manifest: Path) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return self.runner.main([str(manifest)])

    def test_input_kinds_and_exact_file_bytes_match_derivation(self) -> None:
        _derived_manifest, states = self.packager.conformance_suite()
        observed_kinds: set[str] = set()
        for vector in self.manifest["vectors"]:
            kind = vector.get("input_kind", "file")
            observed_kinds.add(kind)
            self.assertIn(kind, self.runner.INPUT_KINDS)
            path = self.manifest_path.parent / vector["input"]
            expected_kind, expected_bytes = states[vector["input"]]
            self.assertEqual(kind, expected_kind)
            if kind == "file":
                self.assertTrue(path.is_file(), vector["id"])
                self.assertEqual(path.read_bytes(), expected_bytes, vector["id"])
            elif kind == "absent":
                self.assertFalse(path.exists(), vector["id"])
            elif kind == "directory":
                self.assertTrue(path.is_dir(), vector["id"])
        self.assertEqual(observed_kinds, {"file", "absent", "directory"})
        empty = next(vector for vector in self.manifest["vectors"] if vector["id"] == "empty-file")
        self.assertEqual((self.manifest_path.parent / empty["input"]).stat().st_size, 0)

    def test_unknown_input_kind_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = self._copied_suite(temporary)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["vectors"][0]["input_kind"] = "unknown"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(self._quiet_main(manifest_path), 1)

    def test_absent_input_must_remain_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = self._copied_suite(temporary)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            vector = next(item for item in manifest["vectors"] if item["input_kind"] == "absent")
            path = manifest_path.parent / vector["input"]
            path.write_bytes(b"appeared")
            self.assertEqual(self._quiet_main(manifest_path), 1)

    def test_vector_ids_are_unique_and_suite_has_a_pass(self) -> None:
        ids = [vector["id"] for vector in self.manifest["vectors"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(any(vector["expect_verdict"] == "PASS" for vector in self.manifest["vectors"]))

    def test_manifest_reasons_equal_demonstrated_corpus_reasons(self) -> None:
        manifest_reasons = {
            vector["expect_reason"]
            for vector in self.manifest["vectors"]
            if "expect_reason" in vector
        }
        self.assertEqual(manifest_reasons, set(self.survey.evaluate_coverage().demonstrated))

    def test_committed_conformance_suite_passes(self) -> None:
        self.assertEqual(self._quiet_main(self.manifest_path), 0)

    def test_hand_edited_expected_reason_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = self._copied_suite(temporary)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            vector = next(item for item in manifest["vectors"] if "expect_reason" in item)
            vector["expect_reason"] = "block_future_reason"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(self._quiet_main(manifest_path), 1)

    def test_hand_edited_vector_bytes_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = self._copied_suite(temporary)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            vector = next(
                item
                for item in manifest["vectors"]
                if item["input_kind"] == "file" and item["expect_verdict"] == "PASS"
            )
            path = manifest_path.parent / vector["input"]
            payload = bytearray(path.read_bytes())
            payload[0] = ord("[") if payload[0] != ord("[") else ord("{")
            path.write_bytes(payload)
            self.assertEqual(self._quiet_main(manifest_path), 1)

    def test_vector_names_do_not_change_the_published_run_count(self) -> None:
        self.assertFalse(any(Path(vector["input"]).name == "run-passport.json" for vector in self.manifest["vectors"]))
        self.assertEqual(len(self.counter.published_passports()), 2)

    def test_manifest_is_byte_identical_to_generator_output(self) -> None:
        self.assertEqual(
            self.manifest_path.read_text(encoding="utf-8"),
            self.packager.conformance_manifest_text(),
        )


class BrandIdentityGateTests(unittest.TestCase):
    """The identity packet is part of the public record, so this suite runs its check.

    The brand checker's own hostile corpus lives in `tools/test_brand_identity.py`.
    What is proven here is narrower and belongs to the public gate: the committed
    packet passes, the check is reachable from this suite the way continuous
    integration reaches it, and it still refuses when a reviewer breaks the
    packet under it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "tools"))
        import check_brand_identity as brand

        cls.brand = brand

    @contextlib.contextmanager
    def _packet(self):
        """A throwaway copy of the identity packet."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "packet"
            (root / "assets").mkdir(parents=True)
            shutil.copytree(ROOT / "assets/svg", root / "assets/svg")
            for name in (
                "assets/brand-manifest.v1.json",
                "assets/BRAND-IDENTITY-v1.0.md",
                "assets/README.md",
            ):
                shutil.copyfile(ROOT / name, root / name)
            yield root

    def _manifest(self, root: Path) -> dict:
        return json.loads(
            (root / "assets/brand-manifest.v1.json").read_text(encoding="utf-8")
        )

    def _write_manifest(self, root: Path, manifest: dict) -> None:
        (root / "assets/brand-manifest.v1.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )

    def _refuse(self, root: Path, fragment: str) -> None:
        with self.assertRaises(self.brand.BrandIdentityError) as caught:
            self.brand.check_identity(root)
        self.assertIn(fragment, str(caught.exception))

    def test_the_committed_identity_passes_its_own_check(self) -> None:
        identity_version, count = self.brand.check_identity(ROOT)
        self.assertEqual(identity_version, "1.0")
        self.assertEqual(count, 8)

    def test_the_checker_exits_zero_on_the_committed_tree(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = self.brand.main([])
        self.assertEqual(code, 0)
        self.assertIn("BRAND_IDENTITY_CHECK: PASS", stdout.getvalue())

    def test_the_checker_exits_one_and_names_its_refusal(self) -> None:
        with self._packet() as root:
            (root / "assets/svg/deedseal-icon.svg").unlink()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = self.brand.main(["--root", str(root)])
            self.assertEqual(code, 1)
            self.assertIn("BRAND_IDENTITY_CHECK: FAIL", stderr.getvalue())

    def test_a_stale_asset_digest_is_refused(self) -> None:
        with self._packet() as root:
            manifest = self._manifest(root)
            for entry in manifest["assets"]:
                if entry["path"] == "assets/svg/deedseal-mark.svg":
                    entry["sha256"] = "0" * 64
            self._write_manifest(root, manifest)
            self._refuse(root, "digest is stale")

    def test_a_scripted_asset_is_refused(self) -> None:
        with self._packet() as root:
            path = root / "assets/svg/deedseal-mark.svg"
            text = path.read_text(encoding="utf-8").replace(
                "</svg>", "<script>1</script></svg>"
            )
            path.write_text(text, encoding="utf-8")
            manifest = self._manifest(root)
            for entry in manifest["assets"]:
                if entry["path"] == "assets/svg/deedseal-mark.svg":
                    entry["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
            self._write_manifest(root, manifest)
            self._refuse(root, "forbidden <script> element")

    def test_a_runtime_verdict_colour_in_a_brand_asset_is_refused(self) -> None:
        with self._packet() as root:
            path = root / "assets/svg/deedseal-mark.svg"
            manifest = self._manifest(root)
            green = manifest["palette"]["runtime_states"]["roles"]["state-pass"]["value"]
            text = path.read_text(encoding="utf-8").replace('fill="#141414"', f'fill="{green}"')
            path.write_text(text, encoding="utf-8")
            for entry in manifest["assets"]:
                if entry["path"] == "assets/svg/deedseal-mark.svg":
                    entry["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
            self._write_manifest(root, manifest)
            self._refuse(root, "runtime verdict colour into a brand asset")

    def test_a_wrong_product_name_is_refused(self) -> None:
        with self._packet() as root:
            manifest = self._manifest(root)
            manifest["product_name"] = "DeedSeal"
            self._write_manifest(root, manifest)
            self._refuse(root, "must be exactly 'Deedseal'")

    def test_a_retired_generator_may_not_come_back(self) -> None:
        self.assertFalse((ROOT / "assets/src/build_card.py").exists())
        self.assertFalse((ROOT / "assets/src/build_mark.py").exists())
        with self._packet() as root:
            (root / "assets/src").mkdir(parents=True)
            (root / "assets/src/build_card.py").write_text("# retired\n", encoding="utf-8")
            self._refuse(root, "retired generator is still present")

    def test_every_declared_asset_is_inside_the_public_tree(self) -> None:
        manifest = self._manifest(ROOT)
        public = {path.relative_to(gate.ROOT).as_posix() for path in gate.all_public_files()}
        for entry in manifest["assets"]:
            self.assertIn(entry["path"], public)
            self.assertTrue((ROOT / entry["path"]).is_file())

    def test_the_identity_packet_carries_no_binary_file(self) -> None:
        for path in sorted((ROOT / "assets").rglob("*")):
            if "__pycache__" in path.parts or not path.is_file():
                continue
            self.assertIsInstance(path.read_text(encoding="utf-8"), str)


# ----------------------------------------------------------------------
# the release policy's prerelease boundary, held in the policy's own bytes
# ----------------------------------------------------------------------

# The complete normative sentence the release-and-tagging policy exists to
# carry. The guard below anchors here rather than on the bare `prerelease: true`
# substring: that substring also occurs decoratively in procedure step 6, so it
# survives an inversion of this clause and cannot hold the boundary.
NORMATIVE_PRERELEASE_CLAUSE = (
    "Every GitHub Release remains a prerelease with `prerelease: true` until "
    "general availability is separately evidenced and Owner-approved. A version "
    "number, a closed engineering workstream or a passing check is not evidence "
    "of general availability."
)

# The one truthful way this policy names general availability: to defer it.
TRUTHFUL_GENERAL_AVAILABILITY_BOUNDARY = (
    "until general availability is separately evidenced and Owner-approved"
)

# General-availability instructions. None of these is text the repository
# carries; each is the *shape* the release policy must never take. They are
# allowed only where the sentence denies or defers them, which is exactly how
# the adopted boundary itself reads.
GENERAL_AVAILABILITY_INSTRUCTION_TERMS = re.compile(
    r"\b(?:prerelease:[ \t]*false|generally[ \t]+available|"
    r"general[ \t-]availability[ \t]+release|ordinary[ \t]+release|"
    r"GA[ \t]+release|evidence[ \t]+of[ \t]+general[ \t]+availability|"
    r"general[ \t]+availability[ \t]+is[ \t]+(?:established|reached|achieved))\b",
    re.IGNORECASE,
)

# A stand-in for the policy document, carrying the same two occurrences of
# `prerelease: true` as the real one -- the normative clause, and the decorative
# mention in procedure step 6. The guard's own probes run against this fixture
# rather than the committed file, so that mutating the committed file produces
# one named failure from the two tests that own it, not a cascade here.
REFERENCE_RELEASE_POLICY = f"""# Release and tagging policy

## Decision

{NORMATIVE_PRERELEASE_CLAUSE}

A published tag target is immutable.

## Release procedure

6. Create the GitHub Release from that exact immutable tag with `prerelease: true`.
"""


def unnegated_general_availability_instructions(policy: str) -> list[str]:
    """General-availability wording used affirmatively rather than deferred.

    Reuses the gate's own clause-scoped negation window, so "is not evidence of
    general availability" reads as the boundary it is, while the same words used
    as an instruction do not.
    """
    offences: list[str] = []
    for match in GENERAL_AVAILABILITY_INSTRUCTION_TERMS.finditer(policy):
        window = policy[max(0, match.start() - gate.NEGATION_WINDOW) : match.start()]
        boundary = max(window.rfind(character) for character in gate.NEGATION_BOUNDARY)
        if boundary >= 0:
            window = window[boundary + 1 :]
        if gate.NEGATION_RE.search(window) is None:
            offences.append(match.group(0))
    return offences


def release_policy_violation(policy: str) -> str | None:
    """Name the way a release policy stopped holding the prerelease boundary.

    Mirrors ``gate.proof_surface_violation``: the named reason, or ``None`` when
    the policy still carries the boundary in its own bytes. Deleting, weakening
    or inverting the normative clause is refused by the first check; an
    affirmative general-availability instruction added alongside an intact
    clause is refused by the second.
    """
    if NORMATIVE_PRERELEASE_CLAUSE not in policy:
        return "normative prerelease clause missing or altered"
    offences = unnegated_general_availability_instructions(policy)
    if offences:
        return f"affirmative general-availability instruction ({offences[0]!r})"
    return None


class BusinessFirstReleasePreflightTests(unittest.TestCase):
    """Hold the adopted public story and release preparation in repository bytes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = (ROOT / "docs/decisions/release-and-tagging-policy.md").read_text(
            encoding="utf-8"
        )

    def test_readme_front_door_has_the_adopted_order_and_exact_frame(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        coordinates = [
            "Deedseal is an owner-governed AI business platform for deploying and operating a business.",
            "Deploy an AI office for your business while keeping authority, business memory and the final decision with the owner.",
            "## For owners and operators",
            "## Platform direction",
            "## Current availability",
            "## What is published today",
            "## Verify it yourself",
        ]
        positions = [readme.index(value) for value in coordinates]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("[deedseal.com](https://deedseal.com)", readme[:positions[-1]])
        self.assertIn("product direction, not a claim", readme[:positions[-1]].lower())
        self.assertIn("not generally available", readme[:positions[-1]].lower())
        self.assertIn("not represented as production-qualified", readme[:positions[-1]].lower())

    def test_readme_keeps_direction_proof_and_nonclaims_separate(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        front = readme[:readme.index("## Verify it yourself")]
        for phrase in (
            "modules, bounded adapters and bounded AI workers",
            "owner-held business memory",
            "two real run passports and their one-byte tampered twins",
            "48 conformance vectors",
            "Python/Go verdict agreement",
            "does not prove the wider business-platform capability",
            "Owner-operated first reference use and product direction only",
            "No trademark-clearance claim",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase.lower(), front.lower())

    def test_public_identity_prose_keeps_the_review_candidate_boundary(self) -> None:
        scanned = []
        for path in gate.all_public_files():
            relative = path.relative_to(ROOT)
            if relative.suffix.lower() != ".md" and relative.as_posix() != brand.MANIFEST_PATH:
                continue
            text = path.read_text(encoding="utf-8")
            scanned.append(relative.as_posix())
            self.assertIsNone(
                brand.identity_alignment_violation(text, relative.as_posix()),
                relative.as_posix(),
            )
        self.assertIn("README.md", scanned)
        self.assertIn("docs/releases/v0.2.0-prerelease-notes.md", scanned)
        self.assertIn(brand.MANIFEST_PATH, scanned)

    def test_review_candidate_assets_cannot_be_promoted_by_public_prose(self) -> None:
        hostile = {
            "Owner-selected": "Brand Identity v1.0 is the Owner-selected identity.",
            "adopted": "Brand Identity v1.0 is the adopted identity.",
            "deployed": "Brand Identity v1.0 is the deployed identity.",
            "canonical": "Brand Identity v1.0 is the canonical identity.",
            "current": "Brand Identity v1.0 is the current public identity.",
        }
        for name, sentence in hostile.items():
            with self.subTest(claim=name):
                self.assertIsNotNone(brand.identity_alignment_violation(sentence))

    def test_downstream_placement_cannot_be_authorized_by_public_prose(self) -> None:
        self.assertEqual(
            brand.identity_alignment_violation(
                "These assets authorize downstream placement."
            ),
            "an authorization of downstream placement",
        )

    def test_live_wordmark_and_green_point_cannot_become_a_permanent_canon(self) -> None:
        self.assertEqual(
            brand.identity_alignment_violation(
                "The Deedseal wordmark and one green point form the permanent identity."
            ),
            "the live wordmark and green point settled as a specified permanent canon",
        )

    def test_faq_matches_the_frozen_envelope_and_release_history(self) -> None:
        faq = (ROOT / "docs/faq.md").read_text(encoding="utf-8")
        self.assertIsNone(brand.faq_alignment_violation(faq))

    def test_faq_calling_the_1_0_envelope_unfrozen_is_refused_by_name(self) -> None:
        faq = (ROOT / "docs/faq.md").read_text(encoding="utf-8")
        hostile = faq.replace(
            "envelope is frozen",
            "envelope is not frozen",
            1,
        )
        self.assertNotEqual(hostile, faq)
        self.assertEqual(
            brand.faq_alignment_violation(hostile),
            "the 1.0 passport envelope called unfrozen",
        )

    def test_faq_denying_the_historical_public_release_is_refused_by_name(self) -> None:
        faq = (ROOT / "docs/faq.md").read_text(encoding="utf-8")
        hostile = faq.replace(
            "A historical `v0.1.0` tag and Release exist and remain public",
            "There is no public release",
            1,
        )
        self.assertNotEqual(hostile, faq)
        self.assertEqual(
            brand.faq_alignment_violation(hostile),
            "no public release, while v0.1.0 is preserved as historical",
        )

    def test_faq_losing_a_required_release_coordinate_is_refused_by_name(self) -> None:
        faq = (ROOT / "docs/faq.md").read_text(encoding="utf-8")
        hostile = faq.replace("`v0.1.0`", "the first historical version", 1)
        self.assertNotEqual(hostile, faq)
        self.assertEqual(
            brand.faq_alignment_violation(hostile),
            "missing FAQ alignment coordinate 'v0.1.0'",
        )

    def test_release_policy_carries_every_immutable_tag_boundary(self) -> None:
        policy = self.policy
        for phrase in (
            "annotated and signed",
            NORMATIVE_PRERELEASE_CLAUSE,
            "Create the GitHub Release from that exact immutable tag with"
            " `prerelease: true`",
            "published tag target is immutable",
            "corrected by a new tag and Release",
            "DS-2026.08.2",
            "evidence-snapshot identifier",
            "v0.1.0",
            "must not be moved, replaced, deleted or retroactively signed",
            "OWNER_ACTION_REQUIRED",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, policy)

    # ------------------------------------------------------------------
    # the prerelease boundary: what the committed policy holds, and what
    # the guard refuses when a policy stops holding it
    # ------------------------------------------------------------------

    def test_the_committed_release_policy_holds_the_prerelease_boundary(self) -> None:
        self.assertIsNone(release_policy_violation(self.policy))

    def test_the_reference_policy_carries_both_prerelease_occurrences(self) -> None:
        """The fixture reproduces the shape the old assertion could not see."""
        self.assertEqual(REFERENCE_RELEASE_POLICY.count("prerelease: true"), 2)
        self.assertIn(NORMATIVE_PRERELEASE_CLAUSE, REFERENCE_RELEASE_POLICY)
        self.assertIsNone(release_policy_violation(REFERENCE_RELEASE_POLICY))

    def test_the_inverted_prerelease_clause_is_refused_by_name(self) -> None:
        """Issue #59 hostile probe 5, run against the guard itself.

        The inversion leaves the bare `prerelease: true` substring standing in
        procedure step 6, which is exactly why an assertion anchored there could
        not see it. The clause-anchored guard names the refusal.
        """
        inverted = REFERENCE_RELEASE_POLICY.replace(
            NORMATIVE_PRERELEASE_CLAUSE,
            "Every GitHub Release is published as an ordinary general-availability"
            " release. Deedseal is generally available, and a passing check is"
            " sufficient evidence of general availability.",
        )
        self.assertNotEqual(inverted, REFERENCE_RELEASE_POLICY)
        self.assertIn("prerelease: true", inverted)
        self.assertEqual(
            release_policy_violation(inverted),
            "normative prerelease clause missing or altered",
        )

    def test_deleting_or_weakening_the_normative_clause_is_refused(self) -> None:
        weakenings = {
            "deleted": "",
            "made optional": (
                "Every GitHub Release may remain a prerelease with `prerelease:"
                " true` until general availability is separately evidenced and"
                " Owner-approved."
            ),
            "boundary dropped": (
                "Every GitHub Release remains a prerelease with `prerelease: true`."
            ),
            "owner approval dropped": (
                "Every GitHub Release remains a prerelease with `prerelease: true`"
                " until general availability is separately evidenced. A version"
                " number, a closed engineering workstream or a passing check is"
                " not evidence of general availability."
            ),
        }
        for name, replacement in weakenings.items():
            with self.subTest(weakening=name):
                self.assertEqual(
                    release_policy_violation(
                        REFERENCE_RELEASE_POLICY.replace(
                            NORMATIVE_PRERELEASE_CLAUSE, replacement
                        )
                    ),
                    "normative prerelease clause missing or altered",
                )

    def test_every_affirmative_general_availability_instruction_is_refused(self) -> None:
        """An added GA instruction is refused even with the clause left intact."""
        instructions = (
            ("ordinary release", "Publish each Release as an ordinary release."),
            (
                "general-availability release",
                "Publish each Release as a general-availability release.",
            ),
            ("GA release", "Publish each Release as a GA release."),
            ("prerelease disabled", "Create the Release with `prerelease: false`."),
            ("product declared available", "Deedseal is generally available."),
            (
                "check treated as GA evidence",
                "A passing check is sufficient evidence of general availability.",
            ),
            (
                "availability asserted as reached",
                "General availability is reached once the suites pass.",
            ),
        )
        for name, sentence in instructions:
            with self.subTest(instruction=name):
                violation = release_policy_violation(
                    f"{REFERENCE_RELEASE_POLICY}\n{sentence}\n"
                )
                self.assertIsNotNone(violation, f"{name} was not refused")
                self.assertTrue(
                    violation.startswith(
                        "affirmative general-availability instruction"
                    ),
                    violation,
                )

    def test_truthful_prerelease_boundary_language_is_accepted(self) -> None:
        """The boundary names general availability in order to defer it."""
        truthful = (
            "Every Release stays a prerelease "
            f"{TRUTHFUL_GENERAL_AVAILABILITY_BOUNDARY}.",
            "Deedseal is not generally available.",
            "A passing check is not evidence of general availability.",
            "No Release is published as an ordinary release.",
            "The Release is created with `prerelease: true`.",
        )
        for sentence in truthful:
            with self.subTest(sentence=sentence):
                self.assertIsNone(
                    release_policy_violation(
                        f"{REFERENCE_RELEASE_POLICY}\n{sentence}\n"
                    )
                )

    def test_candidate_notes_use_one_exact_source_placeholder_for_proof_links(self) -> None:
        notes = (ROOT / "docs/releases/v0.2.0-prerelease-notes.md").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(notes.count("SOURCE_SHA_PLACEHOLDER"), 12)
        self.assertNotIn("/blob/main/", notes)
        for heading in (
            "## Status boundary",
            "## Exact source",
            "## Changes",
            "## Proof links",
            "## Verification",
            "## Release manifest, assets and checksums",
            "## Known limitations",
            "## Non-claims",
        ):
            self.assertIn(heading, notes)

    def test_changelog_separates_the_four_candidate_concerns(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("[Unreleased] — v0.2.0 prerelease candidate", changelog)
        for heading in ("Product presentation", "Brand", "Evidence", "Tooling"):
            self.assertIn(f"### {heading}", changelog)

    def test_codeowners_names_the_owner_for_the_complete_surface(self) -> None:
        codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
        self.assertEqual(codeowners, "* @avoroncov971-maker\n")

    def test_browser_verifier_actions_match_the_existing_immutable_pins(self) -> None:
        """The two workflows carry the same pins, in the same canonical case.

        The pattern is lowercase-only on purpose. A case-insensitive one cannot
        see a divergence it then normalises away, and the pins have to be
        byte-equal for the disclosure exception to recognise both of them.
        """
        pattern = re.compile(
            r"uses:\s+actions/(?P<action>checkout|setup-go)@(?P<sha>[0-9a-f]{40})"
        )
        validation = (ROOT / ".github/workflows/validate-public-record.yml").read_text(
            encoding="utf-8"
        )
        browser = (ROOT / ".github/workflows/verifier-wasm.yml").read_text(
            encoding="utf-8"
        )
        expected = {
            match.group("action"): match.group("sha")
            for match in pattern.finditer(validation)
        }
        observed = {
            match.group("action"): match.group("sha")
            for match in pattern.finditer(browser)
        }
        self.assertEqual(set(observed), {"checkout", "setup-go"})
        self.assertEqual(observed, expected)

    def test_publication_workflow_runs_the_release_manifest_hostile_suite(self) -> None:
        workflow = (ROOT / ".github/workflows/validate-public-record.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(workflow.count("tools/test_release_manifest.py"), 1)


# ----------------------------------------------------------------------
# additive public-story contradictions, mutated in disposable public trees
# ----------------------------------------------------------------------

class AdditivePublicClaimGuardTests(unittest.TestCase):
    """Every Issue #67 claim class fails closed on a real Markdown surface."""

    def _copy_public_tree(self, destination: Path) -> Path:
        root = destination / "repo"
        shutil.copytree(
            ROOT,
            root,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        return root

    def _prove_hostile_and_limited(
        self,
        relative: str,
        hostile: str,
        limited: str,
        reason: str,
    ) -> None:
        """Land each mutation, run the real tree scan, then discard the copy."""
        source = ROOT / relative
        source_bytes = source.read_bytes()
        for label, sentence, expected in (
            ("hostile", hostile, reason),
            ("limited", limited, None),
        ):
            with self.subTest(form=label), tempfile.TemporaryDirectory() as temporary:
                copy_root = self._copy_public_tree(Path(temporary))
                path = copy_root / relative
                before = path.read_bytes()
                mutation = f"\n{sentence}\n".encode("utf-8")
                path.write_bytes(before + mutation)

                # Prove the mutation landed before interpreting the validator.
                self.assertNotEqual(path.read_bytes(), before)
                self.assertIn(mutation, path.read_bytes())

                with mock.patch.object(gate, "ROOT", copy_root):
                    if expected is None:
                        gate.validate_public_text()
                    else:
                        with self.assertRaisesRegex(
                            gate.ValidationError,
                            rf"{re.escape(relative)}: contains forbidden "
                            rf"{re.escape(expected)}",
                        ):
                            gate.validate_public_text()

            # The disposable copy is gone; the candidate source is unchanged.
            self.assertEqual(source.read_bytes(), source_bytes)

    def test_invented_live_lockup_geometry_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "README.md",
            "The live wordmark and green point lockup has a 64-by-64 geometry.",
            "The live lockup has no specified geometry.",
            "manufactured live-lockup geometry specification",
        )

    def test_invented_live_lockup_colour_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "assets/README.md",
            "The live wordmark and green point lockup uses colour #00FF00.",
            "The live lockup has no published colour.",
            "manufactured live-lockup colour specification",
        )

    def test_invented_live_lockup_digest_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "CHANGELOG.md",
            "The live wordmark and green point lockup has digest sha256:deadbeef.",
            "The live lockup has no published digest.",
            "manufactured live-lockup digest specification",
        )

    def test_invented_live_lockup_filename_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "docs/releases/v0.2.0-prerelease-notes.md",
            "The live wordmark and green point lockup is file assets/live-lockup.svg.",
            "The live lockup has no published filename.",
            "manufactured live-lockup filename specification",
        )

    def test_invented_live_lockup_version_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "README.md",
            "The live wordmark and green point lockup is version 1.0.",
            "The live lockup has no assigned version.",
            "manufactured live-lockup version specification",
        )

    def test_v0_2_0_available_claim_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "docs/faq.md",
            "`v0.2.0` is available.",
            "No `v0.2.0` tag or Release exists.",
            "manufactured v0.2.0 publication claim",
        )

    def test_general_availability_claim_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "docs/status.md",
            "Deedseal is generally available.",
            "Deedseal is not generally available.",
            "manufactured general-availability claim",
        )

    def test_public_price_claim_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "README.md",
            "Deedseal costs $99.",
            "No public price is stated.",
            "unapproved public price claim",
        )

    def test_savings_claim_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "CHANGELOG.md",
            "Deedseal saves customers 40%.",
            "No savings of 40% are claimed.",
            "unapproved savings claim",
        )

    def test_customer_claim_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "README.md",
            "West Coast KBP is a Deedseal customer.",
            "West Coast KBP is not a customer.",
            "unapproved customer claim",
        )

    def test_partner_claim_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "README.md",
            "West Coast KBP is a Deedseal partner.",
            "West Coast KBP is not a partner.",
            "unapproved partner claim",
        )

    def test_deployment_claim_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "docs/faq.md",
            "Deedseal is deployed with West Coast KBP.",
            "Deedseal is not deployed with West Coast KBP.",
            "unapproved deployment claim",
        )

    def test_business_outcome_claim_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "README.md",
            "Deedseal has delivered a business outcome.",
            "Deedseal has not delivered a business outcome.",
            "unapproved business-outcome claim",
        )

    def test_zero_egress_claim_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "docs/faq.md",
            "Deedseal guarantees zero-egress.",
            "Deedseal makes no zero-egress claim.",
            "unapproved zero-egress claim",
        )

    def test_fully_local_claim_is_refused(self) -> None:
        self._prove_hostile_and_limited(
            "docs/releases/v0.2.0-prerelease-notes.md",
            "Deedseal runs fully local.",
            "Deedseal is not fully local.",
            "unapproved fully-local claim",
        )

    def test_audit_logging_and_signed_evidence_outcomes_remain_separate(self) -> None:
        accepted = (
            "An audit log records a deployment outcome.",
            "A signed run passport carries an offline-verifiable custody outcome.",
        )
        for sentence in accepted:
            with self.subTest(sentence=sentence):
                self.assertIsNone(gate.public_markdown_claim_violation(sentence))

    def test_every_committed_public_markdown_surface_is_clean(self) -> None:
        scanned = []
        for path in gate.all_public_files():
            relative = path.relative_to(ROOT)
            if relative.suffix.lower() != ".md":
                continue
            scanned.append(relative.as_posix())
            self.assertIsNone(
                gate.public_markdown_claim_violation(
                    path.read_text(encoding="utf-8")
                ),
                relative.as_posix(),
            )
        self.assertIn("README.md", scanned)
        self.assertIn("docs/faq.md", scanned)
        self.assertIn("docs/releases/v0.2.0-prerelease-notes.md", scanned)


# ----------------------------------------------------------------------
# the immutable Action pin: one narrow, syntax-aware exception to the rule
# that a commit-shaped value in a public file is a private coordinate
# ----------------------------------------------------------------------

# Commit-shaped fixtures, assembled rather than written out: this file is itself
# inside the public scan, and a literal 40-hex value here would be a disclosure.
LOWERCASE_PIN = "a" * 40
SECOND_PIN = "b" * 40
UPPERCASE_PIN = "A" * 40
MIXED_CASE_PIN = "A" * 20 + "a" * 20
SHORT_PIN = "a" * 7

WORKFLOW_FIXTURE_PATH = Path(".github/workflows/fixture.yml")
CHECKOUT = "actions/checkout"


def workflow_fixture(*step_lines: str) -> str:
    """A minimal but structurally real workflow carrying the given step lines."""
    body = "\n".join(f"      {line}" for line in step_lines)
    return (
        "name: Fixture\n"
        "\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "\n"
        "permissions:\n"
        "  contents: read\n"
        "\n"
        "jobs:\n"
        "  job:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"{body}\n"
    )


def pinned_step(ref: str, action: str = CHECKOUT) -> str:
    return f"- uses: {action}@{ref}"


class WorkflowActionPinDisclosureTests(unittest.TestCase):
    """The disclosure exception for immutable Action pins, and its limits.

    The rule under test is that a 40-hex value in a public file is a private
    repository coordinate. A pinned workflow has to carry commit-shaped values
    to be pinned at all, so exactly one exception exists. It is syntax-aware,
    not per-file: the exception recognises a complete `uses:` entry in a
    workflow whose ref is 40 lowercase hexadecimal characters and whose line
    carries no second commit-shaped value. Everything else -- including
    everything else in the same file -- stays under the rule.
    """

    WORKFLOWS = (
        ".github/workflows/validate-public-record.yml",
        ".github/workflows/verifier-wasm.yml",
    )

    def workflow_text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    # -- what the committed tree carries ------------------------------------

    def test_the_committed_workflows_pin_every_action_to_a_lowercase_commit(self) -> None:
        for relative in self.WORKFLOWS:
            with self.subTest(workflow=relative):
                path = Path(relative)
                text = self.workflow_text(relative)
                self.assertEqual(gate.workflow_pin_violations(path, text), [])
                self.assertIsNone(gate.disclosure_violation(path, text))
                pins = gate.workflow_action_pins(path, text)
                self.assertTrue(pins)
                for ref in pins.values():
                    self.assertRegex(ref, r"^[0-9a-f]{40}$")

    def test_the_browser_verifier_pins_are_lowercase_forty_hex(self) -> None:
        text = self.workflow_text(".github/workflows/verifier-wasm.yml")
        refs = re.findall(r"uses:[ \t]+actions/(?:checkout|setup-go)@(\S+)", text)
        self.assertEqual(len(refs), 2)
        for ref in refs:
            with self.subTest(ref=ref[:8]):
                self.assertRegex(ref, r"^[0-9a-f]{40}$")
                self.assertEqual(ref, ref.lower())

    def test_no_workflow_is_exempt_by_its_path(self) -> None:
        """The replaced rule waived one named file. Nothing is waived by name now."""
        for relative in self.WORKFLOWS:
            with self.subTest(workflow=relative):
                text = self.workflow_text(relative)
                self.assertEqual(
                    gate.disclosure_violation(
                        Path(relative), f"{text}\n# a note about {SECOND_PIN}\n"
                    ),
                    "private commit identifier",
                )

    # -- what the exception accepts -----------------------------------------

    def test_an_immutable_action_pin_is_accepted_in_its_canonical_shapes(self) -> None:
        accepted = {
            "step entry": workflow_fixture(pinned_step(LOWERCASE_PIN)),
            "quoted reference": workflow_fixture(
                f'- uses: "{CHECKOUT}@{LOWERCASE_PIN}"'
            ),
            "trailing comment": workflow_fixture(
                f"{pinned_step(LOWERCASE_PIN)}  # pinned upstream release"
            ),
            "action in a subdirectory": workflow_fixture(
                pinned_step(LOWERCASE_PIN, "deedseal/deedseal/.github/actions/verify")
            ),
            "two pins in one workflow": workflow_fixture(
                pinned_step(LOWERCASE_PIN),
                pinned_step(SECOND_PIN, "actions/setup-go"),
            ),
        }
        for name, text in accepted.items():
            with self.subTest(shape=name):
                self.assertIsNone(
                    gate.disclosure_violation(WORKFLOW_FIXTURE_PATH, text)
                )
                self.assertEqual(
                    gate.workflow_pin_violations(WORKFLOW_FIXTURE_PATH, text), []
                )

    def test_local_and_container_action_references_need_no_commit_pin(self) -> None:
        """Neither names an upstream commit, so neither can be pinned to one."""
        for reference in ("./.github/actions/local", "docker://alpine:3.20"):
            with self.subTest(reference=reference):
                text = workflow_fixture(f"- uses: {reference}")
                self.assertEqual(
                    gate.workflow_pin_violations(WORKFLOW_FIXTURE_PATH, text), []
                )
                self.assertIsNone(
                    gate.disclosure_violation(WORKFLOW_FIXTURE_PATH, text)
                )

    # -- what the exception must never reach --------------------------------

    def test_a_commit_outside_a_uses_entry_is_refused_inside_a_workflow(self) -> None:
        """Issue #61: the exception cannot disclose an arbitrary 40-hex value."""
        elsewhere = {
            "comment": workflow_fixture(f"# rebuilt from {LOWERCASE_PIN}"),
            "run command": workflow_fixture(f"- run: git checkout {LOWERCASE_PIN}"),
            "run block scalar": workflow_fixture(
                "- run: |",
                f"    uses: {CHECKOUT}@{LOWERCASE_PIN}",
            ),
            "step name": workflow_fixture(f"- name: build {LOWERCASE_PIN}"),
            "env value": workflow_fixture(
                "- run: build.sh", "  env:", f"    SOURCE_REF: {LOWERCASE_PIN}"
            ),
            "action input": workflow_fixture(
                pinned_step(SECOND_PIN), "  with:", f"    ref: {LOWERCASE_PIN}"
            ),
            "arbitrary yaml value": workflow_fixture(f"- ref: {LOWERCASE_PIN}"),
            "yaml list item": workflow_fixture(f"- {LOWERCASE_PIN}"),
            "key that merely ends in uses": workflow_fixture(
                f"- not-uses: {CHECKOUT}@{LOWERCASE_PIN}"
            ),
            "uses inside a quoted string": workflow_fixture(
                f'- name: "uses: {CHECKOUT}@{LOWERCASE_PIN}"'
            ),
        }
        for name, text in elsewhere.items():
            with self.subTest(placement=name):
                self.assertEqual(
                    gate.disclosure_violation(WORKFLOW_FIXTURE_PATH, text),
                    "private commit identifier",
                    f"{name} was not refused",
                )

    def test_a_second_commit_on_a_pin_line_is_refused(self) -> None:
        """The entry classifies its own ref and nothing else on the line."""
        for name, line in (
            (
                "trailing comment",
                f"{pinned_step(LOWERCASE_PIN)}  # was {SECOND_PIN}",
            ),
            ("appended value", f"{pinned_step(LOWERCASE_PIN)} {SECOND_PIN}"),
        ):
            with self.subTest(line=name):
                text = workflow_fixture(line)
                self.assertEqual(
                    gate.disclosure_violation(WORKFLOW_FIXTURE_PATH, text),
                    "private commit identifier",
                )
                self.assertEqual(gate.workflow_action_pins(WORKFLOW_FIXTURE_PATH, text), {})

    def test_the_exception_does_not_reach_outside_a_workflow_file(self) -> None:
        text = workflow_fixture(pinned_step(LOWERCASE_PIN))
        outside = (
            "README.md",
            "docs/verify.md",
            "CHANGELOG.md",
            ".github/CODEOWNERS",
            ".github/dependabot.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/workflows/notes.txt",
            ".github/workflows/README.md",
            "workflows/verifier-wasm.yml",
            "docs/.github/workflows/example.yml",
        )
        for relative in outside:
            with self.subTest(path=relative):
                self.assertEqual(
                    gate.disclosure_violation(Path(relative), text),
                    "private commit identifier",
                    f"{relative} was exempted",
                )
                self.assertEqual(
                    gate.workflow_action_pins(Path(relative), text), {}
                )

    # -- pins this repository refuses to accept as immutable ----------------

    def test_an_uppercase_or_mixed_case_action_pin_is_refused(self) -> None:
        for name, ref in (
            ("uppercase", UPPERCASE_PIN),
            ("mixed case", MIXED_CASE_PIN),
        ):
            with self.subTest(case=name):
                text = workflow_fixture(pinned_step(ref))
                violations = gate.workflow_pin_violations(WORKFLOW_FIXTURE_PATH, text)
                self.assertEqual(len(violations), 1, violations)
                self.assertIn("lowercase commit SHA", violations[0])
                self.assertEqual(gate.workflow_action_pins(WORKFLOW_FIXTURE_PATH, text), {})

    def test_a_short_sha_action_pin_is_refused(self) -> None:
        for name, ref in (
            ("short", SHORT_PIN),
            ("one character short", "a" * 39),
            ("one character long", "a" * 41),
        ):
            with self.subTest(ref=name):
                text = workflow_fixture(pinned_step(ref))
                violations = gate.workflow_pin_violations(WORKFLOW_FIXTURE_PATH, text)
                self.assertEqual(len(violations), 1, violations)
                self.assertIn("lowercase commit SHA", violations[0])

    def test_a_mutable_tag_or_branch_action_pin_is_refused(self) -> None:
        for ref in ("v4", "v7.0.1", "main", "master", "latest", "refs/heads/main"):
            with self.subTest(ref=ref):
                text = workflow_fixture(pinned_step(ref))
                violations = gate.workflow_pin_violations(WORKFLOW_FIXTURE_PATH, text)
                self.assertEqual(len(violations), 1, violations)
                self.assertIn("lowercase commit SHA", violations[0])

    def test_a_malformed_or_unreadable_action_reference_is_refused(self) -> None:
        malformed = {
            "no ref at all": f"- uses: {CHECKOUT}",
            "no repository": f"- uses: checkout@{LOWERCASE_PIN}",
            "path traversal": (
                f"- uses: deedseal/deedseal/../private@{LOWERCASE_PIN}"
            ),
            "empty value": "- uses:",
            "value on the next line": "- uses:\n          actions/checkout",
        }
        for name, line in malformed.items():
            with self.subTest(reference=name):
                text = workflow_fixture(*line.split("\n"))
                self.assertTrue(
                    gate.workflow_pin_violations(WORKFLOW_FIXTURE_PATH, text),
                    f"{name} was not refused",
                )

    # -- everything the rule already refused, still refused ------------------

    def test_existing_disclosure_violations_still_refuse_inside_a_workflow(self) -> None:
        pinned = workflow_fixture(pinned_step(LOWERCASE_PIN))
        additions = {
            "private repository URL": (
                "# see https://github." + "com/" + "private-space/repository"
            ),
            "private host path": "# built from " + "/" + "home/" + "operator/tree",
            "credential-shaped token": "# token " + "gh" + "p_" + "A" * 30,
            "email address": "# owner " + "person" + "@" + "example.invalid",
            "network address": "# host " + "10." + "0.0." + "1",
            "non-English text": "# te" + chr(0x0445) + chr(0x0442) + "st",
        }
        for name, line in additions.items():
            with self.subTest(violation=name):
                self.assertIsNotNone(
                    gate.disclosure_violation(
                        WORKFLOW_FIXTURE_PATH, f"{pinned}{line}\n"
                    ),
                    f"{name} was not refused",
                )

    def test_published_passport_commit_scope_is_untouched_by_the_exception(self) -> None:
        self.assertIsNone(
            gate.disclosure_violation(
                Path("examples/verified/run-passport.json"),
                '{"commit_sha": "' + LOWERCASE_PIN + '"}',
            )
        )
        self.assertEqual(
            gate.disclosure_violation(Path("docs/verify.md"), LOWERCASE_PIN),
            "private commit identifier",
        )

    # -- the gate actually runs both rules over the committed tree -----------

    def test_the_repository_gate_refuses_a_loosened_pin_and_a_leaked_commit(self) -> None:
        """End-to-end, against the real tree, restored byte-for-byte afterwards."""
        path = ROOT / ".github/workflows/verifier-wasm.yml"
        original = path.read_bytes()
        text = original.decode("utf-8")
        pinned = re.search(
            r"uses:[ \t]+actions/checkout@[0-9a-f]{40}", text
        )
        self.assertIsNotNone(pinned)
        mutations = {
            "mutable tag": text.replace(
                pinned.group(0), "uses: actions/checkout@v4", 1
            ),
            "uppercase pin": text.replace(
                pinned.group(0), pinned.group(0).upper().replace("USES:", "uses:"), 1
            ),
            "commit leaked into a comment": f"{text}# {SECOND_PIN}\n",
        }
        try:
            for name, mutated in mutations.items():
                with self.subTest(mutation=name):
                    self.assertNotEqual(mutated, text)
                    path.write_text(mutated, encoding="utf-8", newline="")
                    with self.assertRaises(gate.ValidationError):
                        gate.validate_repository()
        finally:
            path.write_bytes(original)
        self.assertEqual(path.read_bytes(), original)
        gate.validate_repository()

if __name__ == "__main__":
    unittest.main(verbosity=2)
