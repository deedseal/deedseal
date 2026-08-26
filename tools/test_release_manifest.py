#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Unit and hostile tests for the deterministic release manifest builder."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import build_release_manifest as release


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        for relative in release.DISTRIBUTABLE_PATHS:
            source = ROOT / relative
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        self._git("init", "--quiet")
        self._git("config", "core.autocrlf", "false")
        self._git("config", "user.name", "Release Fixture")
        self._git("config", "user.email", "release-fixture")
        self._git("add", ".")
        self._git("commit", "--quiet", "-m", "Create release fixture")
        self.commit = self._git("rev-parse", "HEAD").strip()

    def _git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        return completed.stdout

    def _build(self, name: str = "output") -> Path:
        output = self.base / name
        release.build_release_outputs(self.repo, self.commit, output)
        return output

    def test_build_is_stable_across_external_directories_and_clock_values(self) -> None:
        with mock.patch.object(time, "time", return_value=1):
            first = self._build("first")
        with mock.patch.object(time, "time", return_value=9999999999):
            second = self._build("second")
        for name in (release.MANIFEST_NAME, release.CHECKSUMS_NAME):
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
        manifest = json.loads((first / release.MANIFEST_NAME).read_text(encoding="utf-8"))
        self.assertEqual(manifest["file_count"], len(release.DISTRIBUTABLE_PATHS))
        self.assertNotIn("generated_at", manifest)
        self.assertIn(
            "examples/verified/conformance/vectors/vector-047.json/.gitkeep",
            {entry["path"] for entry in manifest["files"]},
        )

    def test_path_traversal_and_noncanonical_paths_are_refused(self) -> None:
        for hostile in ("../secret", "a/../../secret", "/absolute", "a\\b", "./a"):
            with self.subTest(path=hostile), self.assertRaises(release.ReleaseManifestError):
                release.validate_relative_path(hostile)

    def test_a_symlink_in_the_release_surface_is_refused(self) -> None:
        target = self.repo / release.DISTRIBUTABLE_PATHS[0]
        original = target.with_name("verifier-original.py")
        target.rename(original)
        try:
            os.symlink(original.name, target)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable on this platform: {error}")
        with self.assertRaisesRegex(release.ReleaseManifestError, "symlink"):
            release.build_release_outputs(self.repo, self.commit, self.base / "symlink-output")

    def test_a_missing_release_file_is_refused(self) -> None:
        (self.repo / release.DISTRIBUTABLE_PATHS[-1]).unlink()
        with self.assertRaisesRegex(release.ReleaseManifestError, "missing="):
            release.build_release_outputs(self.repo, self.commit, self.base / "missing-output")

    def test_an_extra_release_file_is_refused(self) -> None:
        extra = self.repo / "examples/verified/conformance/vectors/vector-999.json"
        extra.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(release.ReleaseManifestError, "extra="):
            release.build_release_outputs(self.repo, self.commit, self.base / "extra-output")

    def test_digest_drift_in_emitted_checksums_is_refused(self) -> None:
        output = self._build()
        sums = output / release.CHECKSUMS_NAME
        text = sums.read_text(encoding="ascii")
        sums.write_text(("0" * 64) + text[64:], encoding="ascii")
        with self.assertRaisesRegex(release.ReleaseManifestError, "digest drifted"):
            release.verify_release_outputs(self.repo, self.commit, output)

    def test_timestamp_injection_is_refused_as_nondeterministic(self) -> None:
        output = self._build()
        path = output / release.MANIFEST_NAME
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["generated_at"] = "variable-clock-value"
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaises(release.ReleaseManifestError):
            release.verify_release_outputs(self.repo, self.commit, output)

    def test_dirty_worktree_is_refused(self) -> None:
        path = self.repo / release.DISTRIBUTABLE_PATHS[0]
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(release.ReleaseManifestError, "worktree must be clean"):
            release.build_release_outputs(self.repo, self.commit, self.base / "dirty-output")

    def test_short_nonhex_and_wrong_commits_are_refused(self) -> None:
        for hostile in ("abc123", "z" * 40, "A" * 40, "0" * 39):
            with self.subTest(commit=hostile), self.assertRaises(release.ReleaseManifestError):
                release.build_release_outputs(self.repo, hostile, self.base / ("bad-" + str(len(hostile))))
        with self.assertRaisesRegex(release.ReleaseManifestError, "does not equal worktree HEAD"):
            release.build_release_outputs(self.repo, "f" * 40, self.base / "wrong-output")

    def test_network_layer_can_be_disabled_for_a_complete_build(self) -> None:
        source = (ROOT / "tools/build_release_manifest.py").read_text(encoding="utf-8")
        for forbidden in ("import urllib", "import http.client", "import requests"):
            self.assertNotIn(forbidden, source)
        refusal = AssertionError("network use is forbidden")
        with mock.patch.object(socket, "socket", side_effect=refusal), mock.patch.object(
            socket, "create_connection", side_effect=refusal
        ):
            self._build("offline-output")

    def test_output_inside_worktree_is_refused_without_writing(self) -> None:
        output = self.repo / "release-output"
        with self.assertRaisesRegex(release.ReleaseManifestError, "outside the worktree"):
            release.build_release_outputs(self.repo, self.commit, output)
        self.assertFalse(output.exists())

    def test_output_must_be_fresh_and_exactly_two_files(self) -> None:
        occupied = self.base / "occupied"
        occupied.mkdir()
        with self.assertRaisesRegex(release.ReleaseManifestError, "must be fresh"):
            release.build_release_outputs(self.repo, self.commit, occupied)
        output = self._build("exact-output")
        (output / "extra").write_text("unexpected\n", encoding="utf-8")
        with self.assertRaisesRegex(release.ReleaseManifestError, "missing or extra"):
            release.verify_release_outputs(self.repo, self.commit, output)

    def test_build_does_not_modify_the_supplied_worktree(self) -> None:
        before = self._git("status", "--porcelain=v1", "--untracked-files=all")
        self._build()
        after = self._git("status", "--porcelain=v1", "--untracked-files=all")
        self.assertEqual(before, "")
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
