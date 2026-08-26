#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
"""Build a deterministic manifest for the bounded Deedseal release surface.

The command is deliberately a local, read-only inventory operation. It accepts
one clean Git worktree at one full HEAD commit and writes only two new files in
a fresh directory outside that worktree. It has no publication, tagging,
signing, credential, or network behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA_VERSION = "deedseal.release-manifest/v1"
PUBLIC_REPOSITORY = "deedseal/deedseal"
MANIFEST_NAME = "release-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
FULL_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

# This is the complete release-distributable public-record surface for the
# v0.2.0 prerelease candidate. The conformance manifest declares 48 cases: 46
# are file-backed below, one requires a directory, and one requires absence.
DISTRIBUTABLE_PATHS = (
    "tools/verify_run_passport.py",
    "examples/verified/run-passport.json",
    "examples/verified/run-passport.tampered.json",
    "examples/verified/run-002/run-passport.json",
    "examples/verified/run-002/run-passport.tampered.json",
    "examples/verified/conformance/manifest.json",
    *(f"examples/verified/conformance/vectors/vector-{number:03d}.json"
      for number in range(1, 47)),
    "examples/verified/conformance/vectors/vector-047.json/.gitkeep",
)


class ReleaseManifestError(Exception):
    """The requested release inventory is not safe or exact."""


def fail(message: str) -> None:
    raise ReleaseManifestError(message)


def validate_commit(commit: str) -> str:
    if FULL_COMMIT_RE.fullmatch(commit) is None:
        fail("commit must be an exact 40-character lowercase hexadecimal SHA")
    return commit


def validate_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value:
        fail(f"release path is not canonical: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"release path traverses outside its bounded root: {value!r}")
    if path.as_posix() != value:
        fail(f"release path is not canonical: {value!r}")
    return path


def _git(worktree: Path, *arguments: str) -> str:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    command = [
        "git",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-C",
        str(worktree),
        *arguments,
    ]
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "Git command failed"
        fail(detail)
    return completed.stdout.rstrip("\n")


def _worktree_root(worktree: Path) -> Path:
    if worktree.is_symlink():
        fail("worktree itself must not be a symlink")
    try:
        root = worktree.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        fail(f"worktree is not available: {error}")
    if not root.is_dir():
        fail("worktree must be a directory")
    top = Path(_git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if top != root:
        fail("worktree must name the exact Git repository root")
    return root


def _assert_repository_state(root: Path, commit: str) -> None:
    observed = _git(root, "rev-parse", "HEAD")
    if observed != commit:
        fail(f"supplied commit does not equal worktree HEAD: {observed}")
    dirty = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        fail("worktree must be clean, including untracked files")


def _output_path(root: Path, output: Path) -> Path:
    if output.is_symlink():
        fail("output directory must not be a symlink")
    resolved = output.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError:
        pass
    else:
        fail("output directory must be outside the worktree")
    if resolved.exists():
        fail("output directory must be fresh and must not already exist")
    return resolved


def _discovered_surface(root: Path) -> set[str]:
    discovered: set[str] = set()
    verifier = root / "tools/verify_run_passport.py"
    if verifier.exists() or verifier.is_symlink():
        discovered.add("tools/verify_run_passport.py")

    verified = root / "examples/verified"
    if verified.is_dir():
        for candidate in verified.rglob("run-passport*"):
            discovered.add(candidate.relative_to(root).as_posix())

    conformance = verified / "conformance/manifest.json"
    if conformance.exists() or conformance.is_symlink():
        discovered.add(conformance.relative_to(root).as_posix())

    vectors = verified / "conformance/vectors"
    if vectors.is_dir():
        for candidate in vectors.rglob("*"):
            if candidate.is_file() or candidate.is_symlink():
                discovered.add(candidate.relative_to(root).as_posix())
    return discovered


def _inventory_paths(root: Path) -> list[tuple[str, Path]]:
    required = set(DISTRIBUTABLE_PATHS)
    discovered = _discovered_surface(root)
    missing = sorted(required - discovered)
    extra = sorted(discovered - required)
    if missing or extra:
        fail(f"release file set differs from the bounded set; missing={missing}, extra={extra}")

    inventory: list[tuple[str, Path]] = []
    for raw in DISTRIBUTABLE_PATHS:
        relative = validate_relative_path(raw)
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                fail(f"release path contains a symlink: {raw}")
        if not current.is_file():
            fail(f"release path is not a regular file: {raw}")
        try:
            current.resolve(strict=True).relative_to(root)
        except ValueError:
            fail(f"release path escapes the worktree: {raw}")
        inventory.append((raw, current))
    return sorted(inventory)


def _digest(path: Path) -> tuple[str, int]:
    before = path.stat()
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    after = path.stat()
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or size != before.st_size:
        fail(f"release file changed while it was read: {path.name}")
    return digest.hexdigest(), size


def _manifest(root: Path, commit: str) -> dict[str, Any]:
    files = []
    for relative, path in _inventory_paths(root):
        digest, size = _digest(path)
        files.append({"path": relative, "sha256": digest, "size": size})
    return {
        "schema_version": SCHEMA_VERSION,
        "source": {"repository": PUBLIC_REPOSITORY, "commit": commit},
        "file_count": len(files),
        "files": files,
    }


def _manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def _checksums_bytes(manifest: dict[str, Any]) -> bytes:
    return "".join(
        f"{entry['sha256']}  {entry['path']}\n" for entry in manifest["files"]
    ).encode("ascii")


def _strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(values: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                fail(f"release manifest repeats JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"release manifest is not canonical JSON: {error}")
    if not isinstance(value, dict):
        fail("release manifest root must be an object")
    return value


def _write_new(path: Path, payload: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(payload)


def verify_release_outputs(worktree: Path, commit: str, output: Path) -> None:
    """Independently re-derive and verify a previously emitted pair."""
    commit = validate_commit(commit)
    root = _worktree_root(worktree)
    _assert_repository_state(root, commit)
    resolved_output = output.resolve(strict=True)
    try:
        resolved_output.relative_to(root)
    except ValueError:
        pass
    else:
        fail("output directory must be outside the worktree")
    if resolved_output.is_symlink() or not resolved_output.is_dir():
        fail("output must be a regular external directory")
    observed_names = {item.name for item in resolved_output.iterdir()}
    expected_names = {MANIFEST_NAME, CHECKSUMS_NAME}
    if observed_names != expected_names:
        fail("output directory contains missing or extra files")

    observed_manifest_raw = (resolved_output / MANIFEST_NAME).read_bytes()
    observed_manifest = _strict_json(observed_manifest_raw)
    expected_manifest = _manifest(root, commit)
    if observed_manifest != expected_manifest:
        fail("release manifest content or digest drifted from the exact worktree")
    if observed_manifest_raw != _manifest_bytes(expected_manifest):
        fail("release manifest contains nondeterministic or noncanonical bytes")
    observed_sums = (resolved_output / CHECKSUMS_NAME).read_bytes()
    if observed_sums != _checksums_bytes(expected_manifest):
        fail("SHA256SUMS content or digest drifted from the release manifest")
    _assert_repository_state(root, commit)


def build_release_outputs(worktree: Path, commit: str, output: Path) -> dict[str, Any]:
    commit = validate_commit(commit)
    root = _worktree_root(worktree)
    destination = _output_path(root, output)
    # Establish the bounded filesystem surface before asking Git about dirt so
    # symlinks and missing/extra release files receive their own fail-closed
    # verdict instead of being hidden behind a generic worktree verdict.
    _inventory_paths(root)
    _assert_repository_state(root, commit)
    manifest = _manifest(root, commit)
    _assert_repository_state(root, commit)

    destination.mkdir(parents=True, exist_ok=False)
    _write_new(destination / MANIFEST_NAME, _manifest_bytes(manifest))
    _write_new(destination / CHECKSUMS_NAME, _checksums_bytes(manifest))
    verify_release_outputs(root, commit, destination)
    return manifest


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        manifest = build_release_outputs(args.worktree, args.commit, args.output)
    except ReleaseManifestError as error:
        print(f"RELEASE_MANIFEST: BLOCK {error}", file=sys.stderr)
        return 1
    print(
        f"RELEASE_MANIFEST: PASS commit={manifest['source']['commit']} "
        f"files={manifest['file_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
