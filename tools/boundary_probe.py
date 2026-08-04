#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Re-apply a passport's recorded Landlock boundary to local scratch paths."""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PASSPORT = ROOT / "examples/verified/run-passport.json"

LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38

# These bit positions are the Linux Landlock userspace ABI. The set of bits
# selected for a run is always derived from the passport, never from this map.
ACCESS_BITS = {
    "execute": 1 << 0,
    "write_file": 1 << 1,
    "read_file": 1 << 2,
    "read_dir": 1 << 3,
    "remove_dir": 1 << 4,
    "remove_file": 1 << 5,
    "make_char": 1 << 6,
    "make_dir": 1 << 7,
    "make_reg": 1 << 8,
    "make_sock": 1 << 9,
    "make_fifo": 1 << 10,
    "make_block": 1 << 11,
    "make_sym": 1 << 12,
    "refer": 1 << 13,
    "truncate": 1 << 14,
    "ioctl_dev": 1 << 15,
}

SYSCALLS_BY_MACHINE = {
    "aarch64": (444, 445, 446),
    "arm64": (444, 445, 446),
    "riscv64": (444, 445, 446),
    "x86_64": (444, 445, 446),
}

DENIAL_ERRNOS = {errno.EACCES, errno.EPERM}


class ProbeError(RuntimeError):
    """A named probe failure suitable for terminal output."""


class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProbeError(f"{label} must be an object")
    return value


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProbeError(f"{label} must be a non-empty string")
    return value


def require_string_list(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
        or len(value) != len(set(value))
    ):
        raise ProbeError(f"{label} must be a non-empty list of unique strings")
    unknown = sorted(set(value) - set(ACCESS_BITS))
    if unknown:
        raise ProbeError(f"{label} contains unsupported access rights: {unknown}")
    return value


def access_mask(names: list[str]) -> int:
    mask = 0
    for name in names:
        mask |= ACCESS_BITS[name]
    return mask


def load_boundary(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProbeError(f"passport unreadable: {exc.strerror or exc}") from None
    try:
        passport = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProbeError(f"passport is not valid UTF-8 JSON: {exc}") from None

    root = require_mapping(passport, "passport")
    custody = require_mapping(root.get("custody"), "custody")
    report = require_mapping(custody.get("runner_report"), "custody.runner_report")
    boundary = require_mapping(
        report.get("os_boundary"), "custody.runner_report.os_boundary"
    )

    abi = boundary.get("abi")
    if type(abi) is not int or abi < 1:
        raise ProbeError("os_boundary.abi must be a positive integer")
    if boundary.get("default_for_handled_access") != "deny":
        raise ProbeError("os_boundary.default_for_handled_access must be 'deny'")
    if boundary.get("no_new_privs") is not True:
        raise ProbeError("os_boundary.no_new_privs must be true")

    handled = require_string_list(
        boundary.get("handled_access_fs"), "os_boundary.handled_access_fs"
    )
    rules = boundary.get("rules")
    if not isinstance(rules, list) or len(rules) != 1:
        raise ProbeError("os_boundary.rules must contain exactly one granted-file rule")
    rule = require_mapping(rules[0], "os_boundary.rules[0]")
    require_string(rule.get("allowed_file"), "os_boundary.rules[0].allowed_file")
    allowed = require_string_list(
        rule.get("allowed_access_fs"),
        "os_boundary.rules[0].allowed_access_fs",
    )
    if allowed != ["write_file"]:
        raise ProbeError(
            "os_boundary.rules[0].allowed_access_fs must permit only write_file"
        )
    if set(allowed) - set(handled):
        raise ProbeError("the granted-file rule includes an unhandled access right")

    scratch = require_mapping(boundary.get("runtime_scratch"), "os_boundary.runtime_scratch")
    scratch_class = require_string(
        scratch.get("scratch_class"), "os_boundary.runtime_scratch.scratch_class"
    )
    scratch_allowed = require_string_list(
        scratch.get("allowed_access_fs"),
        "os_boundary.runtime_scratch.allowed_access_fs",
    )
    if set(scratch_allowed) - set(handled):
        raise ProbeError("the runtime-scratch class includes an unhandled access right")
    require_string(
        scratch.get("scratch_root_sha256"),
        "os_boundary.runtime_scratch.scratch_root_sha256",
    )

    return {
        "abi": abi,
        "handled": handled,
        "allowed": allowed,
        "rule_count": len(rules),
        "scratch_class": scratch_class,
    }


def syscall_numbers() -> tuple[int, int, int] | None:
    return SYSCALLS_BY_MACHINE.get(platform.machine().lower())


def raw_syscall(libc: ctypes.CDLL, number: int, *args: object) -> int:
    ctypes.set_errno(0)
    result = libc.syscall(number, *args)
    if result == -1:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return int(result)


def query_local_abi(libc: ctypes.CDLL, create_number: int) -> int:
    return raw_syscall(
        libc,
        create_number,
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
    )


def apply_boundary(
    libc: ctypes.CDLL,
    syscall_ids: tuple[int, int, int],
    handled_mask: int,
    allowed_mask: int,
    permitted_file: Path,
) -> None:
    create_number, add_number, restrict_number = syscall_ids
    ctypes.set_errno(0)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1:
        error_number = ctypes.get_errno()
        raise ProbeError(
            f"prctl(PR_SET_NO_NEW_PRIVS) failed: {errno.errorcode.get(error_number, error_number)}"
        )

    ruleset_attr = RulesetAttr(handled_access_fs=handled_mask)
    try:
        ruleset_fd = raw_syscall(
            libc,
            create_number,
            ctypes.byref(ruleset_attr),
            ctypes.sizeof(ruleset_attr),
            ctypes.c_uint32(0),
        )
    except OSError as exc:
        name = errno.errorcode.get(exc.errno, str(exc.errno))
        raise ProbeError(f"landlock_create_ruleset failed: {name}") from None

    path_fd = -1
    try:
        path_fd = os.open(permitted_file, os.O_PATH | os.O_CLOEXEC)
        path_attr = PathBeneathAttr(
            allowed_access=allowed_mask,
            parent_fd=path_fd,
        )
        try:
            raw_syscall(
                libc,
                add_number,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                ctypes.byref(path_attr),
                ctypes.c_uint32(0),
            )
            raw_syscall(
                libc,
                restrict_number,
                ruleset_fd,
                ctypes.c_uint32(0),
            )
        except OSError as exc:
            name = errno.errorcode.get(exc.errno, str(exc.errno))
            raise ProbeError(f"Landlock ruleset application failed: {name}") from None
    except OSError as exc:
        name = errno.errorcode.get(exc.errno, str(exc.errno))
        raise ProbeError(f"stand-in path setup failed: {name}") from None
    finally:
        if path_fd >= 0:
            os.close(path_fd)
        os.close(ruleset_fd)


def observe(operation: Callable[[], None]) -> int:
    try:
        operation()
    except OSError as exc:
        return exc.errno or errno.EIO
    return 0


def child_probe(
    write_fd: int,
    scratch: Path,
    permitted_file: Path,
    handled_mask: int,
    allowed_mask: int,
    syscall_ids: tuple[int, int, int],
) -> None:
    payload: dict[str, Any]
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        apply_boundary(
            libc,
            syscall_ids,
            handled_mask,
            allowed_mask,
            permitted_file,
        )

        def append_permitted() -> None:
            descriptor = os.open(permitted_file, os.O_WRONLY | os.O_APPEND)
            try:
                os.write(descriptor, b"probe\n")
            finally:
                os.close(descriptor)

        def create_second() -> None:
            descriptor = os.open(
                scratch / "second-file",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(descriptor)

        operations: list[tuple[str, Callable[[], None]]] = [
            ("append_permitted_file", append_permitted),
            ("create_second_file", create_second),
            ("create_directory", lambda: os.mkdir(scratch / "second-directory")),
            ("create_symbolic_link", lambda: os.symlink("permitted-file", scratch / "link")),
            ("unlink_permitted_file", lambda: os.unlink(permitted_file)),
        ]
        payload = {
            "results": {name: observe(operation) for name, operation in operations}
        }
    except ProbeError as exc:
        payload = {"setup_error": str(exc)}
    except BaseException as exc:
        payload = {"setup_error": f"unexpected child error: {type(exc).__name__}: {exc}"}

    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    try:
        os.write(write_fd, encoded)
    except OSError:
        pass
    finally:
        os.close(write_fd)


def run_probe(boundary: dict[str, Any]) -> int:
    syscall_ids = syscall_numbers()
    if syscall_ids is None:
        print(
            "BOUNDARY_PROBE_SKIP: unsupported Linux architecture "
            f"{platform.machine() or 'unknown'}; kernel enforcement was not checked"
        )
        return 0

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        local_abi = query_local_abi(libc, syscall_ids[0])
    except OSError as exc:
        name = errno.errorcode.get(exc.errno, str(exc.errno))
        if exc.errno in {errno.ENOSYS, errno.EOPNOTSUPP}:
            print(
                "BOUNDARY_PROBE_SKIP: Landlock ABI unavailable; kernel enforcement "
                f"was not checked; errno={name}"
            )
            return 0
        raise ProbeError(f"Landlock ABI query failed: {name}") from None
    if local_abi < 1:
        print(
            "BOUNDARY_PROBE_SKIP: Landlock ABI unavailable; kernel enforcement "
            f"was not checked; reported_abi={local_abi}"
        )
        return 0
    print(f"local_landlock_abi: {local_abi}")

    handled_mask = access_mask(boundary["handled"])
    allowed_mask = access_mask(boundary["allowed"])
    scratch_path = Path(tempfile.mkdtemp(prefix="deedseal-boundary-probe-"))
    try:
        permitted_file = scratch_path / "permitted-file"
        permitted_file.write_bytes(b"initial\n")
        read_fd, write_fd = os.pipe()
        try:
            child_pid = os.fork()
        except OSError as exc:
            os.close(read_fd)
            os.close(write_fd)
            name = errno.errorcode.get(exc.errno, str(exc.errno))
            raise ProbeError(f"fork failed: {name}") from None
        if child_pid == 0:
            os.close(read_fd)
            child_probe(
                write_fd,
                scratch_path,
                permitted_file,
                handled_mask,
                allowed_mask,
                syscall_ids,
            )
            os._exit(0)

        os.close(write_fd)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(read_fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
        os.close(read_fd)
        _, wait_status = os.waitpid(child_pid, 0)
        if not os.WIFEXITED(wait_status) or os.WEXITSTATUS(wait_status) != 0:
            raise ProbeError(f"child process ended abnormally: wait_status={wait_status}")
        try:
            payload = json.loads(b"".join(chunks).decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ProbeError(f"child result unreadable: {exc}") from None
        if "setup_error" in payload:
            raise ProbeError(str(payload["setup_error"]))
        results = payload.get("results")
        if not isinstance(results, dict):
            raise ProbeError("child result omitted operation results")

        expected_names = [
            "append_permitted_file",
            "create_second_file",
            "create_directory",
            "create_symbolic_link",
            "unlink_permitted_file",
        ]
        for name in expected_names:
            observed_errno = results.get(name)
            if type(observed_errno) is not int or observed_errno < 0:
                raise ProbeError(f"{name} returned an invalid errno")
            errno_name = "SUCCESS" if observed_errno == 0 else errno.errorcode.get(
                observed_errno, f"ERRNO_{observed_errno}"
            )
            print(f"operation {name}: errno={observed_errno} ({errno_name})")

        if results["append_permitted_file"] != 0:
            name = errno.errorcode.get(
                results["append_permitted_file"],
                str(results["append_permitted_file"]),
            )
            raise ProbeError(f"permitted append was refused with {name}")
        for name in expected_names[1:]:
            if results[name] not in DENIAL_ERRNOS:
                observed = (
                    "SUCCESS"
                    if results[name] == 0
                    else errno.errorcode.get(results[name], str(results[name]))
                )
                raise ProbeError(f"{name} was not denied; observed {observed}")
    finally:
        try:
            shutil.rmtree(scratch_path)
        except OSError as exc:
            raise ProbeError(f"temporary directory cleanup failed: {exc}") from None

    print("BOUNDARY_PROBE_VERDICT: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply a passport's recorded Landlock boundary to local scratch paths."
    )
    parser.add_argument("passport", nargs="?", type=Path, default=DEFAULT_PASSPORT)
    args = parser.parse_args()

    try:
        boundary = load_boundary(args.passport)
        print(
            "BOUNDARY_PROBE_NOTICE: applying the boundary recorded in the passport "
            "to a temporary directory; this does not re-execute the supervised run"
        )
        print(f"recorded_landlock_abi: {boundary['abi']}")
        print(f"recorded_denied_write_classes: {len(boundary['handled'])}")
        print(f"recorded_rule_count: {boundary['rule_count']}")
        print(f"recorded_scratch_class: {boundary['scratch_class']}")
        if sys.platform != "linux":
            print(
                f"BOUNDARY_PROBE_SKIP: unsupported platform {sys.platform}; "
                "Landlock enforcement was not checked"
            )
            return 0
        return run_probe(boundary)
    except ProbeError as exc:
        print(f"BOUNDARY_PROBE_VERDICT: FAIL {exc}")
        return 1
    except BaseException as exc:
        print(f"BOUNDARY_PROBE_VERDICT: FAIL unexpected error: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
