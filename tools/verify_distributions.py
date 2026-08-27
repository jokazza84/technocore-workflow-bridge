#!/usr/bin/env python3
"""Verify deterministic Technocore Workflow Bridge release artifacts offline."""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import io
import json
import stat
import struct
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from build_reproducible import (
    DIST_INFO,
    EPOCH,
    PACKAGE_SOURCE_PREFIX,
    SDIST_FILENAME,
    SDIST_ROOT,
    SCHEMA_SOURCE_DIRECTORY,
    VERSION,
    WHEEL_FILENAME,
    metadata,
    release_paths,
    wheel_files,
)

WHEEL_METADATA_MEMBERS = frozenset(
    {
        f"{DIST_INFO}/LICENSE",
        f"{DIST_INFO}/METADATA",
        f"{DIST_INFO}/RECORD",
        f"{DIST_INFO}/WHEEL",
        f"{DIST_INFO}/entry_points.txt",
        f"{DIST_INFO}/top_level.txt",
    }
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_sums(directory: Path) -> dict[str, str]:
    expected: dict[str, str] = {}
    for line in (directory / "SHA256SUMS").read_text("ascii").splitlines():
        value, separator, name = line.partition("  ")
        if not separator or len(value) != 64 or name in expected:
            raise SystemExit("invalid SHA256SUMS")
        expected[name] = value
    if set(expected) != {SDIST_FILENAME, WHEEL_FILENAME}:
        raise SystemExit("SHA256SUMS artifact set mismatch")
    for name, value in expected.items():
        if digest((directory / name).read_bytes()) != value:
            raise SystemExit(f"artifact digest mismatch: {name}")
    return expected


def verify_sdist(project: Path, path: Path) -> list[str]:
    raw = path.read_bytes()
    if int.from_bytes(raw[4:8], "little") != EPOCH:
        raise SystemExit("sdist gzip timestamp is not fixed")
    names: list[str] = []
    contents: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive.getmembers():
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or member.name in names:
                raise SystemExit(f"unsafe/duplicate sdist member: {member.name}")
            names.append(member.name)
            if member.uid != 0 or member.gid != 0 or member.uname != "root" or member.gname != "root":
                raise SystemExit(f"non-normalized sdist ownership: {member.name}")
            if member.mtime != EPOCH:
                raise SystemExit(f"non-normalized sdist timestamp: {member.name}")
            expected_mode = 0o755 if member.isdir() else 0o644
            if member.mode != expected_mode or not (member.isdir() or member.isfile()):
                raise SystemExit(f"sdist type/mode mismatch: {member.name}")
            if member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise SystemExit(f"unreadable sdist member: {member.name}")
                contents[member.name] = source.read()

    release = release_paths(project)
    expected_files = {f"{SDIST_ROOT}/{relative}" for relative in release}
    expected_files.add(f"{SDIST_ROOT}/PKG-INFO")
    if set(contents) != expected_files:
        raise SystemExit("sdist file allowlist mismatch")
    for relative in release:
        if contents[f"{SDIST_ROOT}/{relative}"] != (project / relative).read_bytes():
            raise SystemExit(f"sdist source differs from project: {relative}")
    if contents[f"{SDIST_ROOT}/PKG-INFO"] != metadata(project):
        raise SystemExit("sdist PKG-INFO mismatch")
    return names


def _record_digest(data: bytes) -> str:
    value = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return f"sha256={value}"


def _manifest_wheel_members(paths: list[str]) -> set[str]:
    members: set[str] = set(WHEEL_METADATA_MEMBERS)
    for relative in paths:
        if not relative.startswith(PACKAGE_SOURCE_PREFIX):
            continue
        package_relative = PurePosixPath(relative.removeprefix(PACKAGE_SOURCE_PREFIX))
        allowed_python = (
            package_relative.suffix == ".py"
            and "__pycache__" not in package_relative.parts
            and "schemas" not in package_relative.parts[:-1]
        )
        allowed_schema = (
            package_relative.parent == SCHEMA_SOURCE_DIRECTORY
            and package_relative.suffix == ".json"
        )
        if not (allowed_python or allowed_schema):
            raise SystemExit(f"manifest contains a forbidden wheel source: {relative}")
        member = f"technocore_workflow_bridge/{package_relative.as_posix()}"
        if member.endswith((".pyc", ".pyo")) or "/__pycache__/" in member:
            raise SystemExit(f"bytecode/cache member is forbidden in wheel: {member}")
        members.add(member)
    return members


def _verify_local_zip_metadata(raw: bytes, info: zipfile.ZipInfo, expected_time: tuple[int, ...]) -> None:
    offset = info.header_offset
    if offset < 0 or offset + 30 > len(raw):
        raise SystemExit(f"wheel local ZIP header is truncated: {info.filename}")
    (
        signature,
        extract_version,
        flag_bits,
        compression,
        dos_time,
        dos_date,
        crc,
        compressed_size,
        file_size,
        filename_length,
        extra_length,
    ) = struct.unpack_from("<IHHHHHIIIHH", raw, offset)
    expected_dos_time = (expected_time[3] << 11) | (expected_time[4] << 5) | (expected_time[5] // 2)
    expected_dos_date = ((expected_time[0] - 1980) << 9) | (expected_time[1] << 5) | expected_time[2]
    filename_start = offset + 30
    filename_end = filename_start + filename_length
    try:
        expected_filename = info.filename.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SystemExit(f"wheel member name is not ASCII: {info.filename}") from exc
    if (
        signature != 0x04034B50
        or extract_version != 20
        or flag_bits != 0
        or compression != zipfile.ZIP_STORED
        or dos_time != expected_dos_time
        or dos_date != expected_dos_date
        or crc != info.CRC
        or compressed_size != info.compress_size
        or file_size != info.file_size
        or raw[filename_start:filename_end] != expected_filename
        or extra_length != 0
    ):
        raise SystemExit(f"wheel local ZIP metadata mismatch: {info.filename}")


def verify_wheel(project: Path, path: Path) -> list[str]:
    timestamp = datetime.fromtimestamp(EPOCH, UTC)
    expected_time = (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    )
    release = release_paths(project)
    allowed_members = _manifest_wheel_members(release)
    expected_files = wheel_files(project, release)
    if set(expected_files) != allowed_members:
        raise SystemExit("builder wheel members differ from the manifest-derived allowlist")
    raw = path.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if archive.comment != b"":
            raise SystemExit("wheel archive comment is forbidden")
        if archive.testzip() is not None:
            raise SystemExit("wheel CRC failure")
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)) or names != sorted(names):
            raise SystemExit("wheel members are duplicate or unsorted")
        if any(name.endswith((".pyc", ".pyo")) or "/__pycache__/" in name for name in names):
            raise SystemExit("wheel contains forbidden bytecode/cache content")
        if set(names) != allowed_members:
            raise SystemExit("wheel member allowlist mismatch")
        for info in infos:
            if (
                info.date_time != expected_time
                or info.create_system != 3
                or info.external_attr != (stat.S_IFREG | 0o644) << 16
                or info.flag_bits != 0
                or info.extra != b""
                or info.comment != b""
                or info.internal_attr != 0
                or info.create_version != 20
                or info.extract_version != 20
                or info.reserved != 0
                or info.volume != 0
                or info.orig_filename != info.filename
                or info.compress_type != zipfile.ZIP_STORED
            ):
                raise SystemExit(f"wheel ZIP metadata mismatch: {info.filename}")
            _verify_local_zip_metadata(raw, info, expected_time)
            if archive.read(info.filename) != expected_files[info.filename]:
                raise SystemExit(f"wheel member differs from source: {info.filename}")
        record_name = f"{DIST_INFO}/RECORD"
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
        if {row[0] for row in rows} != set(names):
            raise SystemExit("wheel RECORD member set mismatch")
        for name, hash_value, size_value in rows:
            if name == record_name:
                if hash_value or size_value:
                    raise SystemExit("wheel RECORD self-entry must be unhashed")
                continue
            data = archive.read(name)
            if hash_value != _record_digest(data) or size_value != str(len(data)):
                raise SystemExit(f"wheel RECORD mismatch: {name}")
    return names


def verify_manifest(directory: Path, sums: dict[str, str], release_count: int) -> None:
    raw = (directory / "RELEASE-MANIFEST.json").read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if raw != (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"):
        raise SystemExit("release manifest is not canonical JSON")
    if (
        value.get("schema") != "TECHNOCORE_WORKFLOW_BRIDGE_RELEASE_V1"
        or value.get("version") != VERSION
        or value.get("source_date_epoch") != EPOCH
        or value.get("release_files") != release_count
    ):
        raise SystemExit("release manifest metadata mismatch")
    for name, expected_hash in sums.items():
        item = value.get("artifacts", {}).get(name)
        if item != {"bytes": (directory / name).stat().st_size, "sha256": expected_hash}:
            raise SystemExit(f"release manifest artifact mismatch: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    project = args.project.resolve()
    directory = args.directory.resolve()
    sums = verify_sums(directory)
    sdist_names = verify_sdist(project, directory / SDIST_FILENAME)
    wheel_names = verify_wheel(project, directory / WHEEL_FILENAME)
    verify_manifest(directory, sums, len(release_paths(project)))
    print(f"sdist_members={len(sdist_names)}")
    print(f"wheel_members={len(wheel_names)}")
    print("hashes_members_modes_timestamps_record=PASS")


if __name__ == "__main__":
    main()
