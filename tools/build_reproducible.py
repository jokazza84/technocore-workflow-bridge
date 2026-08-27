#!/usr/bin/env python3
"""Build deterministic sdist and pure-Python wheel using only the stdlib."""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import gzip
import hashlib
import io
import json
import os
import secrets
import stat
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

VERSION = "0.2.0"
DIST_NAME = "technocore-workflow-bridge"
WHEEL_NAME = "technocore_workflow_bridge"
SDIST_ROOT = f"{DIST_NAME}-{VERSION}"
SDIST_FILENAME = f"{SDIST_ROOT}.tar.gz"
WHEEL_FILENAME = f"{WHEEL_NAME}-{VERSION}-py3-none-any.whl"
DIST_INFO = f"{WHEEL_NAME}-{VERSION}.dist-info"
EPOCH = 1_787_788_800  # 2026-08-27T00:00:00Z
IGNORED_ROOTS = frozenset({".git", ".venv", "build", "dist"})
PACKAGE_SOURCE_PREFIX = "src/technocore_workflow_bridge/"
SCHEMA_SOURCE_DIRECTORY = PurePosixPath("schemas")
RENAME_NOREPLACE = 1


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def release_paths(project: Path) -> list[str]:
    manifest = project / "tools/release-files.txt"
    lines = manifest.read_text("utf-8").splitlines()
    if not lines or any(not line or line != line.strip() for line in lines):
        raise SystemExit("release-files.txt contains an empty or non-canonical line")
    if lines != sorted(lines) or len(lines) != len(set(lines)):
        raise SystemExit("release-files.txt must be sorted and unique")
    paths: list[str] = []
    for value in lines:
        pure = PurePosixPath(value)
        if pure.is_absolute() or ".." in pure.parts or str(pure) != value:
            raise SystemExit(f"unsafe release path: {value}")
        path = project / value
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"release path is not a regular file: {value}")
        if path.stat().st_mode & 0o777 != 0o644:
            raise SystemExit(f"release file mode differs from 0644: {value}")
        paths.append(value)

    actual: list[str] = []
    for path in project.rglob("*"):
        relative = path.relative_to(project)
        if relative.parts[0] in IGNORED_ROOTS or any(
            part == "__pycache__" or part.endswith(".egg-info") for part in relative.parts
        ):
            continue
        if path.is_symlink():
            raise SystemExit(f"symlink outside release allowlist: {relative}")
        if path.is_file():
            actual.append(relative.as_posix())
    if sorted(actual) != paths:
        extra = sorted(set(actual) - set(paths))
        missing = sorted(set(paths) - set(actual))
        raise SystemExit(f"project differs from release allowlist; extra={extra} missing={missing}")
    return paths


def metadata(project: Path) -> bytes:
    readme = (project / "README.md").read_text("utf-8")
    value = (
        "Metadata-Version: 2.1\n"
        "Name: technocore-workflow-bridge\n"
        f"Version: {VERSION}\n"
        "Summary: Bounded read-only Technocore JSONL bridge for agentic coding workflows\n"
        "License: MIT\n"
        "License-File: LICENSE\n"
        "Requires-Python: >=3.12\n"
        "Description-Content-Type: text/markdown\n"
        "\n"
        f"{readme}"
    )
    return value.encode("utf-8")


def _source_files(project: Path, paths: list[str]) -> dict[str, bytes]:
    return {value: (project / value).read_bytes() for value in paths}


def build_sdist(project: Path, paths: list[str]) -> bytes:
    files = _source_files(project, paths)
    files["PKG-INFO"] = metadata(project)
    directories = {SDIST_ROOT}
    for relative in files:
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            directories.add(f"{SDIST_ROOT}/{parent.as_posix()}")
            parent = parent.parent

    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(directories):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = EPOCH
            archive.addfile(info)
        for relative, content in sorted(files.items()):
            info = tarfile.TarInfo(f"{SDIST_ROOT}/{relative}")
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = EPOCH
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return gzip.compress(stream.getvalue(), compresslevel=9, mtime=EPOCH)


def _record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return f"sha256={digest}"


def _wheel_package_files(project: Path, paths: list[str]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
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
            raise SystemExit(f"package release path is not an allowed wheel input: {relative}")
        member = f"technocore_workflow_bridge/{package_relative.as_posix()}"
        files[member] = (project / relative).read_bytes()
    return files


def wheel_files(project: Path, paths: list[str]) -> dict[str, bytes]:
    files = _wheel_package_files(project, paths)
    files.update(
        {
            f"{DIST_INFO}/LICENSE": (project / "LICENSE").read_bytes(),
            f"{DIST_INFO}/METADATA": metadata(project),
            f"{DIST_INFO}/WHEEL": (
                "Wheel-Version: 1.0\n"
                "Generator: technocore-workflow-bridge stdlib-reproducible-builder\n"
                "Root-Is-Purelib: true\n"
                "Tag: py3-none-any\n"
            ).encode("ascii"),
            f"{DIST_INFO}/entry_points.txt": (
                "[console_scripts]\n"
                "technocore-workflow-bridge = technocore_workflow_bridge.cli:main\n"
                "technocore-workflow-consumer = technocore_workflow_bridge.consumer_cli:main\n"
            ).encode("ascii"),
            f"{DIST_INFO}/top_level.txt": b"technocore_workflow_bridge\n",
        }
    )
    record_path = f"{DIST_INFO}/RECORD"
    rows = [f"{name},{_record_hash(content)},{len(content)}" for name, content in sorted(files.items())]
    rows.append(f"{record_path},,")
    files[record_path] = ("\n".join(rows) + "\n").encode("utf-8")
    return files


def build_wheel(project: Path, paths: list[str]) -> bytes:
    files = wheel_files(project, paths)
    timestamp = datetime.fromtimestamp(EPOCH, UTC)
    zip_time = (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=zip_time)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.flag_bits = 0
            info.extra = b""
            info.internal_attr = 0
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, content)
    return output.getvalue()


def one_build(project: Path) -> tuple[bytes, bytes]:
    paths = release_paths(project)
    return build_sdist(project, paths), build_wheel(project, paths)


def _require_secure_output_platform() -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "O_CLOEXEC")
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "pread")
    ):
        raise SystemExit("release output requires Linux/POSIX directory-descriptor safeguards")


def _renameat2_function() -> object:
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, "renameat2", None)
    if function is None:
        raise SystemExit("release output requires Linux renameat2(RENAME_NOREPLACE)")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    return function


def _rename_noreplace(
    source_parent: int,
    source_name: str,
    destination_parent: int,
    destination_name: str,
) -> None:
    function = _renameat2_function()
    result = function(
        source_parent,
        os.fsencode(source_name),
        destination_parent,
        os.fsencode(destination_name),
        RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise SystemExit("release output must not already exist")
    raise OSError(error, os.strerror(error))


def _trusted_directory_identity(
    metadata: os.stat_result,
    label: str,
    system_owner_uid: int,
) -> tuple[int, int]:
    """Reject ancestors another local principal can rename or replace."""

    mode = stat.S_IMODE(metadata.st_mode)
    trusted_owner = metadata.st_uid in {system_owner_uid, os.geteuid()}
    root_owned_sticky = metadata.st_uid == system_owner_uid and bool(mode & stat.S_ISVTX)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or not trusted_owner
        or (mode & 0o022 and not root_owned_sticky)
    ):
        raise SystemExit(
            "release output ancestor chain must be root/user-owned and non-group/world-"
            f"writable except for root-owned sticky directories: {label}"
        )
    return metadata.st_dev, metadata.st_ino


def _open_directory_path(
    path: Path,
    *,
    create_missing: bool,
    expected_prefix: tuple[tuple[int, int], ...] | None = None,
) -> tuple[int, tuple[tuple[int, int], ...]]:
    """Open and attest every component of an absolute directory path."""

    _require_secure_output_platform()
    if not path.is_absolute() or ".." in path.parts:
        raise SystemExit("release output path must be normalized and absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        root_metadata = os.fstat(descriptor)
        system_owner_uid = root_metadata.st_uid
        chain = [_trusted_directory_identity(root_metadata, "/", system_owner_uid)]
        if expected_prefix is not None and (
            not expected_prefix or chain[0] != expected_prefix[0]
        ):
            raise SystemExit("release output ancestor chain changed: /")
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise SystemExit("release output path contains an unsafe component")
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create_missing:
                    raise
                created = False
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
                if created:
                    os.fchmod(next_descriptor, 0o755)
            opened = os.fstat(next_descriptor)
            current = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            identity = _trusted_directory_identity(opened, str(path), system_owner_uid)
            if (current.st_dev, current.st_ino) != identity:
                os.close(next_descriptor)
                raise SystemExit(f"release output ancestor path changed: {component}")
            chain.append(identity)
            index = len(chain) - 1
            if expected_prefix is not None and index < len(expected_prefix):
                if identity != expected_prefix[index]:
                    os.close(next_descriptor)
                    raise SystemExit(f"release output ancestor chain changed: {component}")
            os.close(descriptor)
            descriptor = next_descriptor
        if expected_prefix is not None and len(chain) < len(expected_prefix):
            raise SystemExit("release output ancestor chain is shorter than expected")
        return descriptor, tuple(chain)
    except BaseException:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short release artifact write")
        remaining = remaining[written:]


def _validate_output_files(
    directory_descriptor: int,
    files: dict[str, bytes],
    identities: dict[str, tuple[int, int]],
) -> None:
    if set(os.listdir(directory_descriptor)) != set(files):
        raise SystemExit("release output contains an unexpected or missing artifact")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    for name, expected in sorted(files.items()):
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o644
                or metadata.st_size != len(expected)
                or (metadata.st_dev, metadata.st_ino) != identities[name]
            ):
                raise SystemExit(f"release artifact identity/mode/size mismatch: {name}")
            chunks: list[bytes] = []
            offset = 0
            while offset <= len(expected):
                chunk = os.pread(descriptor, min(64 * 1024, len(expected) + 1 - offset), offset)
                if not chunk:
                    break
                chunks.append(chunk)
                offset += len(chunk)
            if b"".join(chunks) != expected:
                raise SystemExit(f"release artifact bytes mismatch: {name}")
            current = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise SystemExit(f"release artifact path changed during validation: {name}")
        finally:
            os.close(descriptor)


def _write_new_output(output: Path, files: dict[str, bytes]) -> None:
    """Build privately, then atomically publish a new descriptor-verified directory."""

    if output.name in {"", ".", ".."}:
        raise SystemExit("release output filename is invalid")
    for name, content in files.items():
        if (
            PurePosixPath(name).name != name
            or name in {"", ".", ".."}
            or type(content) is not bytes
        ):
            raise SystemExit(f"unsafe release artifact: {name}")
    _require_secure_output_platform()
    _renameat2_function()
    parent_descriptor: int | None = None
    output_descriptor: int | None = None
    artifact_descriptors: dict[str, int] = {}
    staging_name: str | None = None
    try:
        parent_descriptor, parent_chain = _open_directory_path(
            output.parent,
            create_missing=True,
        )
        parent_metadata = os.fstat(parent_descriptor)
        if (
            parent_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(parent_metadata.st_mode) & 0o022
        ):
            raise SystemExit("release output parent must be user-owned and not group/world-writable")
        try:
            os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SystemExit("release output must not already exist")

        for _attempt in range(64):
            candidate = f".{output.name}.tmp-{secrets.token_hex(16)}"
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                continue
            staging_name = candidate
            break
        if staging_name is None:
            raise SystemExit("could not allocate a private release staging directory")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        output_descriptor = os.open(staging_name, directory_flags, dir_fd=parent_descriptor)
        opened = os.fstat(output_descriptor)
        current_staging = os.stat(staging_name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or (current_staging.st_dev, current_staging.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise SystemExit("private release staging directory identity mismatch")
        identities: dict[str, tuple[int, int]] = {}
        for name, content in sorted(files.items()):
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=output_descriptor)
            except FileExistsError as exc:
                raise SystemExit(f"release artifact already exists: {name}") from exc
            artifact_descriptors[name] = descriptor
            _write_all(descriptor, content)
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            identities[name] = (metadata.st_dev, metadata.st_ino)
        os.fchmod(output_descriptor, 0o755)
        os.fsync(output_descriptor)
        _validate_output_files(output_descriptor, files, identities)

        current_staging = os.stat(staging_name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (current_staging.st_dev, current_staging.st_ino) != (opened.st_dev, opened.st_ino):
            raise SystemExit("release staging path changed before publication")
        _rename_noreplace(parent_descriptor, staging_name, parent_descriptor, output.name)
        staging_name = None
        os.fsync(parent_descriptor)
        current_descriptor, current_chain = _open_directory_path(
            output,
            create_missing=False,
            expected_prefix=parent_chain,
        )
        try:
            current = os.fstat(current_descriptor)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise SystemExit("release output path changed during publication")
            _validate_output_files(current_descriptor, files, identities)
            current_path = os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (current_path.st_dev, current_path.st_ino) != (opened.st_dev, opened.st_ino):
                raise SystemExit("release output path changed after validation")
        finally:
            os.close(current_descriptor)
        final_descriptor, _final_chain = _open_directory_path(
            output,
            create_missing=False,
            expected_prefix=current_chain,
        )
        try:
            final = os.fstat(final_descriptor)
            if (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino):
                raise SystemExit("release output path changed after final ancestor validation")
        finally:
            os.close(final_descriptor)
    except OSError as exc:
        raise SystemExit(f"secure release output failed: {exc}") from exc
    finally:
        for descriptor in artifact_descriptors.values():
            os.close(descriptor)
        if output_descriptor is not None:
            os.close(output_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    project = args.project.resolve()
    output = Path(os.path.abspath(args.out))
    if not project.is_dir():
        raise SystemExit("project is not a directory")
    first = one_build(project)
    second = one_build(project)
    if first != second:
        raise SystemExit("reproducibility check failed: two builds differ")
    artifacts = {SDIST_FILENAME: first[0], WHEEL_FILENAME: first[1]}
    sums = "".join(f"{sha256(content)}  {name}\n" for name, content in sorted(artifacts.items()))
    manifest = {
        "schema": "TECHNOCORE_WORKFLOW_BRIDGE_RELEASE_V1",
        "version": VERSION,
        "source_date_epoch": EPOCH,
        "release_files": len(release_paths(project)),
        "artifacts": {
            name: {"bytes": len(content), "sha256": sha256(content)}
            for name, content in sorted(artifacts.items())
        },
    }
    output_files = {
        **artifacts,
        "SHA256SUMS": sums.encode("ascii"),
        "RELEASE-MANIFEST.json": (
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8"),
    }
    _write_new_output(output, output_files)
    print(f"release_files={manifest['release_files']}")
    print("reproducible_builds=2")
    for name, content in sorted(artifacts.items()):
        print(f"sha256 {sha256(content)} {name}")


if __name__ == "__main__":
    main()
