from __future__ import annotations

import contextlib
import io
import os
import shutil
import stat
import sys
import tempfile
import unittest
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

import build_reproducible as builder
import verify_distributions as verifier


def copy_release_project(destination: Path) -> Path:
    project = destination / "project"
    project.mkdir()
    paths = (PROJECT / "tools/release-files.txt").read_text("utf-8").splitlines()
    for relative in paths:
        source = PROJECT / relative
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o644)
    return project


def run_builder(project: Path, output: Path) -> str:
    stdout = io.StringIO()
    arguments = [
        "build_reproducible.py",
        "--project",
        str(project),
        "--out",
        str(output),
    ]
    with mock.patch.object(sys, "argv", arguments), contextlib.redirect_stdout(stdout):
        builder.main()
    return stdout.getvalue()


class ReleaseToolTests(unittest.TestCase):
    def _rewrite_wheel_metadata(
        self,
        raw: bytes,
        destination: Path,
        mutate: object,
    ) -> None:
        with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(
            destination,
            "w",
            compression=zipfile.ZIP_STORED,
        ) as target:
            for index, original in enumerate(source.infolist()):
                info = zipfile.ZipInfo(original.filename, date_time=original.date_time)
                info.create_system = original.create_system
                info.external_attr = original.external_attr
                info.flag_bits = original.flag_bits
                info.extra = original.extra
                info.internal_attr = original.internal_attr
                info.compress_type = original.compress_type
                if index == 0:
                    mutate(info)
                target.writestr(info, source.read(original.filename))

    def test_unmanifested_bytecode_never_reaches_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = copy_release_project(Path(directory))
            schemas = project / "src/technocore_workflow_bridge/schemas"
            legacy = schemas / "payload.pyc"
            legacy.write_bytes(b"UNMANIFESTED-BYTECODE")
            legacy.chmod(0o644)
            with self.assertRaisesRegex(SystemExit, "project differs from release allowlist"):
                builder.one_build(project)

            legacy.unlink()
            cache = schemas / "__pycache__"
            cache.mkdir()
            pep3147 = cache / "payload.cpython-312.pyc"
            pep3147.write_bytes(b"CACHE-NOISE")
            _sdist, wheel = builder.one_build(project)
            with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
                self.assertFalse(any(name.endswith((".pyc", ".pyo")) for name in archive.namelist()))
                self.assertFalse(any("/__pycache__/" in name for name in archive.namelist()))

            unexpected_source = schemas / "payload.py"
            unexpected_source.write_text("raise RuntimeError('not package code')\n", encoding="utf-8")
            unexpected_source.chmod(0o644)
            manifest = project / "tools/release-files.txt"
            paths = manifest.read_text("utf-8").splitlines()
            paths.append("src/technocore_workflow_bridge/schemas/payload.py")
            manifest.write_text("\n".join(sorted(paths)) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "not an allowed wheel input"):
                builder.one_build(project)

    def test_verifier_rejects_contaminated_wheel_even_with_consistent_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = copy_release_project(root)
            paths = builder.release_paths(project)
            clean = builder.build_wheel(project, paths)
            payloads: dict[str, bytes] = {}
            with zipfile.ZipFile(io.BytesIO(clean)) as archive:
                for name in archive.namelist():
                    if name != f"{builder.DIST_INFO}/RECORD":
                        payloads[name] = archive.read(name)
            payloads["technocore_workflow_bridge/schemas/payload.pyc"] = b"BYTECODE"
            record_path = f"{builder.DIST_INFO}/RECORD"
            rows = [
                f"{name},{builder._record_hash(content)},{len(content)}"
                for name, content in sorted(payloads.items())
            ]
            rows.append(f"{record_path},,")
            payloads[record_path] = ("\n".join(rows) + "\n").encode("utf-8")

            timestamp = datetime.fromtimestamp(builder.EPOCH, UTC)
            zip_time = (
                timestamp.year,
                timestamp.month,
                timestamp.day,
                timestamp.hour,
                timestamp.minute,
                timestamp.second,
            )
            contaminated = root / builder.WHEEL_FILENAME
            with zipfile.ZipFile(contaminated, "w", compression=zipfile.ZIP_STORED) as archive:
                for name, content in sorted(payloads.items()):
                    info = zipfile.ZipInfo(name, date_time=zip_time)
                    info.create_system = 3
                    info.external_attr = 0o100644 << 16
                    info.compress_type = zipfile.ZIP_STORED
                    archive.writestr(info, content)
            with self.assertRaisesRegex(SystemExit, "bytecode|allowlist"):
                verifier.verify_wheel(project, contaminated)

    def test_verifier_rejects_symlink_and_extended_timestamp_zip_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = copy_release_project(root)
            clean = builder.build_wheel(project, builder.release_paths(project))

            symlink = root / "symlink-metadata.whl"
            self._rewrite_wheel_metadata(
                clean,
                symlink,
                lambda info: setattr(info, "external_attr", (stat.S_IFLNK | 0o644) << 16),
            )
            with self.assertRaisesRegex(SystemExit, "ZIP metadata"):
                verifier.verify_wheel(project, symlink)

            extended_timestamp = root / "extended-timestamp.whl"
            timestamp_extra = b"\x55\x54\x05\x00\x01" + builder.EPOCH.to_bytes(4, "little")
            self._rewrite_wheel_metadata(
                clean,
                extended_timestamp,
                lambda info: setattr(info, "extra", timestamp_extra),
            )
            with self.assertRaisesRegex(SystemExit, "ZIP metadata"):
                verifier.verify_wheel(project, extended_timestamp)

    @unittest.skipUnless(sys.platform.startswith("linux"), "secure builder output requires Linux")
    def test_missing_nested_output_builds_and_verifies_normally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = copy_release_project(root)
            output = root / "missing" / "nested" / "dist"
            stdout = run_builder(project, output)
            self.assertIn("reproducible_builds=2", stdout)
            self.assertEqual(output.stat().st_mode & 0o777, 0o755)
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    builder.SDIST_FILENAME,
                    builder.WHEEL_FILENAME,
                    "SHA256SUMS",
                    "RELEASE-MANIFEST.json",
                },
            )
            self.assertTrue(all((path.stat().st_mode & 0o777) == 0o644 for path in output.iterdir()))
            sums = verifier.verify_sums(output)
            verifier.verify_sdist(project, output / builder.SDIST_FILENAME)
            verifier.verify_wheel(project, output / builder.WHEEL_FILENAME)
            verifier.verify_manifest(output, sums, len(builder.release_paths(project)))

    @unittest.skipUnless(sys.platform.startswith("linux"), "secure builder output requires Linux")
    def test_existing_output_and_leaf_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(SystemExit, "must not already exist"):
                builder._write_new_output(existing, {"artifact": b"safe"})

            victim = root / "victim"
            victim.mkdir()
            link = root / "link"
            link.symlink_to(victim, target_is_directory=True)
            with self.assertRaisesRegex(SystemExit, "must not already exist"):
                builder._write_new_output(link, {"artifact": b"safe"})
            self.assertEqual(list(victim.iterdir()), [])

            ancestor = root / "ancestor"
            ancestor.symlink_to(victim, target_is_directory=True)
            with self.assertRaisesRegex(SystemExit, "secure release output failed"):
                builder._write_new_output(ancestor / "dist", {"artifact": b"safe"})
            self.assertEqual(list(victim.iterdir()), [])

    @unittest.skipUnless(sys.platform.startswith("linux"), "secure builder output requires Linux")
    def test_regular_output_replacement_before_publish_cannot_receive_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "dist"
            attacker = root / "attacker"
            attacker.mkdir()
            original_rename = builder._rename_noreplace
            swapped = False

            def replace_then_publish(
                source_parent: int,
                source_name: str,
                destination_parent: int,
                destination_name: str,
            ) -> None:
                nonlocal swapped
                os.rename(attacker, output)
                swapped = True
                original_rename(
                    source_parent,
                    source_name,
                    destination_parent,
                    destination_name,
                )

            with mock.patch.object(builder, "_rename_noreplace", replace_then_publish):
                with self.assertRaisesRegex(SystemExit, "must not already exist"):
                    builder._write_new_output(output, {"artifact": b"safe"})
            self.assertTrue(swapped)
            self.assertEqual(list(output.iterdir()), [])

    @unittest.skipUnless(sys.platform.startswith("linux"), "secure builder output requires Linux")
    def test_output_swap_after_open_is_detected_without_redirect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "dist"
            moved = root / "moved"
            victim = root / "victim"
            victim.mkdir()
            sentinel = victim / "sentinel"
            sentinel.write_bytes(b"do-not-change")
            original_open = os.open
            swapped = False

            def open_then_swap(
                path: str | bytes,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
                if (
                    not swapped
                    and path == output.name
                    and dir_fd is not None
                    and flags & os.O_DIRECTORY
                ):
                    os.rename(output.name, moved.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                    os.symlink(victim, output.name, dir_fd=dir_fd, target_is_directory=True)
                    swapped = True
                return descriptor

            with mock.patch.object(os, "open", open_then_swap):
                with self.assertRaisesRegex(SystemExit, "path changed|secure release output failed"):
                    builder._write_new_output(output, {"artifact": b"safe"})
            self.assertTrue(swapped)
            self.assertEqual(sentinel.read_bytes(), b"do-not-change")
            self.assertEqual({path.name for path in victim.iterdir()}, {"sentinel"})
            self.assertEqual((moved / "artifact").read_bytes(), b"safe")

    @unittest.skipUnless(sys.platform.startswith("linux"), "secure builder output requires Linux")
    def test_artifact_symlink_injection_never_overwrites_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "dist"
            victim = root / "sentinel"
            victim.write_bytes(b"do-not-change")
            original_open = os.open
            injected = False

            def inject_before_artifact_open(
                path: str | bytes,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal injected
                if not injected and path == "artifact" and dir_fd is not None and flags & os.O_CREAT:
                    os.symlink(victim, path, dir_fd=dir_fd)
                    injected = True
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(os, "open", inject_before_artifact_open):
                with self.assertRaisesRegex(SystemExit, "artifact already exists"):
                    builder._write_new_output(output, {"artifact": b"safe"})
            self.assertTrue(injected)
            self.assertEqual(victim.read_bytes(), b"do-not-change")

    @unittest.skipUnless(sys.platform.startswith("linux"), "secure builder output requires Linux")
    def test_artifact_replacement_after_write_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "dist"
            original_open = os.open
            original_write_all = builder._write_all
            artifact_directory: int | None = None
            replaced = False

            def capture_artifact_directory(
                path: str | bytes,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal artifact_directory
                descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
                if path == "artifact" and dir_fd is not None and flags & os.O_CREAT:
                    artifact_directory = dir_fd
                return descriptor

            def replace_after_write(descriptor: int, content: bytes) -> None:
                nonlocal replaced
                original_write_all(descriptor, content)
                if not replaced:
                    if artifact_directory is None:
                        raise AssertionError("artifact directory was not captured")
                    os.unlink("artifact", dir_fd=artifact_directory)
                    replacement = original_open(
                        "artifact",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=artifact_directory,
                    )
                    try:
                        os.write(replacement, b"attacker-bytes")
                        os.fchmod(replacement, 0o644)
                    finally:
                        os.close(replacement)
                    replaced = True

            with mock.patch.object(os, "open", capture_artifact_directory), mock.patch.object(
                builder, "_write_all", replace_after_write
            ):
                with self.assertRaisesRegex(SystemExit, "identity/mode/size|bytes mismatch"):
                    builder._write_new_output(output, {"artifact": b"release-bytes"})
            self.assertTrue(replaced)
            self.assertFalse(output.exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "secure builder output requires Linux")
    def test_nonsticky_ancestor_swap_fails_without_accepting_external_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ancestor = root / "shared"
            parent = ancestor / "parent"
            parent.mkdir(parents=True)
            parent.chmod(0o700)
            output = parent / "dist"

            replacement = root / "replacement"
            external_output = replacement / "parent" / "dist"
            external_output.mkdir(parents=True)
            external_artifact = external_output / "artifact"
            external_artifact.write_bytes(b"external-bytes")
            external_artifact.chmod(0o644)
            moved = root / "moved"
            original_rename = builder._rename_noreplace
            swapped = False

            def swap_ancestor_then_publish(
                source_parent: int,
                source_name: str,
                destination_parent: int,
                destination_name: str,
            ) -> None:
                nonlocal swapped
                ancestor.chmod(0o777)
                os.rename(ancestor, moved)
                os.rename(replacement, ancestor)
                swapped = True
                original_rename(
                    source_parent,
                    source_name,
                    destination_parent,
                    destination_name,
                )

            with mock.patch.object(builder, "_rename_noreplace", swap_ancestor_then_publish):
                with self.assertRaisesRegex(SystemExit, "ancestor chain changed"):
                    builder._write_new_output(output, {"artifact": b"verified-bytes"})

            self.assertTrue(swapped)
            self.assertEqual((output / "artifact").read_bytes(), b"external-bytes")
            self.assertEqual((moved / "parent" / "dist" / "artifact").read_bytes(), b"verified-bytes")

            already_shared = root / "already-shared"
            already_shared.mkdir(mode=0o777)
            already_shared.chmod(0o777)
            with self.assertRaisesRegex(SystemExit, "ancestor chain"):
                builder._write_new_output(
                    already_shared / "private" / "dist",
                    {"artifact": b"never-written"},
                )


if __name__ == "__main__":
    unittest.main()
