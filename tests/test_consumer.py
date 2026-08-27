from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from technocore_workflow_bridge import cli, consumer, consumer_cli


GOLDEN_INPUT = PROJECT / "examples/golden/bridge-records.jsonl"
GOLDEN_OUTPUT = PROJECT / "examples/golden/sanitized-records.jsonl"
SCHEMAS = PROJECT / "src/technocore_workflow_bridge/schemas"


class ConsumerTests(unittest.TestCase):
    def test_golden_output_is_byte_exact_and_still_untrusted(self) -> None:
        records = consumer.decode_jsonl(GOLDEN_INPUT.read_bytes())
        actual = consumer.sanitized_jsonl(records)
        self.assertEqual(actual, GOLDEN_OUTPUT.read_bytes())
        self.assertEqual(len(records), 2)
        self.assertTrue(all(item["trust"] == "UNTRUSTED_DATA" for item in records))
        self.assertTrue(
            all(item["sanitization"]["human_review_required"] is True for item in records)
        )
        self.assertIn("Café", records[0]["untrusted_data"]["text"])
        self.assertIn("\\u001B", records[0]["untrusted_data"]["text"])
        self.assertNotIn("\x1b", records[0]["untrusted_data"]["text"])

    def test_formal_schemas_are_closed_draft_2020_12_documents(self) -> None:
        names = {
            "technocore-bridge-record-v1.schema.json",
            "technocore-sanitized-record-v1.schema.json",
        }
        self.assertEqual({path.name for path in SCHEMAS.glob("*.json")}, names)
        for name in names:
            schema = json.loads((SCHEMAS / name).read_text("utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(len(schema["oneOf"]), 2)
            self.assertIn("UNTRUSTED_DATA", json.dumps(schema, sort_keys=True))
            self.assertNotIn("additionalProperties\": true", json.dumps(schema))

    def test_duplicate_unknown_noncanonical_and_tampered_records_fail(self) -> None:
        with self.assertRaisesRegex(consumer.ConsumerError, "duplicate JSON key"):
            consumer.decode_jsonl(b'{"schema":"x","schema":"y"}\n')

        source = GOLDEN_INPUT.read_bytes().splitlines()[0]
        record = json.loads(source)
        record["unexpected"] = True
        with self.assertRaisesRegex(consumer.ConsumerError, "unknown or missing"):
            consumer.sanitize_record(record)

        record = json.loads(source)
        record["untrusted_data"]["text"] += "tampered"
        with self.assertRaisesRegex(consumer.ConsumerError, "dedupe key"):
            consumer.sanitize_record(record)

        noncanonical = json.dumps(json.loads(source), ensure_ascii=False).encode("utf-8") + b"\n"
        with self.assertRaisesRegex(consumer.ConsumerError, "not canonical"):
            consumer.decode_jsonl(noncanonical)

    def test_bounds_and_closed_route_are_enforced(self) -> None:
        record = json.loads(GOLDEN_INPUT.read_bytes().splitlines()[0])
        record["provenance"]["path"] = "/r/other?format=json&since=0&limit=2"
        with self.assertRaisesRegex(consumer.ConsumerError, "provenance"):
            consumer.sanitize_record(record)

        with self.assertRaisesRegex(consumer.ConsumerError, "byte bound"):
            consumer.decode_jsonl(b"x" * (consumer.MAX_INPUT_BYTES + 1))

        one = GOLDEN_INPUT.read_bytes().splitlines(keepends=True)[0]
        with self.assertRaisesRegex(consumer.ConsumerError, "record count"):
            consumer.decode_jsonl(one * (consumer.MAX_RECORDS + 1))

    def test_atomic_output_is_mode_0600_and_replace_is_explicit(self) -> None:
        records = consumer.decode_jsonl(GOLDEN_INPUT.read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sanitized.jsonl"
            consumer.save_sanitized(path, records)
            self.assertEqual(path.read_bytes(), GOLDEN_OUTPUT.read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(consumer.ConsumerError, "output exists"):
                consumer.save_sanitized(path, records)
            consumer.save_sanitized(path, records, replace=True)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            target = Path(directory) / "target"
            target.write_text("not output", encoding="utf-8")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(consumer.ConsumerError, "symlink"):
                consumer.save_sanitized(link, records, replace=True)

    def test_no_replace_cannot_overwrite_a_concurrent_creator(self) -> None:
        records = consumer.decode_jsonl(GOLDEN_INPUT.read_bytes())
        original_link = os.link
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.jsonl"

            def create_then_link(*args: object, **kwargs: object) -> None:
                output.write_bytes(b"concurrent owner\n")
                original_link(*args, **kwargs)

            with mock.patch.object(os, "link", side_effect=create_then_link):
                with self.assertRaisesRegex(consumer.ConsumerError, "output exists"):
                    consumer.save_sanitized(output, records)
            self.assertEqual(output.read_bytes(), b"concurrent owner\n")

    def test_save_revalidates_sanitized_records(self) -> None:
        records = consumer.decode_jsonl(GOLDEN_INPUT.read_bytes())
        records[0]["untrusted_data"]["text"] = "unsafe\x1bcontrol"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.jsonl"
            with self.assertRaisesRegex(consumer.ConsumerError, "non-sanitized"):
                consumer.save_sanitized(output, records)
            self.assertFalse(output.exists())

    def test_schema_constraints_match_runtime_provenance_policy(self) -> None:
        source_schema = json.loads(
            (SCHEMAS / "technocore-bridge-record-v1.schema.json").read_text("utf-8")
        )
        sanitized_schema = json.loads(
            (SCHEMAS / "technocore-sanitized-record-v1.schema.json").read_text("utf-8")
        )
        expected_lobby_types = sorted(consumer.LOBBY_CONTENT_TYPES)
        expected_patterns_types = sorted(consumer.PATTERNS_CONTENT_TYPES)
        for schema in (source_schema, sanitized_schema):
            lobby = schema["$defs"]["lobby_provenance"]["allOf"][1]["properties"]
            patterns = schema["$defs"]["patterns_provenance"]["allOf"][1]["properties"]
            self.assertEqual(sorted(lobby["content_type"]["enum"]), expected_lobby_types)
            self.assertEqual(sorted(patterns["content_type"]["enum"]), expected_patterns_types)
            self.assertIn("|200)", lobby["path"]["pattern"])

        valid = json.loads(GOLDEN_INPUT.read_bytes().splitlines()[0])
        consumer.sanitize_record(valid)
        for content_type in ("text/html", "Application/JSON", ""):
            invalid = json.loads(json.dumps(valid))
            invalid["provenance"]["content_type"] = content_type
            with self.assertRaisesRegex(consumer.ConsumerError, "media type"):
                consumer.sanitize_record(invalid)
        for field in ("tls_version", "cipher"):
            invalid = json.loads(json.dumps(valid))
            invalid["provenance"][field] = ""
            with self.assertRaisesRegex(consumer.ConsumerError, "cannot be empty"):
                consumer.sanitize_record(invalid)
        invalid = json.loads(json.dumps(valid))
        invalid["provenance"]["path"] = "/r/lobby?format=json&since=0&limit=999"
        with self.assertRaisesRegex(consumer.ConsumerError, "limit"):
            consumer.sanitize_record(invalid)

    def test_integrated_output_failure_does_not_advance_lobby_state(self) -> None:
        source_record = json.loads(GOLDEN_INPUT.read_bytes().splitlines()[0])
        state = mock.Mock()
        updated = mock.Mock()
        with mock.patch.object(
            sys,
            "argv",
            [
                "bridge",
                "--allow-network",
                "lobby",
                "--state",
                "state.json",
                "--sanitized-output",
                "review.jsonl",
            ],
        ), mock.patch.object(cli.CursorState, "load", return_value=state), mock.patch.object(
            cli, "fetch_once", return_value=([source_record], updated)
        ), mock.patch.object(
            cli, "save_sanitized", side_effect=consumer.ConsumerError("output refused")
        ):
            with self.assertRaisesRegex(SystemExit, "output refused"):
                cli.main()
        updated.save.assert_not_called()

    def test_standalone_consumer_cli_reads_stdin_and_writes_no_remote_text_to_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.jsonl"
            stdin = mock.Mock()
            stdin.buffer = io.BytesIO(GOLDEN_INPUT.read_bytes())
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(sys, "argv", ["consumer", "--output", str(output)]), mock.patch.object(
                sys, "stdin", stdin
            ), mock.patch.object(sys, "stdout", stdout), mock.patch.object(sys, "stderr", stderr):
                consumer_cli.main()
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("sanitized_records=2", stderr.getvalue())
            self.assertEqual(output.read_bytes(), GOLDEN_OUTPUT.read_bytes())

    def test_consumer_has_no_network_or_remote_write_surface(self) -> None:
        sources = "\n".join(
            (PROJECT / f"src/technocore_workflow_bridge/{name}").read_text("utf-8")
            for name in ("consumer.py", "consumer_cli.py")
        )
        for forbidden in (
            "http.client",
            "urllib",
            "socket",
            "say-signed",
            "/set/",
            '"POST"',
            "identity" + ".seed",
        ):
            self.assertNotIn(forbidden, sources)

    def test_golden_fixtures_contain_no_operational_identity(self) -> None:
        combined = GOLDEN_INPUT.read_text("utf-8") + GOLDEN_OUTPUT.read_text("utf-8")
        for forbidden in (
            "did:key:",
            "identity" + ".seed",
            "0000000000000000",
            "receipt",
        ):
            self.assertNotIn(forbidden, combined)


if __name__ == "__main__":
    unittest.main()
