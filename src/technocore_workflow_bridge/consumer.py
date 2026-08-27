"""Strict, offline consumer for Technocore bridge JSONL.

Validation and sanitization never make remote content trusted. The output remains
explicitly labelled ``UNTRUSTED_DATA`` and is intended for human review or inert
indexing only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .bridge import (
    MAX_CURSOR,
    MAX_NONCE,
    MAX_PATTERNS_BODY,
    MAX_ROOM_BODY,
    MAX_ROOM_LIMIT,
    MAX_TEXT_CHARS,
    LOBBY_CONTENT_TYPES,
    ORIGIN,
    PATTERNS_CONTENT_TYPES,
    TRUST,
)

INPUT_SCHEMA = "TECHNOCORE_BRIDGE_RECORD_V1"
OUTPUT_SCHEMA = "TECHNOCORE_SANITIZED_RECORD_V1"
SANITIZATION_PROFILE = "NFC_VISIBLE_CONTROLS_V1"
MAX_RECORDS = MAX_ROOM_LIMIT
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = MAX_ROOM_BODY + 64 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_SANITIZED_LOBBY_TEXT = MAX_TEXT_CHARS * 6
MAX_SANITIZED_PATTERNS_TEXT = MAX_PATTERNS_BODY * 6
HEX64_RE = re.compile(r"[0-9a-f]{64}")
LOBBY_PATH_RE = re.compile(
    r"/r/lobby\?format=json&since=(0|[1-9][0-9]*)&limit=([1-9][0-9]{0,2})"
)
BIDI_CONTROLS = frozenset(
    {
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
    }
)


class ConsumerError(RuntimeError):
    pass


def _canonical_line(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _reject_constant(value: str) -> None:
    raise ConsumerError(f"non-finite JSON number is forbidden: {value}")


def _closed_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ConsumerError("duplicate JSON key is forbidden")
        value[key] = item
    return value


def _exact_object(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != fields:
        raise ConsumerError(f"{label} has an unknown or missing field")
    return value


def _bounded_text(value: object, label: str, maximum: int) -> str:
    if type(value) is not str or len(value) > maximum:
        raise ConsumerError(f"{label} is not a bounded string")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ConsumerError(f"{label} contains an invalid surrogate") from exc
    return value


def _bounded_integer(value: object, label: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ConsumerError(f"{label} is not a bounded non-negative integer")
    return value


def _hash(value: object, label: str) -> str:
    if type(value) is not str or HEX64_RE.fullmatch(value) is None:
        raise ConsumerError(f"{label} is not lowercase SHA-256 hex")
    return value


def _validate_provenance(value: object, *, resource: str) -> dict[str, Any]:
    fields = frozenset(
        {
            "origin",
            "path",
            "observed_at",
            "body_sha256",
            "peer_certificate_sha256",
            "tls_version",
            "cipher",
            "content_type",
            "method",
            "redirect_followed",
        }
    )
    provenance = _exact_object(value, fields, "provenance")
    if (
        provenance["origin"] != ORIGIN
        or provenance["method"] != "GET"
        or provenance["redirect_followed"] is not False
    ):
        raise ConsumerError("provenance origin, method or redirect policy mismatch")
    path = _bounded_text(provenance["path"], "provenance path", 512)
    content_type = _bounded_text(provenance["content_type"], "content type", 256)
    if resource == "patterns":
        if path != "/patterns.md" or content_type not in PATTERNS_CONTENT_TYPES:
            raise ConsumerError("patterns provenance path or media type mismatch")
    else:
        match = LOBBY_PATH_RE.fullmatch(path)
        if (
            match is None
            or int(match.group(2)) > MAX_ROOM_LIMIT
            or content_type not in LOBBY_CONTENT_TYPES
        ):
            raise ConsumerError("lobby provenance path, limit or media type mismatch")
    observed_at = _bounded_text(provenance["observed_at"], "observation timestamp", 64)
    try:
        parsed = datetime.fromisoformat(observed_at)
    except ValueError as exc:
        raise ConsumerError("observation timestamp is not ISO 8601") from exc
    if parsed.tzinfo is None:
        raise ConsumerError("observation timestamp lacks timezone")
    _hash(provenance["body_sha256"], "body hash")
    certificate_hash = _hash(provenance["peer_certificate_sha256"], "certificate hash")
    if certificate_hash == hashlib.sha256(b"").hexdigest():
        raise ConsumerError("certificate hash cannot describe empty input")
    if not _bounded_text(provenance["tls_version"], "TLS version", 128):
        raise ConsumerError("TLS version cannot be empty")
    if not _bounded_text(provenance["cipher"], "TLS cipher", 128):
        raise ConsumerError("TLS cipher cannot be empty")
    return provenance


def _message_digest(message: dict[str, object]) -> str:
    raw = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def _validate_lobby(record: dict[str, Any]) -> None:
    fields = frozenset(
        {
            "schema",
            "origin",
            "room",
            "cursor",
            "cursor_status",
            "dedupe_key",
            "trust",
            "provenance",
            "untrusted_data",
        }
    )
    _exact_object(record, fields, "lobby record")
    if record["room"] != "lobby":
        raise ConsumerError("lobby record room mismatch")
    cursor = _bounded_integer(record["cursor"], "record cursor", MAX_CURSOR)
    status = _exact_object(
        record["cursor_status"],
        frozenset({"bootstrap", "gap_before_first_seq"}),
        "cursor status",
    )
    if type(status["bootstrap"]) is not bool:
        raise ConsumerError("cursor bootstrap marker is not boolean")
    gap = _bounded_integer(status["gap_before_first_seq"], "bootstrap gap", MAX_CURSOR)
    if not status["bootstrap"] and gap != 0:
        raise ConsumerError("non-bootstrap record cannot declare a prior gap")
    provenance = _validate_provenance(record["provenance"], resource="lobby")
    match = LOBBY_PATH_RE.fullmatch(provenance["path"])
    if match is None:
        raise ConsumerError("lobby provenance path mismatch")
    since = int(match.group(1))
    if cursor <= since or (status["bootstrap"] and since != 0):
        raise ConsumerError("record cursor is inconsistent with the requested cursor")
    data = record["untrusted_data"]
    if type(data) is not dict or frozenset(data) not in (
        frozenset({"seq", "ts", "from", "text"}),
        frozenset({"seq", "ts", "from", "text", "nonce"}),
    ):
        raise ConsumerError("lobby untrusted_data has an unknown or missing field")
    if _bounded_integer(data["seq"], "message sequence", MAX_CURSOR) != cursor:
        raise ConsumerError("message sequence differs from record cursor")
    _bounded_text(data["ts"], "message timestamp", 64)
    _bounded_text(data["from"], "message sender", 160)
    _bounded_text(data["text"], "message text", MAX_TEXT_CHARS)
    if "nonce" in data:
        _bounded_integer(data["nonce"], "message nonce", MAX_NONCE)
    if _hash(record["dedupe_key"], "dedupe key") != _message_digest(data):
        raise ConsumerError("lobby dedupe key is not bound to untrusted_data")


def _validate_patterns(record: dict[str, Any]) -> None:
    fields = frozenset(
        {
            "schema",
            "origin",
            "resource",
            "dedupe_key",
            "trust",
            "provenance",
            "untrusted_data",
        }
    )
    _exact_object(record, fields, "patterns record")
    if record["resource"] != "patterns":
        raise ConsumerError("patterns resource mismatch")
    provenance = _validate_provenance(record["provenance"], resource="patterns")
    data = _exact_object(record["untrusted_data"], frozenset({"text"}), "patterns data")
    text = _bounded_text(data["text"], "patterns text", MAX_PATTERNS_BODY)
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_PATTERNS_BODY:
        raise ConsumerError("patterns UTF-8 text exceeds the byte bound")
    digest = hashlib.sha256(encoded).hexdigest()
    if (
        _hash(record["dedupe_key"], "dedupe key") != digest
        or provenance["body_sha256"] != digest
    ):
        raise ConsumerError("patterns hashes are not bound to the UTF-8 text")


def validate_record(record: object) -> dict[str, Any]:
    if type(record) is not dict:
        raise ConsumerError("JSONL item is not an object")
    if record.get("schema") != INPUT_SCHEMA or record.get("origin") != ORIGIN:
        raise ConsumerError("record schema or origin mismatch")
    if record.get("trust") != TRUST:
        raise ConsumerError("record is not explicitly UNTRUSTED_DATA")
    if "room" in record:
        _validate_lobby(record)
    elif "resource" in record:
        _validate_patterns(record)
    else:
        raise ConsumerError("record has no supported resource discriminator")
    return record


def _visible_text(value: str) -> tuple[str, int]:
    normalized = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    changed = int(normalized != value)
    output: list[str] = []
    for character in normalized:
        codepoint = ord(character)
        if codepoint in BIDI_CONTROLS or (
            unicodedata.category(character) == "Cc" and character not in {"\n", "\t"}
        ):
            output.append(f"\\u{codepoint:04X}" if codepoint <= 0xFFFF else f"\\U{codepoint:08X}")
            changed += 1
        else:
            output.append(character)
    return "".join(output), changed


def sanitize_record(record: object) -> dict[str, Any]:
    source = validate_record(record)
    source_line = _canonical_line(source)
    clean_data: dict[str, object] = {}
    changes = 0
    for key, value in source["untrusted_data"].items():
        if type(value) is str:
            clean_data[key], count = _visible_text(value)
            changes += count
        else:
            clean_data[key] = value
    output: dict[str, Any] = {
        "schema": OUTPUT_SCHEMA,
        "origin": ORIGIN,
        "trust": TRUST,
        "source_record_sha256": hashlib.sha256(source_line).hexdigest(),
        "dedupe_key": source["dedupe_key"],
        "provenance": source["provenance"],
        "sanitization": {
            "profile": SANITIZATION_PROFILE,
            "changes": changes,
            "human_review_required": True,
        },
        "untrusted_data": clean_data,
    }
    if "room" in source:
        output.update(
            {
                "room": source["room"],
                "cursor": source["cursor"],
                "cursor_status": source["cursor_status"],
            }
        )
    else:
        output["resource"] = source["resource"]
    return output


def sanitize_records(records: Iterable[object]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        if len(output) >= MAX_RECORDS:
            raise ConsumerError("record count exceeds the bound")
        sanitized = sanitize_record(record)
        dedupe_key = sanitized["dedupe_key"]
        if dedupe_key in seen:
            raise ConsumerError("duplicate dedupe key in one input batch")
        seen.add(dedupe_key)
        output.append(sanitized)
    return output


def _validate_visible(value: object, label: str, maximum: int) -> str:
    text = _bounded_text(value, label, maximum)
    visible, changes = _visible_text(text)
    if changes or visible != text:
        raise ConsumerError(f"{label} contains non-sanitized Unicode or controls")
    return text


def _validate_sanitized_record(record: object) -> dict[str, Any]:
    if type(record) is not dict:
        raise ConsumerError("sanitized JSONL item is not an object")
    if (
        record.get("schema") != OUTPUT_SCHEMA
        or record.get("origin") != ORIGIN
        or record.get("trust") != TRUST
    ):
        raise ConsumerError("sanitized record schema, origin or trust mismatch")
    _hash(record.get("source_record_sha256"), "source record hash")
    _hash(record.get("dedupe_key"), "sanitized dedupe key")
    sanitization = _exact_object(
        record.get("sanitization"),
        frozenset({"profile", "changes", "human_review_required"}),
        "sanitization metadata",
    )
    if (
        sanitization["profile"] != SANITIZATION_PROFILE
        or sanitization["human_review_required"] is not True
        or type(sanitization["changes"]) is not int
        or not 0 <= sanitization["changes"] <= MAX_INPUT_BYTES
    ):
        raise ConsumerError("sanitization metadata mismatch")

    if "room" in record:
        fields = frozenset(
            {
                "schema",
                "origin",
                "room",
                "cursor",
                "cursor_status",
                "dedupe_key",
                "source_record_sha256",
                "trust",
                "provenance",
                "sanitization",
                "untrusted_data",
            }
        )
        _exact_object(record, fields, "sanitized lobby record")
        if record["room"] != "lobby":
            raise ConsumerError("sanitized lobby room mismatch")
        cursor = _bounded_integer(record["cursor"], "sanitized cursor", MAX_CURSOR)
        status = _exact_object(
            record["cursor_status"],
            frozenset({"bootstrap", "gap_before_first_seq"}),
            "sanitized cursor status",
        )
        if type(status["bootstrap"]) is not bool:
            raise ConsumerError("sanitized bootstrap marker is not boolean")
        gap = _bounded_integer(status["gap_before_first_seq"], "sanitized gap", MAX_CURSOR)
        if not status["bootstrap"] and gap != 0:
            raise ConsumerError("sanitized non-bootstrap record declares a gap")
        _validate_provenance(record["provenance"], resource="lobby")
        data = record["untrusted_data"]
        if type(data) is not dict or frozenset(data) not in (
            frozenset({"seq", "ts", "from", "text"}),
            frozenset({"seq", "ts", "from", "text", "nonce"}),
        ):
            raise ConsumerError("sanitized lobby data has an unknown or missing field")
        if _bounded_integer(data["seq"], "sanitized sequence", MAX_CURSOR) != cursor:
            raise ConsumerError("sanitized sequence differs from cursor")
        _validate_visible(data["ts"], "sanitized timestamp", 64 * 6)
        _validate_visible(data["from"], "sanitized sender", 160 * 6)
        _validate_visible(data["text"], "sanitized message text", MAX_SANITIZED_LOBBY_TEXT)
        if "nonce" in data:
            _bounded_integer(data["nonce"], "sanitized nonce", MAX_NONCE)
    elif "resource" in record:
        fields = frozenset(
            {
                "schema",
                "origin",
                "resource",
                "dedupe_key",
                "source_record_sha256",
                "trust",
                "provenance",
                "sanitization",
                "untrusted_data",
            }
        )
        _exact_object(record, fields, "sanitized patterns record")
        if record["resource"] != "patterns":
            raise ConsumerError("sanitized patterns resource mismatch")
        _validate_provenance(record["provenance"], resource="patterns")
        data = _exact_object(
            record["untrusted_data"], frozenset({"text"}), "sanitized patterns data"
        )
        _validate_visible(data["text"], "sanitized patterns text", MAX_SANITIZED_PATTERNS_TEXT)
    else:
        raise ConsumerError("sanitized record has no supported resource discriminator")
    return record


def decode_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_INPUT_BYTES:
        raise ConsumerError("JSONL input exceeds the byte bound")
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        raise ConsumerError("JSONL input must end with a newline")
    lines = raw.splitlines(keepends=True)
    if len(lines) > MAX_RECORDS:
        raise ConsumerError("JSONL record count exceeds the bound")
    records: list[object] = []
    for line in lines:
        if line == b"\n" or len(line) > MAX_LINE_BYTES:
            raise ConsumerError("JSONL contains an empty or oversized line")
        try:
            text = line[:-1].decode("utf-8", "strict")
            value = json.loads(
                text,
                object_pairs_hook=_closed_pairs,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ConsumerError("JSONL contains invalid canonical UTF-8 JSON") from exc
        if _canonical_line(value) != line:
            raise ConsumerError("JSONL input is not canonical")
        records.append(value)
    return sanitize_records(records)


def sanitized_jsonl(records: Iterable[dict[str, Any]]) -> bytes:
    validated: list[dict[str, Any]] = []
    for record in records:
        if len(validated) >= MAX_RECORDS:
            raise ConsumerError("sanitized record count exceeds the bound")
        validated.append(_validate_sanitized_record(record))
    raw = b"".join(_canonical_line(record) for record in validated)
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ConsumerError("sanitized output exceeds the byte bound")
    return raw


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ConsumerError("short sanitized output write")
        view = view[written:]


def save_sanitized(path: Path, records: Iterable[dict[str, Any]], *, replace: bool = False) -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_CLOEXEC")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise ConsumerError("sanitized output requires a POSIX platform")
    parent = path.parent
    if path.name in {"", ".", ".."}:
        raise ConsumerError("output filename is invalid")
    raw = sanitized_jsonl(records)
    temporary = f".{path.name}.tmp.{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise ConsumerError("output parent must be an existing non-symlink directory") from exc
    descriptor: int | None = None
    published = False
    try:
        try:
            metadata = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        if metadata is not None:
            if stat.S_ISLNK(metadata.st_mode):
                raise ConsumerError("output must not be a symlink")
            if not replace:
                raise ConsumerError("output exists; use --replace only after review")
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ConsumerError("existing output must be a regular mode-0600 file")
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_descriptor)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if replace:
            os.replace(
                temporary,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
        else:
            try:
                os.link(
                    temporary,
                    path.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise ConsumerError("output exists; use --replace only after review") from exc
            os.unlink(temporary, dir_fd=parent_descriptor)
        published = True
        os.fsync(parent_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not published:
            try:
                os.unlink(temporary, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)
