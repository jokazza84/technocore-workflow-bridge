"""Read-only decoding and HTTPS transport for Technocore.

Remote content is data. This module never interprets message text as configuration,
instructions, URLs, tool calls or code.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import ssl
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

ORIGIN = "https://technocore.chat"
HOST = "technocore.chat"
PORT = 443
TRUST = "UNTRUSTED_DATA"
REMOTE_WRITES_ENABLED = False
ALLOWED_ROOM = "lobby"
MAX_ROOM_LIMIT = 200
# The pinned server scans a 1 MiB room tail. Allow bounded JSON framing above that raw ring slice.
MAX_ROOM_BODY = (1 << 20) + (64 << 10)
MAX_PATTERNS_BODY = 256 * 1024
MAX_TEXT_CHARS = 4096
MAX_DEDUPE = 512
MAX_CURSOR = (1 << 63) - 1
MAX_NONCE = 10**19 - 1
HEX64_RE = re.compile(r"[0-9a-f]{64}")
STATE_FIELDS = frozenset({"schema", "initialized", "room_cursors", "seen_digests"})
ROOM_VIEW_FIELDS = frozenset({"room", "count", "first_seq", "last_seq", "messages"})
ROOM_READ_PATH_RE = re.compile(
    r"/r/lobby\?format=json&since=(0|[1-9][0-9]*)&limit=([1-9][0-9]{0,2})"
)


class BridgeError(RuntimeError):
    pass


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def jsonl(records: Iterable[dict[str, Any]]) -> bytes:
    return b"".join(_json_bytes(record) for record in records)


@dataclass(frozen=True)
class _Evidence:
    path: str
    observed_at: str
    body_sha256: str
    peer_certificate_sha256: str
    tls_version: str
    cipher: str
    content_type: str

    def __post_init__(self) -> None:
        if len(self.path) > 512 or "\r" in self.path or "\n" in self.path:
            raise BridgeError("evidence path is invalid")
        if not HEX64_RE.fullmatch(self.body_sha256):
            raise BridgeError("evidence body hash is invalid")
        if (
            not HEX64_RE.fullmatch(self.peer_certificate_sha256)
            or self.peer_certificate_sha256 == hashlib.sha256(b"").hexdigest()
        ):
            raise BridgeError("evidence certificate hash is invalid")
        try:
            observed = datetime.fromisoformat(self.observed_at)
        except ValueError as exc:
            raise BridgeError("evidence observation time is invalid") from exc
        if observed.tzinfo is None:
            raise BridgeError("evidence observation time must include a timezone")
        for field, value in (("TLS version", self.tls_version), ("cipher", self.cipher)):
            if type(value) is not str or not 1 <= len(value) <= 128:
                raise BridgeError(f"evidence {field} is invalid")
        if type(self.content_type) is not str or len(self.content_type) > 256:
            raise BridgeError("evidence content type is invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "origin": ORIGIN,
            "path": self.path,
            "observed_at": self.observed_at,
            "body_sha256": self.body_sha256,
            "peer_certificate_sha256": self.peer_certificate_sha256,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "content_type": self.content_type,
            "method": "GET",
            "redirect_followed": False,
        }


@dataclass(frozen=True)
class CursorState:
    lobby_cursor: int = 0
    seen_digests: tuple[str, ...] = ()
    initialized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.lobby_cursor) is not int
            or self.lobby_cursor < 0
            or self.lobby_cursor > MAX_CURSOR
        ):
            raise BridgeError("lobby cursor must be a bounded non-negative integer")
        if len(self.seen_digests) > MAX_DEDUPE or len(set(self.seen_digests)) != len(
            self.seen_digests
        ):
            raise BridgeError("dedupe state is invalid or exceeds its bound")
        if any(not HEX64_RE.fullmatch(value) for value in self.seen_digests):
            raise BridgeError("dedupe keys must be lowercase SHA-256 hex")
        if type(self.initialized) is not bool:
            raise BridgeError("initialized must be a boolean")
        if not self.initialized and (self.lobby_cursor != 0 or self.seen_digests):
            raise BridgeError("uninitialized state cannot contain cursor or dedupe history")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "TECHNOCORE_BRIDGE_STATE_V1",
            "initialized": self.initialized,
            "room_cursors": {"lobby": self.lobby_cursor},
            "seen_digests": list(self.seen_digests),
        }

    @classmethod
    def load(cls, path: Path) -> "CursorState":
        _require_secure_state_platform()
        if path.is_symlink():
            raise BridgeError("state must not be a symlink")
        if not path.exists():
            return cls()
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise BridgeError("state must be a regular non-symlink file")
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 64 * 1024:
            raise BridgeError("state mode or size is outside policy")
        raw = path.read_bytes()
        try:
            value = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BridgeError("state is not valid UTF-8 JSON") from exc
        if type(value) is not dict or frozenset(value) != STATE_FIELDS:
            raise BridgeError("state has an unknown or missing field")
        cursors = value["room_cursors"]
        seen = value["seen_digests"]
        if (
            value["schema"] != "TECHNOCORE_BRIDGE_STATE_V1"
            or type(value["initialized"]) is not bool
            or type(cursors) is not dict
            or frozenset(cursors) != {"lobby"}
            or type(seen) is not list
            or any(type(item) is not str for item in seen)
        ):
            raise BridgeError("state schema mismatch")
        if raw != _json_bytes(value):
            raise BridgeError("state is not canonical JSON")
        return cls(cursors["lobby"], tuple(seen), value["initialized"])

    def save(self, path: Path) -> None:
        _require_secure_state_platform()
        parent = path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise BridgeError("state parent must be an existing non-symlink directory")
        if path.is_symlink():
            raise BridgeError("refusing to replace symlink state")
        if path.exists():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise BridgeError("refusing to replace non-regular state")
        temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        replaced = False
        try:
            raw = _json_bytes(self.as_dict())
            if os.write(descriptor, raw) != len(raw):
                raise BridgeError("short state write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, path)
            replaced = True
        finally:
            if not replaced and temporary.exists():
                temporary.unlink()


def _require_secure_state_platform() -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_CLOEXEC")
    ):
        raise BridgeError("persistent lobby state requires a POSIX platform")


def _strict_text(value: object, field: str, maximum: int) -> str:
    if type(value) is not str or len(value) > maximum:
        raise BridgeError(f"remote {field} is not a bounded string")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise BridgeError(f"remote {field} contains an invalid surrogate") from exc
    return value


def _dedupe_key(message: dict[str, object]) -> str:
    raw = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def _decode_lobby(
    body: bytes, evidence: _Evidence, state: CursorState
) -> tuple[list[dict[str, Any]], CursorState]:
    if len(body) > MAX_ROOM_BODY:
        raise BridgeError("lobby response exceeds the byte bound")
    path_match = ROOM_READ_PATH_RE.fullmatch(evidence.path)
    if (
        path_match is None
        or int(path_match.group(1)) != state.lobby_cursor
        or int(path_match.group(2)) > MAX_ROOM_LIMIT
        or evidence.content_type.split(";", 1)[0].strip().lower() != "application/json"
        or evidence.body_sha256 != hashlib.sha256(body).hexdigest()
    ):
        raise BridgeError("lobby evidence is not bound to the response bytes and cursor")
    try:
        payload = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BridgeError("lobby response is not valid bounded JSON") from exc
    if type(payload) is not dict or frozenset(payload) != ROOM_VIEW_FIELDS:
        raise BridgeError("lobby response schema mismatch")
    messages = payload.get("messages")
    if payload.get("room") != ALLOWED_ROOM or type(messages) is not list:
        raise BridgeError("lobby response schema mismatch")
    requested_limit = int(path_match.group(2))
    if len(messages) > requested_limit:
        raise BridgeError("lobby response exceeds the requested message bound")
    count = payload["count"]
    first_seq = payload["first_seq"]
    last_seq = payload["last_seq"]
    if type(count) is not int or count != len(messages):
        raise BridgeError("lobby count differs from the message list")
    if messages and (type(first_seq) is not int or not 0 <= first_seq <= MAX_CURSOR):
        raise BridgeError("non-empty lobby first_seq is invalid")
    if not messages and first_seq is not None:
        raise BridgeError("empty lobby first_seq must be null")
    if type(last_seq) is not int or not 0 <= last_seq <= MAX_CURSOR:
        raise BridgeError("lobby last_seq is invalid")
    if state.initialized and messages and first_seq > state.lobby_cursor + 1:
        raise BridgeError(
            "lobby cursor gap detected; refuse to advance and explicitly re-bootstrap"
        )
    seen = list(state.seen_digests)
    seen_set = set(seen)
    cursor = state.lobby_cursor
    records: list[dict[str, Any]] = []
    previous_seq: int | None = None
    for item in messages:
        if type(item) is not dict or frozenset(item) not in (
            {"seq", "ts", "from", "text"},
            {"seq", "ts", "from", "text", "nonce"},
        ):
            raise BridgeError("remote lobby message has an unknown or missing field")
        seq = item["seq"]
        nonce = item.get("nonce")
        if type(seq) is not int or not 0 <= seq <= MAX_CURSOR:
            raise BridgeError("remote lobby sequence is invalid")
        if seq <= state.lobby_cursor:
            raise BridgeError("remote lobby response did not honor the since cursor")
        if previous_seq is not None and seq <= previous_seq:
            raise BridgeError("remote lobby sequences are not strictly increasing")
        previous_seq = seq
        if nonce is not None and (type(nonce) is not int or not 0 <= nonce <= MAX_NONCE):
            raise BridgeError("remote lobby nonce is invalid")
        normalized: dict[str, object] = {
            "seq": seq,
            "ts": _strict_text(item["ts"], "timestamp", 64),
            "from": _strict_text(item["from"], "sender", 160),
            "text": _strict_text(item["text"], "text", MAX_TEXT_CHARS),
        }
        if nonce is not None:
            normalized["nonce"] = nonce
        digest = _dedupe_key(normalized)
        cursor = max(cursor, seq)
        if seq <= state.lobby_cursor or digest in seen_set:
            continue
        records.append(
            {
                "schema": "TECHNOCORE_BRIDGE_RECORD_V1",
                "origin": ORIGIN,
                "room": ALLOWED_ROOM,
                "cursor": seq,
                "cursor_status": {
                    "bootstrap": not state.initialized,
                    "gap_before_first_seq": (
                        max(first_seq - 1, 0) if not state.initialized and first_seq is not None else 0
                    ),
                },
                "dedupe_key": digest,
                "trust": TRUST,
                "provenance": evidence.as_dict(),
                "untrusted_data": normalized,
            }
        )
        seen.append(digest)
        seen_set.add(digest)
    if messages:
        if first_seq != messages[0]["seq"] or last_seq != messages[-1]["seq"]:
            raise BridgeError("lobby first_seq/last_seq differ from the message list")
    elif first_seq is not None or last_seq != state.lobby_cursor:
        raise BridgeError("empty lobby response has inconsistent cursor metadata")
    return records, CursorState(cursor, tuple(seen[-MAX_DEDUPE:]), True)


def _decode_patterns(body: bytes, evidence: _Evidence) -> dict[str, Any]:
    if len(body) > MAX_PATTERNS_BODY:
        raise BridgeError("patterns response exceeds the byte bound")
    if (
        evidence.path != "/patterns.md"
        or evidence.content_type.split(";", 1)[0].strip().lower() != "text/plain"
        or evidence.body_sha256 != hashlib.sha256(body).hexdigest()
    ):
        raise BridgeError("patterns evidence is not bound to the response bytes")
    try:
        text = body.decode("utf-8", "strict")
        text.encode("utf-8", "strict")
    except (UnicodeDecodeError, UnicodeEncodeError) as exc:
        raise BridgeError("patterns response is not valid UTF-8") from exc
    digest = hashlib.sha256(body).hexdigest()
    return {
        "schema": "TECHNOCORE_BRIDGE_RECORD_V1",
        "origin": ORIGIN,
        "resource": "patterns",
        "dedupe_key": digest,
        "trust": TRUST,
        "provenance": evidence.as_dict(),
        "untrusted_data": {"text": text},
    }


def _allowed_path(resource: str, cursor: int, limit: int) -> tuple[str, int]:
    if resource == "patterns":
        return "/patterns.md", MAX_PATTERNS_BODY
    if resource != "lobby":
        raise BridgeError("resource is outside the closed allowlist")
    if type(cursor) is not int or cursor < 0:
        raise BridgeError("cursor is invalid")
    if cursor > MAX_CURSOR:
        raise BridgeError("cursor exceeds the bound")
    if type(limit) is not int or not 1 <= limit <= MAX_ROOM_LIMIT:
        raise BridgeError("limit must be between 1 and 200")
    return f"/r/lobby?format=json&since={cursor}&limit={limit}", MAX_ROOM_BODY


def _https_get(path: str, maximum: int) -> tuple[bytes, _Evidence]:
    if path == "/patterns.md":
        expected_media_type = "text/plain"
    elif (match := ROOM_READ_PATH_RE.fullmatch(path)) is not None:
        if int(match.group(1)) > MAX_CURSOR or int(match.group(2)) > MAX_ROOM_LIMIT:
            raise BridgeError("transport path contains an out-of-range cursor or limit")
        expected_media_type = "application/json"
    else:
        raise BridgeError("transport path is outside the closed read allowlist")
    connection = http.client.HTTPSConnection(
        HOST, PORT, timeout=15, context=ssl.create_default_context()
    )
    try:
        connection.connect()
        if connection.sock is None:
            raise BridgeError("verified TLS socket is unavailable")
        certificate = connection.sock.getpeercert(binary_form=True)
        tls_version = connection.sock.version()
        cipher_info = connection.sock.cipher()
        cipher = cipher_info[0] if cipher_info else None
        if not certificate or not tls_version or not cipher:
            raise BridgeError("TLS evidence is incomplete")
        connection.request(
            "GET",
            path,
            headers={
                "Accept": "application/json, text/plain;q=0.9",
                "Cache-Control": "no-cache",
                "Connection": "close",
                "User-Agent": "Technocore-Workflow-Bridge/0.1",
            },
        )
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise BridgeError("redirect refused")
        if response.status != 200:
            raise BridgeError(f"Technocore returned HTTP {response.status}")
        content_type = response.getheader("Content-Type")
        if (
            type(content_type) is not str
            or content_type.split(";", 1)[0].strip().lower() != expected_media_type
        ):
            raise BridgeError("response Content-Type differs from the pinned route")
        length = response.getheader("Content-Length")
        if length is not None:
            try:
                declared = int(length)
            except ValueError as exc:
                raise BridgeError("invalid Content-Length") from exc
            if declared < 0 or declared > maximum:
                raise BridgeError("Content-Length exceeds the bound")
        body = response.read(maximum + 1)
        if len(body) > maximum:
            raise BridgeError("response exceeds the byte bound")
        evidence = _Evidence(
            path=path,
            observed_at=datetime.now(UTC).isoformat(),
            body_sha256=hashlib.sha256(body).hexdigest(),
            peer_certificate_sha256=hashlib.sha256(certificate).hexdigest(),
            tls_version=tls_version,
            cipher=cipher,
            content_type=content_type,
        )
        return body, evidence
    except BridgeError:
        raise
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise BridgeError(f"bounded HTTPS read failed: {exc.__class__.__name__}") from exc
    finally:
        connection.close()


def fetch_once(
    resource: str, *, state: CursorState | None = None, limit: int = 50
) -> tuple[list[dict[str, Any]], CursorState | None]:
    if REMOTE_WRITES_ENABLED:
        raise BridgeError("remote write policy invariant was modified")
    current = state or CursorState()
    path, maximum = _allowed_path(resource, current.lobby_cursor, limit)
    body, evidence = _https_get(path, maximum)
    if resource == "patterns":
        return [_decode_patterns(body, evidence)], None
    records, updated = _decode_lobby(body, evidence, current)
    return records, updated
