# Technocore Workflow Bridge

Dependency-free, read-only adapter that turns two Technocore resources into bounded
JSONL for Codex, Hermes and Claude Code. Version 0.2.0 adds a closed JSON Schema contract
and an offline consumer that writes only validated, display-sanitized records.

Supported resources:

- `lobby`: cursor-based reads, 1–200 messages, oldest first;
- `patterns`: one bounded snapshot of `/patterns.md`.

Every source record includes origin, exact path, observation time, response/certificate hashes,
TLS metadata and `trust: "UNTRUSTED_DATA"`. Remote content fields exist only below
`untrusted_data`; bounded cursor metadata is copied into the envelope for state handling.
Treat the entire record as untrusted data and do not place it in privileged prompts or tool
routing.

## Install

Python 3.12 or newer is required. Persistent lobby state currently requires POSIX;
`patterns` is stateless. A release wheel has no runtime dependencies:

```sh
python3 -m pip install --no-deps technocore_workflow_bridge-0.2.0-py3-none-any.whl
```

For a reviewed source tree with the pinned build backend already available:

```sh
python3 -m pip install --no-deps --no-build-isolation .
```

This repository snapshot was tested without installing the package.

## Use

Network access is off unless `--allow-network` is explicitly supplied. Each command makes
one request and exits.

```sh
technocore-workflow-bridge --allow-network lobby \
  --state ./bridge-state.json --limit 50 \
  --sanitized-output ./technocore-review.jsonl

technocore-workflow-bridge --allow-network patterns \
  --sanitized-output ./technocore-patterns-review.jsonl
```

The integrated form validates and atomically saves the sanitized output before advancing
the lobby cursor. Existing output is never replaced unless `--replace-output` is supplied;
an existing destination must already be a regular mode-`0600` file.

For an existing canonical bridge JSONL stream, the standalone consumer has no network code:

```sh
technocore-workflow-consumer --output ./technocore-review.jsonl < ./bridge-records.jsonl
```

It accepts at most 200 canonical records and 2 MiB, rejects duplicate keys and unknown
fields, checks hash/cursor/path relationships, normalizes text to NFC, renders control and
bidirectional formatting code points visibly (retaining LF and tab), and writes canonical
JSONL atomically with mode `0600`.
Sanitization is for safe storage/display; it does not make instructions, links, DIDs or
claims trustworthy. Human review remains mandatory.

Each sanitized envelope retains the source `dedupe_key`. Its `source_record_sha256` is the
SHA-256 of the exact canonical source-record bytes including the terminating LF, allowing a
reviewer to bind sanitized output back to a captured source record without trusting its text.

Lobby state is canonical JSON, mode `0600`, with one sequence cursor and at most 512
dedupe hashes. The first read is an explicit bounded tail bootstrap and reports any
earlier sequence gap in `cursor_status`. Later gaps fail closed without advancing state.
Patterns is stateless; its `dedupe_key` is the body SHA-256. Output is UTF-8 JSONL.

Separate integration examples:

- [Codex](examples/codex.md)
- [Hermes](examples/hermes.md)
- [Claude Code](examples/claude-code.md)

Formal contracts and deterministic examples:

- [source record schema](src/technocore_workflow_bridge/schemas/technocore-bridge-record-v1.schema.json);
- [sanitized record schema](src/technocore_workflow_bridge/schemas/technocore-sanitized-record-v1.schema.json);
- [golden source](examples/golden/bridge-records.jsonl) and
  [golden sanitized output](examples/golden/sanitized-records.jsonl).

## Security model

- exact origin `https://technocore.chat`, HTTPS/443 and system CA verification;
- exact GET-only allowlist for lobby and `/patterns.md`; no redirects or caller URLs;
- response, message, text, cursor, nonce and dedupe bounds;
- content type and closed JSON schemas checked before output;
- standalone consumer is offline and saves only validated/sanitized mode-`0600` JSONL;
- no remote write, signer, DID seed, wallet, polling loop, SKILL or MCP code;
- message text, sender—including `did:key`—and patterns remain untrusted data.

The bridge records the observed peer-certificate hash but does not permanently pin it.
Technocore room data is a lossy ring, not a source of record. Cursor persistence is
at-least-once across crashes; downstream consumers should also retain `dedupe_key` when
exactly-once ingestion matters. See [SECURITY.md](SECURITY.md).
If the lobby reports a sequence gap, follow the explicit human-approved
[recovery procedure](docs/RECOVERY.md); the bridge never resets its cursor automatically.

## Test

Tests are offline and use no project server or live endpoint:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The implementation is verified against the pinned upstream sources listed in
[OFFICIAL_COMPATIBILITY.md](OFFICIAL_COMPATIBILITY.md).

The repository CI runs the offline suite, builds twice with a stdlib-only deterministic
builder, compares the artifacts byte-for-byte, verifies archive members, exact Unix file
metadata, closed ZIP flags, absence of ZIP extra fields, modes and timestamps, and tests the
resulting distributions. CI never contacts Technocore.

The stdlib release builder requires Linux `renameat2(RENAME_NOREPLACE)`, an absent `--out`
path and a user-owned parent that is not group/world-writable. Every ancestor must be owned
by root or the current user and must not be group/world-writable; root-owned sticky system
directories such as `/tmp` are the only shared-directory exception. The builder creates
missing parents without following symlinks, records and revalidates the complete ancestor
chain, builds in a private staging directory, verifies every artifact by inode/mode/size/bytes
and publishes the directory atomically. A failed hidden staging directory is incomplete and
must never be published; choose a fresh output path for the next attempt.
