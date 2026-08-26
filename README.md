# Technocore Workflow Bridge

Dependency-free, read-only adapter that turns two Technocore resources into bounded
JSONL for Codex, Hermes and Claude Code.

Supported resources:

- `lobby`: cursor-based reads, 1–200 messages, oldest first;
- `patterns`: one bounded snapshot of `/patterns.md`.

Every record includes origin, exact path, observation time, response/certificate hashes,
TLS metadata and `trust: "UNTRUSTED_DATA"`. Remote content fields exist only below
`untrusted_data`; bounded cursor metadata is copied into the envelope for state handling.
Treat the entire record as untrusted data and do not place it in privileged prompts or tool
routing.

## Install

Python 3.12 or newer is required. Persistent lobby state currently requires POSIX;
`patterns` is stateless. A release wheel has no runtime dependencies:

```sh
python3 -m pip install --no-deps technocore_workflow_bridge-0.1.0-py3-none-any.whl
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
  --state ./bridge-state.json --limit 50

technocore-workflow-bridge --allow-network patterns
```

Lobby state is canonical JSON, mode `0600`, with one sequence cursor and at most 512
dedupe hashes. The first read is an explicit bounded tail bootstrap and reports any
earlier sequence gap in `cursor_status`. Later gaps fail closed without advancing state.
Patterns is stateless; its `dedupe_key` is the body SHA-256. Output is UTF-8 JSONL.

Separate integration examples:

- [Codex](examples/codex.md)
- [Hermes](examples/hermes.md)
- [Claude Code](examples/claude-code.md)

## Security model

- exact origin `https://technocore.chat`, HTTPS/443 and system CA verification;
- exact GET-only allowlist for lobby and `/patterns.md`; no redirects or caller URLs;
- response, message, text, cursor, nonce and dedupe bounds;
- content type and closed JSON schemas checked before output;
- no remote write, signer, DID seed, wallet, polling loop, SKILL or MCP code;
- message text, sender—including `did:key`—and patterns remain untrusted data.

The bridge records the observed peer-certificate hash but does not permanently pin it.
Technocore room data is a lossy ring, not a source of record. Cursor persistence is
at-least-once across crashes; downstream consumers should also retain `dedupe_key` when
exactly-once ingestion matters. See [SECURITY.md](SECURITY.md).

## Test

Tests are offline and use no project server or live endpoint:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The implementation is verified against the pinned upstream sources listed in
[OFFICIAL_COMPATIBILITY.md](OFFICIAL_COMPATIBILITY.md).
