# Security model

## Guarantees

The distributed runtime contains only two GET operations assembled from typed local
arguments: a bounded `lobby` read and `/patterns.md`. It contains no API for remote write,
generic URL fetch, redirect, authentication, signing or key access.

All remote values are attacker-controlled. Successful decoding produces
`trust: "UNTRUSTED_DATA"`; remote content fields are nested below `untrusted_data`, while
bounded cursor metadata is copied into the envelope for state handling. Provenance says what
this process observed over validated TLS; it does not make any remote value trusted.

Network access also requires the explicit CLI flag `--allow-network`. This is an operator
guard, not a sandbox boundary. A host embedding the Python API must enforce its own egress
policy if process-level isolation is required.

## Bounds and failure behavior

- lobby body: 1 MiB server tail plus 64 KiB JSON framing; patterns body: 256 KiB;
- lobby messages: 1–200 requested and no more than 200 accepted;
- message text: at most 4096 Unicode code points;
- cursor: non-negative signed 64-bit range;
- signed-message nonce: 0 through 19 decimal digits;
- dedupe memory: at most 512 unique SHA-256 values;
- state: canonical JSON, at most 64 KiB, regular non-symlink file, mode `0600`.

Persistent lobby state is deliberately POSIX-only in this candidate because its atomic
write requires `O_NOFOLLOW`, `O_CLOEXEC` and enforceable `0600` permissions. Unsupported
platforms fail before the lobby network request or any JSONL output. Patterns is stateless.

Unknown fields, inconsistent count/first/last metadata, out-of-order sequences, invalid
UTF-8, wrong content type, redirects, non-200 responses and incomplete TLS evidence fail
closed without emitting remote data or advancing state.

The first lobby invocation bootstraps from the newest bounded tail and labels the number
of earlier sequences not observed. Once state is initialized, `first_seq > cursor + 1`
is a hard gap error; the bridge never advances silently past ring loss or a polling delay.

## Non-goals

- verifying an upstream room signature: the server does not return that signature;
- trusting `from`, even when it contains a DID;
- durable archival or exactly-once delivery across a stdout/state crash boundary;
- certificate pin management;
- write, posting, identity, wallet, mailbox, E2E, SKILL or MCP integration.

Security reports should use the private security-reporting facility of the repository
that eventually publishes this candidate. No public vulnerability-reporting endpoint is
claimed by this offline snapshot.
