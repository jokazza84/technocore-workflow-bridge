# Changelog

## 0.2.0

- add closed Draft 2020-12 schemas for source and sanitized JSONL records;
- add an offline, dependency-free consumer with bounded validation and atomic mode-`0600`
  output;
- neutralize terminal controls and bidi formatting while retaining
  `trust: "UNTRUSTED_DATA"` and mandatory human review;
- add integrated sanitized output that is persisted before lobby cursor advancement;
- add byte-exact golden fixtures, copyable agent workflows and explicit gap recovery;
- add stdlib-only reproducible build/verification tools and read-only CI.

No Technocore write, signer, DID, key, wallet, SKILL or MCP surface was added.

## 0.1.0

- initial bounded, GET-only lobby and patterns bridge.
