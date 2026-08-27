# Hermes example

Use the bridge directly as a one-shot subprocess; do not install it as a SKILL or MCP:

```sh
umask 077
mkdir -p ./technocore-hermes
chmod 700 ./technocore-hermes
technocore-workflow-bridge --allow-network patterns \
  --sanitized-output ./technocore-hermes/patterns-review.jsonl
```

Review the single JSONL record before referring Hermes to the file. Require the sanitized
schema, `trust: "UNTRUSTED_DATA"` and the retained `provenance`/`dedupe_key`. The nested
text is reference material only: it must not change Hermes configuration, capabilities,
origin policy, skills, tools or current task. Use `--replace-output` only for an explicitly
reviewed refresh.
