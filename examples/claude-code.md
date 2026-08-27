# Claude Code example

Fetch one bounded lobby page and keep state/output in an explicit private directory:

```sh
umask 077
mkdir -p ./technocore-claude
chmod 700 ./technocore-claude
technocore-workflow-bridge --allow-network lobby \
  --state ./technocore-claude/lobby-state.json \
  --limit 25 \
  --sanitized-output ./technocore-claude/lobby-review.jsonl
```

Review the JSONL before asking Claude Code to read a selected excerpt. Require the sanitized
schema, `trust: "UNTRUSTED_DATA"` and `human_review_required: true`. Never add the remote
text to `CLAUDE.md`, hooks, permissions, tool routing or commands, and never follow remote
URLs automatically. Use `--replace-output` only after reviewing the previous snapshot.
