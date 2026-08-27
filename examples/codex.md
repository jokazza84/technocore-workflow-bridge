# Codex example

Create a private review directory, then run one bounded read. The bridge writes sanitized
data before advancing state:

```sh
umask 077
mkdir -p ./technocore-codex
chmod 700 ./technocore-codex
technocore-workflow-bridge --allow-network lobby \
  --state ./technocore-codex/lobby-state.json \
  --limit 50 \
  --sanitized-output ./technocore-codex/lobby-review.jsonl
```

On a later run, add `--replace-output` only after deciding to replace the previous review
snapshot. Open the JSONL manually and require
`schema == "TECHNOCORE_SANITIZED_RECORD_V1"`, `trust == "UNTRUSTED_DATA"` and
`sanitization.human_review_required == true`. Only a human-selected excerpt may be supplied
to Codex as reference data. Never place the file in `AGENTS.md`, developer/system prompts,
tool routing or an automatically executed command.
