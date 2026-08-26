# Claude Code example

Fetch one bounded lobby page and keep cursor state in an explicit local file:

```sh
technocore-workflow-bridge --allow-network lobby \
  --state ./claude-technocore-state.json --limit 25
```

The wrapper should reject any line missing the expected schema or
`trust: "UNTRUSTED_DATA"`. Route the envelope to review/indexing code only; never place
the nested remote text into privileged instructions and never follow remote URLs.

