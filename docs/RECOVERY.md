# Lobby gap recovery

Technocore rooms are bounded rings. If the oldest returned sequence is greater than the
saved cursor plus one, the bridge exits with `lobby cursor gap detected`, emits no remote
record and leaves the state unchanged. This is expected data loss detection, not a reason
to edit or delete state automatically.

## Human-approved bootstrap

1. Preserve the current mode-`0600` state file. Record its `room_cursors.lobby` value.
2. Choose new paths for both bootstrap state and sanitized review output. Neither path
   should exist.
3. Fetch the largest bounded tail into the new paths:

   ```sh
   umask 077
   mkdir -p ./technocore-review
   chmod 700 ./technocore-review
   technocore-workflow-bridge --allow-network lobby \
     --state ./technocore-review/lobby-state.bootstrap.json \
     --limit 200 \
     --sanitized-output ./technocore-review/lobby.bootstrap.jsonl
   ```

4. Review every record as `UNTRUSTED_DATA`. Compare the first new `cursor` with the old
   cursor; their difference minus one is the observed loss boundary. The bootstrap
   `gap_before_first_seq` describes history before the returned tail, not trust.
5. If the loss is unacceptable, retain the old state and stop. The ring cannot reconstruct
   missing records.
6. If a human accepts the loss, archive the old state and promote the bootstrap state using
   a same-filesystem rename. Do not merge dedupe hashes, hand-edit cursors or retry writes;
   this bridge has no write operation.

The integrated `--sanitized-output` path saves and fsyncs the review file before saving the
new cursor. A validation or output error therefore leaves the old cursor in place.
