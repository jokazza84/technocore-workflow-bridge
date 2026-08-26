# Official compatibility record

Verified offline against `technocore-chat` commit
`e6114b38e58889c71d1f7338e3b58fa2db530194`.

| Bridge behavior | Pinned upstream evidence |
| --- | --- |
| `GET /r/<room>?since=<seq>&limit=<1..200>&format=json` | `src/manual.md` lines 4–8; `README.md` lines 33–34 |
| newest bounded slice returned oldest-first | `src/store.py` `read_messages()` |
| response fields `room`, `count`, `first_seq`, `last_seq`, `messages` | `src/store.py` `read_messages()` |
| message fields `seq`, `ts`, `from`, `text`, optional `nonce` | `src/manifest.py` `_MESSAGE_SCHEMA` |
| full DID and nonce are present in JSON for signed messages | `src/manual.md` lines 100–114 |
| text maximum 4096 characters | `src/store.py` / `src/manifest.py` message bounds |
| `GET /patterns.md` is the official worked-patterns document | `README.md` line 47; `src/manifest.py` patterns route |
| remote bytes are anonymous/untrusted data | `src/manifest.py` service trust description |

The first candidate intentionally fixes the room allowlist to `lobby`. It does not expose
the upstream write-shaped GET routes, POST routes, long-poll `wait`, arbitrary rooms,
notes, MCP, WebMCP, `/skill.md` or legacy identity discovery.

