"""One-shot CLI. Network must be explicitly enabled; remote writes do not exist."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .bridge import BridgeError, CursorState, fetch_once, jsonl
from .consumer import ConsumerError, sanitize_records, save_sanitized


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--allow-network", action="store_true")
    subcommands = parser.add_subparsers(dest="resource", required=True)
    lobby = subcommands.add_parser("lobby")
    lobby.add_argument("--state", type=Path, required=True)
    lobby.add_argument("--limit", type=int, default=50)
    lobby.add_argument("--sanitized-output", type=Path)
    lobby.add_argument("--replace-output", action="store_true")
    patterns = subcommands.add_parser("patterns")
    patterns.add_argument("--sanitized-output", type=Path)
    patterns.add_argument("--replace-output", action="store_true")
    args = parser.parse_args()
    if not args.allow_network:
        raise SystemExit("network is disabled by default; review and pass --allow-network")
    try:
        state = CursorState.load(args.state) if args.resource == "lobby" else None
        records, updated = fetch_once(
            args.resource,
            state=state,
            limit=args.limit if args.resource == "lobby" else 50,
        )
        if args.sanitized_output is not None:
            sanitized = sanitize_records(records)
            save_sanitized(args.sanitized_output, sanitized, replace=args.replace_output)
        else:
            if args.replace_output:
                raise ConsumerError("--replace-output requires --sanitized-output")
            sys.stdout.buffer.write(jsonl(records))
            sys.stdout.buffer.flush()
        if updated is not None:
            updated.save(args.state)
    except (BridgeError, ConsumerError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
