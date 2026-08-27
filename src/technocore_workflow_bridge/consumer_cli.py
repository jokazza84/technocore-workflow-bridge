"""Validate bridge JSONL from stdin and atomically save sanitized JSONL."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .consumer import ConsumerError, MAX_INPUT_BYTES, decode_jsonl, save_sanitized


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace an existing regular mode-0600 output after explicit review",
    )
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ConsumerError("JSONL input exceeds the byte bound")
        records = decode_jsonl(raw)
        save_sanitized(args.output, records, replace=args.replace)
    except ConsumerError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"sanitized_records={len(records)} output={args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
