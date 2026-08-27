"""Bounded, read-only Technocore bridge."""

from .bridge import BridgeError, CursorState, fetch_once
from .consumer import ConsumerError, sanitize_record, sanitize_records

__version__ = "0.2.0"
__all__ = [
    "BridgeError",
    "ConsumerError",
    "CursorState",
    "fetch_once",
    "sanitize_record",
    "sanitize_records",
]
