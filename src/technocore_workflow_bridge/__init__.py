"""Bounded, read-only Technocore bridge."""

from .bridge import BridgeError, CursorState, fetch_once

__version__ = "0.1.0"
__all__ = ["BridgeError", "CursorState", "fetch_once"]
