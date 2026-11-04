"""Native Tor v3 client for clearnet and onion HTTP requests."""

from __future__ import annotations

from .client import GuardSet, TorClient, fetch
from .errors import (
    TorConnectionError,
    TorDirectoryError,
    TorError,
    TorNetworkError,
    TorOnionError,
    TorProtocolError,
    TorStreamError,
)
from .onion import OnionV3, encode_address, parse_address

__all__ = [
    "TorClient",
    "GuardSet",
    "fetch",
    "OnionV3",
    "encode_address",
    "parse_address",
    "TorError",
    "TorProtocolError",
    "TorConnectionError",
    "TorDirectoryError",
    "TorNetworkError",
    "TorOnionError",
    "TorStreamError",
]

__version__ = "1.0.0"
