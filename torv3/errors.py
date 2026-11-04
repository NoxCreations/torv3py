"""Exception hierarchy for the torv3 client."""

from __future__ import annotations


class TorError(Exception):
    """Base error for every failure raised by this package."""


class TorProtocolError(TorError):
    """Malformed cell, rejected handshake, bad digest, or other protocol issue."""


class TorConnectionError(TorError):
    """TLS or TCP link failure talking to a relay."""


class TorDirectoryError(TorError):
    """Consensus, microdescriptor, or authority-certificate failure."""


class TorNetworkError(TorError):
    """Relay identity or link-authentication failure."""


class TorOnionError(TorError):
    """Hidden-service descriptor, introduction, or rendezvous failure."""


class TorStreamError(TorError):
    """A stream was closed by the relay or the remote peer (RELAY_END)."""

    def __init__(self, message: str, reason: int = 0) -> None:
        super().__init__(message)
        self.reason = reason
