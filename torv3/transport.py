"""Adapters between a Tor circuit, byte streams, and TLS."""

from __future__ import annotations

import ssl
import time

from .circuit import Circuit
from .errors import TorConnectionError, TorStreamError


class CircuitStream:
    """One Tor stream exposed as a byte stream."""

    def __init__(self, circuit: Circuit, stream_id: int) -> None:
        self.circuit = circuit
        self.stream_id = stream_id

    def write(self, data: bytes) -> None:
        self.circuit.send_data(self.stream_id, data)

    def read(self, timeout: float) -> bytes:
        data = self.circuit.read_stream_data_if_available(self.stream_id, max(0.01, timeout))
        return data or b""

    def close(self) -> None:
        self.circuit.close_stream(self.stream_id)


class TLSStream:
    """TLS over a byte stream using an SSL memory BIO."""

    def __init__(self, transport: CircuitStream, host: str, verify: bool, timeout: float) -> None:
        self.transport = transport
        self.host = host
        self.timeout = timeout
        if verify:
            self.context = ssl.create_default_context()
        else:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.ssl_object = self.context.wrap_bio(
            self.incoming,
            self.outgoing,
            server_side=False,
            server_hostname=host if verify else None,
        )
        self._handshake()

    def _flush(self) -> None:
        data = self.outgoing.read()
        if data:
            self.transport.write(data)

    def _pump(self, timeout: float) -> None:
        data = self.transport.read(timeout)
        if not data:
            return
        self.incoming.write(data)

    def _handshake(self) -> None:
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self.ssl_object.do_handshake()
                self._flush()
                return
            except ssl.SSLWantReadError:
                self._flush()
                if time.monotonic() >= deadline:
                    raise TorConnectionError(f"TLS handshake with {self.host} timed out")
                self._pump(max(0.05, deadline - time.monotonic()))
            except ssl.SSLWantWriteError:
                self._flush()
            except ssl.SSLError as exc:
                raise TorConnectionError(f"TLS handshake with {self.host} failed: {exc}") from exc

    def write(self, data: bytes) -> None:
        deadline = time.monotonic() + self.timeout
        view = memoryview(data)
        while view:
            try:
                written = self.ssl_object.write(view)
                view = view[written:]
                self._flush()
            except ssl.SSLWantWriteError:
                self._flush()
            except ssl.SSLWantReadError:
                self._flush()
                if time.monotonic() >= deadline:
                    raise TorConnectionError(f"TLS write to {self.host} timed out")
                self._pump(max(0.05, deadline - time.monotonic()))
            except ssl.SSLError as exc:
                raise TorConnectionError(f"TLS write to {self.host} failed: {exc}") from exc

    def read(self, timeout: float) -> bytes:
        deadline = time.monotonic() + max(0.01, timeout)
        while True:
            try:
                data = self.ssl_object.read(16384)
                self._flush()
                return data
            except ssl.SSLWantReadError:
                self._flush()
                if time.monotonic() >= deadline:
                    return b""
                self._pump(max(0.05, deadline - time.monotonic()))
            except ssl.SSLWantWriteError:
                self._flush()
            except ssl.SSLZeroReturnError:
                return b""
            except ssl.SSLError as exc:
                raise TorStreamError(f"TLS read from {self.host} failed: {exc}") from exc

    def close(self) -> None:
        try:
            self.ssl_object.unwrap()
        except (ssl.SSLError, ValueError):
            pass
        try:
            self._flush()
        except TorStreamError:
            pass
