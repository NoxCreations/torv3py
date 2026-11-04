"""TLS link session to a Tor relay (tor-spec §4)."""

from __future__ import annotations

import socket
import ssl
import struct
import time

from .cells import Cell, Commands
from .certs import verify_link_certs
from .errors import TorConnectionError, TorProtocolError


class LinkSession:
    """A TLS connection speaking the Tor link protocol."""

    def __init__(self, sock: ssl.SSLSocket, address: str, port: int) -> None:
        self.sock = sock
        self.peer_address = address
        self.peer_port = port
        self.link_version = 0
        self.circ_id_width = 2

    @classmethod
    def connect(cls, address: str, port: int, timeout: float = 15.0) -> "LinkSession":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.options |= ssl.OP_NO_COMPRESSION
        try:
            raw = socket.create_connection((address, port), timeout=timeout)
            sock = context.wrap_socket(raw, server_hostname=None)
        except (OSError, ssl.SSLError) as exc:
            raise TorConnectionError(
                f"Unable to open TLS connection to {address}:{port} ({exc})"
            ) from exc

        sock.settimeout(timeout)
        return cls(sock, address, port)

    def recv_exact(self, n: int) -> bytes:
        chunks: list[bytes] = []
        remaining = n
        while remaining:
            chunk = self.sock.recv(remaining)
            if not chunk:
                raise TorConnectionError("Connection closed while reading cell data")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def send_raw(self, data: bytes) -> None:
        try:
            self.sock.sendall(data)
        except OSError as exc:
            raise TorConnectionError(f"Failed to write to relay connection: {exc}") from exc

    def send_cell(self, cell: Cell) -> None:
        self.send_raw(cell.encode(self.circ_id_width))

    def read_cell(self, timeout: float = 15.0) -> Cell:
        self.sock.settimeout(max(0.1, timeout))
        return Cell.read(self, self.circ_id_width)

    def negotiate(
        self, expected_ed25519_id: bytes | None = None, timeout: float = 30.0
    ) -> None:
        payload = b"".join(struct.pack(">H", version) for version in Commands.LINK_VERSIONS)
        self.send_raw(Cell(0, Commands.VERSIONS, payload, True).encode(2))

        deadline = time.monotonic() + timeout
        saw_netinfo = False
        certs_payload = b""
        peer_versions: list[int] | None = None

        while time.monotonic() < deadline:
            try:
                cell = self.read_cell(max(0.1, deadline - time.monotonic()))
            except TimeoutError:
                break

            if cell.command == Commands.VERSIONS:
                if peer_versions is None:
                    peer_versions = self._parse_versions(cell.payload)
                    common = sorted(set(Commands.LINK_VERSIONS) & set(peer_versions))
                    if not common:
                        raise TorProtocolError("No common link protocol version with relay")
                    self.link_version = common[-1]
                    self.circ_id_width = 4 if self.link_version >= 4 else 2
                continue

            if cell.command == Commands.NETINFO:
                saw_netinfo = True
                break

            if cell.command == Commands.CERTS:
                certs_payload += cell.payload
                continue

            if cell.command == Commands.DESTROY:
                raise TorConnectionError("Relay sent DESTROY during handshake")

        if self.link_version == 0:
            raise TorProtocolError("Relay did not send VERSIONS")
        if not saw_netinfo:
            raise TorProtocolError("Relay did not send NETINFO")

        if expected_ed25519_id is not None:
            if not certs_payload:
                raise TorProtocolError("Relay did not present link certificates")
            if not verify_link_certs(certs_payload, expected_ed25519_id):
                raise TorProtocolError(
                    "Relay link certificate is not signed by the expected identity"
                )

        self.send_cell(
            Cell.fixed(
                0,
                Commands.NETINFO,
                struct.pack(">I", int(time.time()) & 0xFFFFFFFF)
                + b"\x04\x04"
                + b"\x00\x00\x00\x00"
                + b"\x00",
            )
        )

    @staticmethod
    def _parse_versions(payload: bytes) -> list[int]:
        if len(payload) % 2:
            raise TorProtocolError("Malformed VERSIONS cell (odd length)")
        return [
            struct.unpack(">H", payload[index : index + 2])[0]
            for index in range(0, len(payload), 2)
        ]

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
