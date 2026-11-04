"""Tor link-protocol cells and relay-cell payloads (tor-spec §3, §6)."""

from __future__ import annotations

import struct

from .errors import TorConnectionError, TorProtocolError


class Commands:
    PADDING = 0
    CREATE = 1
    CREATED = 2
    RELAY = 3
    DESTROY = 4
    CREATE_FAST = 5
    CREATED_FAST = 6
    VERSIONS = 7
    NETINFO = 8
    RELAY_EARLY = 9
    CREATE2 = 10
    CREATED2 = 11

    VPADDING = 128
    CERTS = 129
    AUTH_CHALLENGE = 130
    AUTHENTICATE = 131
    AUTHORIZE = 132

    RELAY_BEGIN = 1
    RELAY_DATA = 2
    RELAY_END = 3
    RELAY_CONNECTED = 4
    RELAY_SENDME = 5
    RELAY_EXTEND = 6
    RELAY_EXTENDED = 7
    RELAY_TRUNCATE = 8
    RELAY_TRUNCATED = 9
    RELAY_DROP = 10
    RELAY_RESOLVE = 11
    RELAY_RESOLVED = 12
    RELAY_BEGIN_DIR = 13
    RELAY_EXTEND2 = 14
    RELAY_EXTENDED2 = 15

    RELAY_ESTABLISH_INTRO = 32
    RELAY_ESTABLISH_RENDEZVOUS = 33
    RELAY_INTRODUCE1 = 34
    RELAY_INTRODUCE2 = 35
    RELAY_RENDEZVOUS1 = 36
    RELAY_RENDEZVOUS2 = 37
    RELAY_INTRO_ESTABLISHED = 38
    RELAY_RENDEZVOUS_ESTABLISHED = 39
    RELAY_INTRODUCE_ACK = 40

    NTOR_HTYPE = 0x0002
    LINK_VERSIONS = (3, 4)
    PAYLOAD_LEN = 509
    CIRCWINDOW_START = 1000
    CIRCWINDOW_INCREMENT = 100
    STREAMWINDOW_START = 500
    STREAMWINDOW_INCREMENT = 50
    MAX_RELAY_EARLY = 8

    @staticmethod
    def is_variable_length(command: int) -> bool:
        return command in (
            Commands.VERSIONS,
            Commands.VPADDING,
            Commands.CERTS,
            Commands.AUTH_CHALLENGE,
            Commands.AUTHENTICATE,
            Commands.AUTHORIZE,
        )


class Cell:
    """One link-protocol cell."""

    def __init__(self, circuit_id: int, command: int, payload: bytes, variable: bool = False) -> None:
        self.circuit_id = circuit_id
        self.command = command
        self.payload = payload
        self.variable = variable

    @classmethod
    def fixed(cls, circuit_id: int, command: int, payload: bytes) -> "Cell":
        if len(payload) > Commands.PAYLOAD_LEN:
            raise TorProtocolError(f"Fixed cell payload too long: {len(payload)}")
        return cls(circuit_id, command, payload.ljust(Commands.PAYLOAD_LEN, b"\x00"), False)

    @classmethod
    def variable(cls, circuit_id: int, command: int, body: bytes) -> "Cell":
        return cls(circuit_id, command, body, True)

    def encode(self, circ_id_width: int = 4) -> bytes:
        if circ_id_width == 2:
            if self.circuit_id > 0xFFFF:
                raise TorProtocolError("Circuit ID does not fit in 2 bytes")
            header = struct.pack(">H", self.circuit_id) + bytes([self.command])
        else:
            header = struct.pack(">I", self.circuit_id) + bytes([self.command])

        if self.variable:
            return header + struct.pack(">H", len(self.payload)) + self.payload
        return header + self.payload

    @classmethod
    def read(cls, stream, circ_id_width: int = 4) -> "Cell":
        """Read one cell from a LinkSession-like object with ``recv_exact``."""
        header = stream.recv_exact(circ_id_width + 1)
        if circ_id_width == 2:
            circuit_id = struct.unpack(">H", header[:2])[0]
            command = header[2]
        else:
            circuit_id = struct.unpack(">I", header[:4])[0]
            command = header[4]

        if not Commands.is_variable_length(command):
            return cls(circuit_id, command, stream.recv_exact(Commands.PAYLOAD_LEN), False)

        length = struct.unpack(">H", stream.recv_exact(2))[0]
        body = stream.recv_exact(length) if length else b""
        return cls(circuit_id, command, body, True)


class RelayCell:
    """509-byte relay-cell payload helpers."""

    HEADER_LEN = 11
    DIGEST_OFFSET = 5
    DIGEST_LEN = 4
    MAX_DATA = Commands.PAYLOAD_LEN - HEADER_LEN  # 498

    @staticmethod
    def build(command: int, stream_id: int, data: bytes) -> bytes:
        if len(data) > RelayCell.MAX_DATA:
            raise TorProtocolError(f"Relay cell data too long: {len(data)} > {RelayCell.MAX_DATA}")
        header = (
            bytes([command & 0xFF])
            + struct.pack(">H", 0)
            + struct.pack(">H", stream_id & 0xFFFF)
            + b"\x00" * RelayCell.DIGEST_LEN
            + struct.pack(">H", len(data))
        )
        return (header + data).ljust(Commands.PAYLOAD_LEN, b"\x00")

    @staticmethod
    def command(payload: bytes) -> int:
        return payload[0]

    @staticmethod
    def recognized(payload: bytes) -> int:
        return struct.unpack(">H", payload[1:3])[0]

    @staticmethod
    def stream_id(payload: bytes) -> int:
        return struct.unpack(">H", payload[3:5])[0]

    @staticmethod
    def digest(payload: bytes) -> bytes:
        return payload[RelayCell.DIGEST_OFFSET : RelayCell.DIGEST_OFFSET + RelayCell.DIGEST_LEN]

    @staticmethod
    def length(payload: bytes) -> int:
        return struct.unpack(">H", payload[9:11])[0]

    @staticmethod
    def data(payload: bytes) -> bytes:
        length = RelayCell.length(payload)
        if length > RelayCell.MAX_DATA:
            raise TorProtocolError(f"Relay cell claims invalid length {length}")
        return payload[RelayCell.HEADER_LEN : RelayCell.HEADER_LEN + length]

    @staticmethod
    def zero_digest(payload: bytes) -> bytes:
        return (
            payload[: RelayCell.DIGEST_OFFSET]
            + b"\x00" * RelayCell.DIGEST_LEN
            + payload[RelayCell.DIGEST_OFFSET + RelayCell.DIGEST_LEN :]
        )

    @staticmethod
    def insert_digest(payload: bytes, digest: bytes) -> bytes:
        if len(digest) != RelayCell.DIGEST_LEN:
            raise TorProtocolError("Relay digest must be 4 bytes")
        return (
            payload[: RelayCell.DIGEST_OFFSET]
            + digest
            + payload[RelayCell.DIGEST_OFFSET + RelayCell.DIGEST_LEN :]
        )


def recv_exact_socket(sock, n: int) -> bytes:
    """Read exactly *n* bytes from a socket; raise on close."""
    chunks: list[bytes] = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise TorConnectionError("Connection closed while reading cell data")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
