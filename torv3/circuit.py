"""Origin circuits: CREATE2/EXTEND2, relay cells, streams, flow control."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time

from .cells import Cell, Commands, RelayCell
from .crypto import (
    AESCTR,
    ntor_client_keys,
    ntor_onion_skin,
    x25519_generate,
)
from .directory import RelayInfo
from .errors import TorError, TorProtocolError, TorStreamError
from .link import LinkSession


class CircuitLayer:
    """One hop's AES-CTR and rolling-digest state."""

    SENDME_TAG_LEN = 20

    def __init__(
        self,
        df: bytes,
        db: bytes,
        kf: bytes,
        kb: bytes,
        digest_algorithm: str = "sha1",
    ) -> None:
        if len(kf) not in (16, 32) or len(kf) != len(kb):
            raise TorProtocolError("Relay keys must both be 16 or both 32 bytes")
        if not df or not db:
            raise TorProtocolError("Relay digest seeds must not be empty")

        self.algorithm = digest_algorithm
        self.forward_cipher = AESCTR(kf)
        self.backward_cipher = AESCTR(kb)
        self.forward_digest = hashlib.new(digest_algorithm)
        self.forward_digest.update(df)
        self.backward_digest = hashlib.new(digest_algorithm)
        self.backward_digest.update(db)
        self.last_forward_digest = b""
        self.last_backward_digest = b""

    def set_digest(self, payload: bytes) -> bytes:
        zeroed = RelayCell.zero_digest(payload)
        context = self.forward_digest.copy()
        context.update(zeroed)
        digest = context.digest()[: RelayCell.DIGEST_LEN]
        self.forward_digest.update(zeroed)
        self.last_forward_digest = self.forward_digest.copy().digest()
        return RelayCell.insert_digest(payload, digest)

    def encrypt(self, payload: bytes) -> bytes:
        return self.forward_cipher.encrypt(payload)

    def decrypt(self, payload: bytes) -> bytes:
        return self.backward_cipher.decrypt(payload)

    def verify_digest(self, payload: bytes) -> bool:
        received = RelayCell.digest(payload)
        zeroed = RelayCell.zero_digest(payload)
        context = self.backward_digest.copy()
        context.update(zeroed)
        calculated = context.digest()[: RelayCell.DIGEST_LEN]
        self.backward_digest.update(zeroed)
        self.last_backward_digest = self.backward_digest.copy().digest()
        return hmac.compare_digest(calculated, received)

    def inbound_sendme_tag(self) -> bytes:
        return self.last_backward_digest[: self.SENDME_TAG_LEN]

    def outbound_sendme_tag(self) -> bytes:
        return self.last_forward_digest[: self.SENDME_TAG_LEN]


class Circuit:
    def __init__(self, link: LinkSession, circuit_id: int) -> None:
        self.link = link
        self.circuit_id = circuit_id
        self.layers: list[CircuitLayer] = []
        self.hops: list[RelayInfo] = []
        self.relay_early_count = 0
        self.next_stream_id = 1
        self.connected: set[int] = set()
        self.pending_events: dict[int, list[tuple[int, bytes]]] = {}
        self.package_window: dict[int, int] = {}
        self.deliver_window: dict[int, int] = {}
        self.received_data: dict[int, int] = {}
        self.stream_received_data: dict[int, int] = {}
        self.stream_sendme_tag: dict[int, bytes] = {}
        self.sent_data_digests: dict[int, list[bytes]] = {}
        self.stream_package_window: dict[int, int] = {}
        self.sent_stream_digests: dict[int, list[bytes]] = {}
        self.closed = False

    @classmethod
    def create(
        cls,
        link: LinkSession,
        first_hop: RelayInfo,
        circuit_id: int | None = None,
        timeout: float = 20.0,
    ) -> "Circuit":
        if not first_hop.can_extend() or len(first_hop.identity_digest) != 20:
            raise TorProtocolError("First hop is missing an ntor onion key or identity digest")

        circuit = cls(link, circuit_id if circuit_id is not None else random_circuit_id())
        private, public = x25519_generate()
        skin = ntor_onion_skin(first_hop.identity_digest, first_hop.ntor_onion_key, public)
        payload = struct.pack(">HH", Commands.NTOR_HTYPE, len(skin)) + skin
        link.send_cell(Cell.fixed(circuit.circuit_id, Commands.CREATE2, payload))

        cell = circuit._read_circuit_cell(Commands.CREATED2, timeout)
        if len(cell.payload) < 66:
            raise TorProtocolError("Malformed CREATED2 payload")
        hlen = struct.unpack(">H", cell.payload[:2])[0]
        if hlen != 64:
            raise TorProtocolError("Malformed CREATED2 payload")

        server_public = cell.payload[2:34]
        auth = cell.payload[34:66]
        keys = ntor_client_keys(
            first_hop.identity_digest,
            first_hop.ntor_onion_key,
            private,
            public,
            server_public,
            auth,
        )
        circuit.layers.append(CircuitLayer(keys["df"], keys["db"], keys["kf"], keys["kb"]))
        circuit.hops.append(first_hop)
        circuit._init_windows()
        return circuit

    def extend(self, hop: RelayInfo, timeout: float = 20.0) -> None:
        if not hop.can_extend() or len(hop.identity_digest) != 20:
            raise TorProtocolError(f"Cannot extend to {hop.nickname}: missing ntor key")
        if self.relay_early_count >= Commands.MAX_RELAY_EARLY:
            raise TorProtocolError("RELAY_EARLY limit reached on this circuit")

        private, public = x25519_generate()
        handshake = ntor_onion_skin(hop.identity_digest, hop.ntor_onion_key, public)

        specs = b""
        try:
            import ipaddress

            address = ipaddress.ip_address(hop.address)
            if address.version == 4:
                specs += b"\x00\x06" + address.packed + struct.pack(">H", hop.or_port)
            else:
                specs += b"\x04\x12" + address.packed + struct.pack(">H", hop.or_port)
        except ValueError:
            pass
        specs += b"\x02\x14" + hop.identity_digest
        if hop.ed25519_id is not None:
            specs += b"\x03\x20" + hop.ed25519_id

        nspec = 3 if hop.ed25519_id is not None else 2
        payload = (
            bytes([nspec])
            + specs
            + struct.pack(">HH", Commands.NTOR_HTYPE, len(handshake))
            + handshake
        )

        self.send_relay(Commands.RELAY_EXTEND2, 0, payload, len(self.layers) - 1, early=True)
        reply = self.wait_for_relay(Commands.RELAY_EXTENDED2, timeout)
        data = reply[2]
        if len(data) < 66:
            raise TorProtocolError("Malformed RELAY_EXTENDED2 payload")
        hlen = struct.unpack(">H", data[:2])[0]
        if hlen != 64:
            raise TorProtocolError(f"Unexpected EXTENDED2 handshake: length={hlen}")

        server_public = data[2:34]
        auth = data[34:66]
        keys = ntor_client_keys(
            hop.identity_digest,
            hop.ntor_onion_key,
            private,
            public,
            server_public,
            auth,
        )
        self.layers.append(CircuitLayer(keys["df"], keys["db"], keys["kf"], keys["kb"]))
        self.hops.append(hop)
        self._init_windows()

    def add_rendezvous_layer(self, df: bytes, db: bytes, kf: bytes, kb: bytes) -> None:
        self.layers.append(CircuitLayer(df, db, kf, kb, "sha3_256"))
        self.hops.append(self.hops[-1])
        self._init_windows()

    def _init_windows(self) -> None:
        index = len(self.layers) - 1
        self.package_window[index] = Commands.CIRCWINDOW_START
        self.deliver_window[index] = Commands.CIRCWINDOW_START
        self.received_data[index] = 0

    def begin_stream(
        self, host: str, port: int, begin_dir: bool = False, timeout: float = 15.0
    ) -> int:
        stream_id = self.next_stream_id
        self.next_stream_id += 1

        if begin_dir:
            self.send_relay(Commands.RELAY_BEGIN_DIR, stream_id, b"", len(self.layers) - 1)
        else:
            self.send_relay(
                Commands.RELAY_BEGIN,
                stream_id,
                f"{host}:{port}".encode() + b"\x00",
                len(self.layers) - 1,
            )

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            event = self.next_stream_event(stream_id, deadline - time.monotonic())
            if event is None:
                break
            command, data = event
            if command == Commands.RELAY_CONNECTED:
                self.connected.add(stream_id)
                return stream_id
            if command == Commands.RELAY_END:
                raise TorStreamError(
                    f"Relay refused the stream to {host}:{port}",
                    data[0] if data else 0,
                )

        raise TorStreamError(f"Timed out waiting for RELAY_CONNECTED from {host}:{port}")

    def send_data(self, stream_id: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + RelayCell.MAX_DATA]
            offset += len(chunk)
            hop = len(self.layers) - 1

            self._wait_for_package_window(hop)
            self._wait_for_stream_window(stream_id)
            self.package_window[hop] -= 1
            self.stream_package_window[stream_id] = (
                self.stream_package_window.get(stream_id, Commands.STREAMWINDOW_START) - 1
            )

            self.send_relay(Commands.RELAY_DATA, stream_id, chunk, hop)
            tag = self.layers[hop].outbound_sendme_tag()
            self.sent_data_digests.setdefault(hop, []).append(tag)
            self.sent_stream_digests.setdefault(stream_id, []).append(tag)

    def _wait_for_package_window(self, hop: int) -> None:
        deadline = time.monotonic() + 30.0
        while self.package_window.get(hop, Commands.CIRCWINDOW_START) <= 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TorError(f"Timed out waiting for a circuit SENDME from hop {hop}")
            relay = self.receive_relay_cell(remaining)
            if relay is not None:
                self._dispatch(relay)

    def _wait_for_stream_window(self, stream_id: int) -> None:
        deadline = time.monotonic() + 30.0
        while self.stream_package_window.get(stream_id, Commands.STREAMWINDOW_START) <= 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TorError(f"Timed out waiting for a stream SENDME on stream {stream_id}")
            relay = self.receive_relay_cell(remaining)
            if relay is not None:
                self._dispatch(relay)

    def next_stream_event(
        self, stream_id: int, timeout: float = 15.0
    ) -> tuple[int, bytes] | None:
        deadline = time.monotonic() + timeout
        while True:
            queued = self.pending_events.get(stream_id)
            if queued:
                return queued.pop(0)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None

            relay = self.receive_relay_cell(remaining)
            if relay is None:
                return None
            self._dispatch(relay)

    def read_stream_data(self, stream_id: int, timeout: float = 15.0) -> bytes:
        data = self.read_stream_data_if_available(stream_id, timeout)
        if data is None:
            raise TorStreamError(f"Timed out reading stream {stream_id}")
        return data

    def read_stream_data_if_available(self, stream_id: int, timeout: float = 15.0) -> bytes | None:
        event = self.next_stream_event(stream_id, timeout)
        if event is None:
            return None
        command, data = event
        if command == Commands.RELAY_END:
            raise TorStreamError("Stream closed by the remote host", data[0] if data else 0)
        if command != Commands.RELAY_DATA:
            return b""
        return data

    def close_stream(self, stream_id: int) -> None:
        if stream_id in self.connected:
            try:
                self.send_relay(Commands.RELAY_END, stream_id, b"\x00", len(self.layers) - 1)
            except TorError:
                pass
        self.connected.discard(stream_id)
        for mapping in (
            self.pending_events,
            self.stream_package_window,
            self.sent_stream_digests,
            self.stream_received_data,
            self.stream_sendme_tag,
        ):
            mapping.pop(stream_id, None)

    def send_relay(
        self,
        command: int,
        stream_id: int,
        data: bytes,
        hop: int | None = None,
        early: bool = False,
    ) -> None:
        if self.closed:
            raise TorError("Circuit is closed")
        if hop is None:
            hop = len(self.layers) - 1
        if hop >= len(self.layers):
            raise TorProtocolError(f"No such hop {hop} on circuit")

        payload = RelayCell.build(command, stream_id, data)
        for index in range(hop, -1, -1):
            if index == hop:
                payload = self.layers[index].set_digest(payload)
            payload = self.layers[index].encrypt(payload)

        is_extend = command in (Commands.RELAY_EXTEND2, Commands.RELAY_EXTEND)
        cell_command = Commands.RELAY
        if (early or is_extend) and self.relay_early_count < Commands.MAX_RELAY_EARLY:
            self.relay_early_count += 1
            cell_command = Commands.RELAY_EARLY

        self.link.send_cell(Cell.fixed(self.circuit_id, cell_command, payload))

    def wait_for_relay(self, expected_command: int, timeout: float = 15.0) -> tuple[int, int, bytes, int]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            relay = self.receive_relay_cell(deadline - time.monotonic())
            if relay is None:
                break
            if relay[0] == expected_command:
                return relay
            self._dispatch(relay)
        raise TorError(f"Timed out waiting for relay command {expected_command}")

    def receive_relay_cell(self, timeout: float = 15.0) -> tuple[int, int, bytes, int] | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                cell = self.link.read_cell(max(0.1, deadline - time.monotonic()))
            except TimeoutError:
                return None
            except TorError:
                if time.monotonic() >= deadline:
                    return None
                raise

            if cell.circuit_id != self.circuit_id:
                continue
            if cell.command in (Commands.PADDING, Commands.VPADDING):
                continue
            if cell.command == Commands.DESTROY:
                self.closed = True
                reason = cell.payload[0] if cell.payload else 0
                raise TorError(f"Circuit destroyed by the network (reason {reason})")
            if cell.command not in (Commands.RELAY, Commands.RELAY_EARLY):
                continue

            relay = self._peel_relay_cell(cell.payload)
            if relay is None:
                continue

            command, stream_id, data, hop = relay
            if command == Commands.RELAY_SENDME:
                self._handle_sendme(relay)
                continue
            if command == Commands.RELAY_DATA:
                self._handle_inbound_data(relay)
            if command == Commands.RELAY_DROP:
                continue
            return relay

        return None

    def _peel_relay_cell(self, payload: bytes) -> tuple[int, int, bytes, int] | None:
        raw = payload
        for index, layer in enumerate(self.layers):
            raw = layer.decrypt(raw)
            if index >= len(self.hops):
                continue
            recognized = RelayCell.recognized(raw)
            matches = layer.verify_digest(raw)
            if recognized == 0 and matches:
                if RelayCell.length(raw) > RelayCell.MAX_DATA:
                    raise TorProtocolError("Relay cell announces an oversized payload")
                return (
                    RelayCell.command(raw),
                    RelayCell.stream_id(raw),
                    RelayCell.data(raw),
                    index,
                )
        return None

    def _handle_inbound_data(self, relay: tuple[int, int, bytes, int]) -> None:
        _, stream_id, data, hop = relay
        self.deliver_window[hop] = self.deliver_window.get(hop, 0) - 1
        self.received_data[hop] = self.received_data.get(hop, 0) + 1
        self.stream_received_data[stream_id] = self.stream_received_data.get(stream_id, 0) + 1
        self.stream_sendme_tag[stream_id] = self.layers[hop].inbound_sendme_tag()

        if self.stream_received_data[stream_id] % Commands.STREAMWINDOW_INCREMENT == 0:
            self.send_relay(
                Commands.RELAY_SENDME,
                stream_id,
                self.sendme_payload(self.stream_sendme_tag[stream_id]),
                hop,
            )

        if self.received_data[hop] % Commands.CIRCWINDOW_INCREMENT == 0:
            self.send_relay(
                Commands.RELAY_SENDME,
                0,
                self.sendme_payload(self.layers[hop].inbound_sendme_tag()),
                hop,
            )
            self.deliver_window[hop] += Commands.CIRCWINDOW_INCREMENT

        self.pending_events.setdefault(stream_id, []).append((Commands.RELAY_DATA, data))

    @staticmethod
    def sendme_payload(tag: bytes) -> bytes:
        if len(tag) != CircuitLayer.SENDME_TAG_LEN:
            raise TorProtocolError(f"SENDME tag must be {CircuitLayer.SENDME_TAG_LEN} bytes")
        return b"\x01" + struct.pack(">H", len(tag)) + tag

    def _handle_sendme(self, relay: tuple[int, int, bytes, int]) -> None:
        _, stream_id, data, hop = relay
        if len(data) < 3 or data[0] != 1:
            raise TorProtocolError(f"Malformed SENDME cell from hop {hop}")
        length = struct.unpack(">H", data[1:3])[0]
        if length != CircuitLayer.SENDME_TAG_LEN or len(data) < 3 + length:
            raise TorProtocolError(f"Unexpected SENDME tag length from hop {hop}")
        tag = data[3 : 3 + length]

        if stream_id != 0:
            queue = self.sent_stream_digests.get(stream_id, [])
            if queue:
                index = min(len(queue), Commands.STREAMWINDOW_INCREMENT) - 1
                if not hmac.compare_digest(queue[index], tag):
                    raise TorProtocolError(f"Stream SENDME tag mismatch on stream {stream_id}")
                del queue[: index + 1]
            self.stream_package_window[stream_id] = (
                self.stream_package_window.get(stream_id, Commands.STREAMWINDOW_START)
                + Commands.STREAMWINDOW_INCREMENT
            )
            return

        queue = self.sent_data_digests.get(hop, [])
        if not queue:
            raise TorProtocolError(f"Circuit SENDME from hop {hop} acknowledges no data")
        index = min(len(queue), Commands.CIRCWINDOW_INCREMENT) - 1
        if not hmac.compare_digest(queue[index], tag):
            raise TorProtocolError(f"SENDME tag mismatch from hop {hop}")
        del queue[: index + 1]
        self.package_window[hop] = (
            self.package_window.get(hop, Commands.CIRCWINDOW_START)
            + Commands.CIRCWINDOW_INCREMENT
        )

    def _dispatch(self, relay: tuple[int, int, bytes, int]) -> None:
        command, stream_id, data, _ = relay
        if command in (Commands.RELAY_DATA, Commands.RELAY_SENDME):
            return
        self.pending_events.setdefault(stream_id, []).append((command, data))

    def _read_circuit_cell(self, expected_command: int, timeout: float) -> Cell:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                cell = self.link.read_cell(max(0.1, deadline - time.monotonic()))
            except TimeoutError:
                break
            if cell.circuit_id != self.circuit_id:
                continue
            if cell.command == expected_command:
                return cell
            if cell.command == Commands.DESTROY:
                raise TorError("Relay destroyed the circuit during creation")
        raise TorError(f"Timed out waiting for cell command {expected_command}")

    def hop_count(self) -> int:
        return len(self.layers)

    def close(self, close_link: bool = True) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.link.send_cell(
                    Cell.fixed(self.circuit_id, Commands.DESTROY, b"\x00")
                )
            except TorError:
                pass
        if close_link:
            self.link.close()


def random_circuit_id() -> int:
    return 0x80000000 | secrets.randbits(31)
