"""High-level Tor client: bootstrap, circuits, clearnet and onion requests."""

from __future__ import annotations

import hashlib
import json
import os
import random
import secrets
import struct
import time
from urllib.parse import urljoin, urlsplit

from .cells import Commands
from .circuit import Circuit
from .directory import (
    DirectoryFetcher,
    RelayInfo,
    parse_http_response,
)
from .errors import (
    TorDirectoryError,
    TorError,
    TorOnionError,
    TorStreamError,
)
from .link import LinkSession
from .onion import OnionV3, encode_lspecs
from .transport import CircuitStream, TLSStream


class GuardSet:
    """Small persisted entry-guard sample (guard-spec.txt)."""

    def __init__(self, file: str | None) -> None:
        self.file = file
        self.fingerprints: list[str] = self._load()

    def _load(self) -> list[str]:
        if not self.file:
            return []
        try:
            with open(self.file, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return []
        if data.get("version") != 1 or not isinstance(data.get("guards"), list):
            return []
        return [value.upper() for value in data["guards"] if isinstance(value, str)][-8:]

    def _save(self) -> None:
        if not self.file:
            return
        try:
            directory = os.path.dirname(os.path.abspath(self.file))
            os.makedirs(directory, exist_ok=True)
            temp = self.file + ".tmp"
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump({"version": 1, "guards": self.fingerprints}, handle)
            os.chmod(temp, 0o600)
            os.replace(temp, self.file)
        except OSError:
            pass

    def select(self, candidates: list[RelayInfo], exclude: list[str] | None = None) -> RelayInfo | None:
        exclude = exclude or []
        eligible = {
            relay.fingerprint: relay
            for relay in candidates
            if relay.fingerprint not in exclude and relay.is_selectable()
        }
        if not eligible:
            return None
        for fingerprint in self.fingerprints:
            if fingerprint in eligible:
                return eligible[fingerprint]
        chosen = secrets.choice(list(eligible.values()))
        self.remember(chosen.fingerprint)
        return chosen

    def remember(self, fingerprint: str) -> None:
        fingerprint = fingerprint.upper()
        if fingerprint in self.fingerprints:
            return
        self.fingerprints.append(fingerprint)
        self.fingerprints = self.fingerprints[-8:]
        self._save()

    def rotate(self, candidates: list[RelayInfo]) -> RelayInfo | None:
        eligible = {
            relay.fingerprint: relay for relay in candidates if relay.is_selectable()
        }
        if not eligible:
            return None
        fresh = [
            relay
            for fingerprint, relay in eligible.items()
            if fingerprint not in self.fingerprints
        ]
        if not fresh:
            current = self.fingerprints[0] if self.fingerprints else None
            fresh = [relay for fingerprint, relay in eligible.items() if fingerprint != current]
        if not fresh:
            return None
        chosen = secrets.choice(fresh)
        self.fingerprints = [chosen.fingerprint]
        self._save()
        return chosen

    def reject(self, fingerprint: str) -> None:
        fingerprint = fingerprint.upper()
        if fingerprint in self.fingerprints:
            self.fingerprints.remove(fingerprint)
            self._save()


def _default_cache_file() -> str:
    return os.path.expanduser(
        os.environ.get("TORV3_CACHE", "~/.cache/torv3/consensus.json")
    )


class TorClient:
    """A native Tor client with no tor process, SOCKS, or HTTP proxy."""

    def __init__(self, cache_file: str | None, guard_file: str | None = None) -> None:
        self.directory = DirectoryFetcher(cache_file)
        if guard_file is None and cache_file:
            guard_file = os.path.join(os.path.dirname(os.path.abspath(cache_file)), "guards.json")
        self.guards = GuardSet(guard_file)
        self.relays: dict[str, RelayInfo] = {}
        self.params: dict[str, str] = {}
        self.shared_random: bytes | None = None
        self.previous_shared_random: bytes | None = None
        self.period_length = 1440
        self.valid_after: int | None = None
        self.path_length = 3
        self.descriptor_revisions: dict[bytes, int] = {}
        self._hsdir_identities_loaded = False

    @classmethod
    def create(cls, cache_file: str | None = None, guard_file: str | None = None) -> "TorClient":
        return cls(cache_file if cache_file is not None else _default_cache_file(), guard_file)

    def bootstrap(self, force: bool = False, ttl: int = 3600) -> "TorClient":
        data = self.directory.relays(force=force, ttl=ttl)
        self.relays = data["relays"]
        self.params = data["params"]
        self.shared_random = data.get("shared_random")
        self.previous_shared_random = data.get("shared_random_previous")
        self.valid_after = data.get("valid_after") or None
        self.period_length = max(60, int(self.params.get("hsdir-interval", 1440)))
        if not self.relays:
            raise TorDirectoryError("Consensus produced no usable relays")
        return self

    # -- path selection -----------------------------------------------------

    def pick_path(
        self,
        hops: int,
        flags: list[str] | tuple[str, ...] = (),
        exclude: list[str] | tuple[str, ...] = (),
    ) -> list[RelayInfo]:
        excluded = set(exclude)
        candidates = [
            relay
            for relay in self.relays.values()
            if relay.is_selectable()
            and relay.fingerprint not in excluded
            and all(relay.has_flag(flag) for flag in flags)
        ]
        if len(candidates) < hops:
            raise TorDirectoryError(
                f"Not enough usable relays with flags [{','.join(flags)}] "
                f"({len(candidates)} available, {hops} needed)"
            )
        return secrets.SystemRandom().sample(candidates, hops)

    def _select_guard(self, exclude: list[str] | None = None) -> RelayInfo:
        exclude = exclude or []
        candidates = [
            relay
            for relay in self.relays.values()
            if relay.has_flag("Guard") and relay.is_selectable() and relay.fingerprint not in exclude
        ]
        guard = self.guards.select(candidates, exclude)
        if guard is None:
            guard = self.pick_path(1, ("Guard", "Fast", "Running"), exclude)[0]
        return guard

    def _path_to(self, target: RelayInfo, exclude: list[str] | None = None) -> list[RelayInfo]:
        exclude = list(exclude or [])
        guard = self._select_guard(exclude + [target.fingerprint])
        middles = (
            []
            if self.path_length <= 2
            else self.pick_path(
                self.path_length - 2,
                ("Fast", "Running"),
                exclude + [guard.fingerprint, target.fingerprint],
            )
        )
        return [guard, *middles, target]

    # -- circuits -----------------------------------------------------------

    def build_circuit(self, hops: list[RelayInfo]) -> Circuit:
        if not hops:
            raise TorError("A circuit needs at least one hop")
        missing = [hop for hop in hops if hop.ntor_onion_key is None]
        if missing:
            self.directory.fetch_microdescriptors(missing)
        for hop in hops:
            if not hop.can_extend() or hop.ed25519_id is None:
                raise TorDirectoryError(
                    f"Missing ntor key or ed25519 identity for {hop.nickname} ({hop.fingerprint})"
                )

        first = hops[0]
        if first.ed25519_id is None:
            raise TorDirectoryError(f"No ed25519 identity for {first.nickname}")

        try:
            link = LinkSession.connect(first.address, first.or_port, timeout=15.0)
            link.negotiate(first.ed25519_id, timeout=30.0)
        except TorError:
            self.guards.reject(first.fingerprint)
            raise

        circuit = Circuit.create(link, first, timeout=20.0)
        try:
            for hop in hops[1:]:
                circuit.extend(hop, timeout=20.0)
        except TorError:
            circuit.close()
            raise
        return circuit

    def _build_circuit_to(self, target: RelayInfo, exclude: list[str] | None = None, attempts: int = 3) -> Circuit:
        last: TorError | None = None
        for _ in range(attempts):
            try:
                return self.build_circuit(self._path_to(target, exclude))
            except TorError as exc:
                last = exc
        raise TorError(
            f"Could not build a circuit to {target.nickname}: {last or 'unknown error'}"
        )

    # -- requests -----------------------------------------------------------

    def request(
        self,
        url: str,
        follow_redirects: bool = False,
        *,
        allow_clearnet: bool = False,
        timeout: float = 45.0,
        max_bytes: int = 8 * 1024 * 1024,
        max_redirects: int = 5,
        client_auth_key: str | bytes | None = None,
    ) -> dict:
        """Fetch *url* through Tor.

        Returns ``{"status", "headers", "body", "url"}``.  Redirects are
        returned as-is unless *follow_redirects* is true; the final URL is
        always reported.  Clearnet targets require ``allow_clearnet=True``.
        """
        seen = {url}
        current = url

        for hop in range(max_redirects + 1):
            response = self._request_once(
                current,
                allow_clearnet=allow_clearnet,
                timeout=timeout,
                max_bytes=max_bytes,
                client_auth_key=client_auth_key,
            )
            if not follow_redirects or response["status"] not in (301, 302, 303, 307, 308):
                return response

            location = (response["headers"].get("location") or [None])[0]
            if not location:
                return response
            if hop >= max_redirects:
                raise TorError(f"Too many redirects (limit {max_redirects})")

            nxt = urljoin(current, location)
            if nxt in seen:
                raise TorError(f"Redirect loop detected at {nxt}")
            seen.add(nxt)
            current = nxt

        return response

    def _request_once(
        self,
        url: str,
        *,
        allow_clearnet: bool,
        timeout: float,
        max_bytes: int,
        client_auth_key: str | bytes | None,
    ) -> dict:
        parts = urlsplit(url)
        if not parts.hostname:
            raise TorError(f"Invalid URL: {url}")
        scheme = parts.scheme.lower()
        host = parts.hostname.lower()
        if scheme not in ("http", "https"):
            raise TorError(f"Unsupported URL scheme: {scheme}://{host}")
        port = parts.port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in host) or "/" in host:
            raise TorError("Invalid characters in URL host")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
            raise TorError("Invalid control characters in URL path")

        if host.endswith(".onion"):
            return self._request_onion(
                host,
                port,
                path,
                timeout=timeout,
                tls=scheme == "https",
                client_auth_key=client_auth_key,
                max_bytes=max_bytes,
            )

        if not allow_clearnet:
            raise TorError(f"Clearnet access is disabled: {host}")
        return self._request_clearnet(
            host, port, path, timeout=timeout, tls=scheme == "https", max_bytes=max_bytes
        )

    def _request_clearnet(
        self,
        host: str,
        port: int,
        path: str,
        *,
        timeout: float,
        tls: bool,
        max_bytes: int,
    ) -> dict:
        if not self.relays:
            self.bootstrap()
        exit_relay = self.pick_path(1, ("Exit", "Fast", "Running"))[0]
        circuit = self._build_circuit_to(exit_relay)
        try:
            stream_id = circuit.begin_stream(host, port, timeout=timeout)
            response = self._http_exchange(
                circuit, stream_id, host, port, path, timeout, max_bytes, tls
            )
            default_port = 443 if tls else 80
            response["url"] = (
                f"{'https' if tls else 'http'}://{host}"
                + ("" if port == default_port else f":{port}")
                + path
            )
            return response
        finally:
            circuit.close()

    def _request_onion(
        self,
        host: str,
        port: int,
        path: str,
        *,
        timeout: float,
        tls: bool,
        client_auth_key: str | bytes | None,
        max_bytes: int,
    ) -> dict:
        if not self.relays:
            self.bootstrap()

        onion = OnionV3(host, self.valid_after, self.period_length)
        if client_auth_key is not None:
            onion.set_client_auth_key(client_auth_key)

        descriptor = self._fetch_onion_descriptor(onion, timeout)
        parsed = onion.decrypt_descriptor(descriptor)

        revision = int(parsed["revision"])
        accepted = self.descriptor_revisions.get(onion.blinded)
        if accepted is not None and revision < accepted:
            raise TorOnionError(
                f"Descriptor revision {revision} for {host} is older than accepted revision {accepted}"
            )
        self.descriptor_revisions[onion.blinded] = revision

        intro_points = parsed["introduction_points"]
        if not intro_points:
            raise TorOnionError(f"Descriptor for {host} lists no usable introduction points")

        rendezvous = self.pick_path(1, ("Fast", "Running"))[0]
        rendezvous_circuit = self._build_circuit_to(rendezvous)
        intro_circuit: Circuit | None = None

        try:
            cookie = secrets.token_bytes(20)
            rendezvous_circuit.send_relay(
                Commands.RELAY_ESTABLISH_RENDEZVOUS,
                0,
                cookie,
                rendezvous_circuit.hop_count() - 1,
            )
            rendezvous_circuit.wait_for_relay(
                Commands.RELAY_RENDEZVOUS_ESTABLISHED, timeout
            )

            specs = link_specifiers_for(rendezvous)
            ordered = list(intro_points)
            secrets.SystemRandom().shuffle(ordered)
            introduce: dict | None = None
            last_status: int | None = None

            for point in ordered[:3]:
                intro_relay = self.relay_from_link_specifiers(point["link_specifiers"])
                if intro_relay is None:
                    continue
                if intro_circuit is not None:
                    intro_circuit.close()
                intro_circuit = self._build_circuit_to(
                    intro_relay, [rendezvous.fingerprint]
                )
                candidate = onion.build_introduce1(
                    point,
                    rendezvous.ntor_onion_key,
                    specs,
                    cookie,
                )
                intro_circuit.send_relay(
                    Commands.RELAY_INTRODUCE1,
                    0,
                    candidate["body"],
                    intro_circuit.hop_count() - 1,
                    early=True,
                )
                ack = intro_circuit.wait_for_relay(Commands.RELAY_INTRODUCE_ACK, timeout)
                last_status = struct.unpack(">H", ack[2][:2])[0] if len(ack[2]) >= 2 else -1
                if last_status == 0:
                    introduce = candidate
                    break

            if introduce is None:
                raise TorOnionError(
                    f"Every introduction point rejected the request (last status {last_status})"
                )

            rendezvous2 = rendezvous_circuit.wait_for_relay(
                Commands.RELAY_RENDEZVOUS2, max(timeout, 60.0)
            )
            keys = onion.process_rend2(introduce, rendezvous2[2])
            rendezvous_circuit.add_rendezvous_layer(
                keys["df"], keys["db"], keys["kf"], keys["kb"]
            )

            stream_id = rendezvous_circuit.begin_stream(
                onion.hostname(), port, timeout=timeout
            )
            response = self._http_exchange(
                rendezvous_circuit,
                stream_id,
                host,
                port,
                path,
                timeout,
                max_bytes,
                tls,
            )
            default_port = 443 if tls else 80
            response["url"] = (
                f"{'https' if tls else 'http'}://{host}"
                + ("" if port == default_port else f":{port}")
                + path
            )
            return response
        finally:
            if intro_circuit is not None:
                intro_circuit.close()
            rendezvous_circuit.close()

    def _fetch_onion_descriptor(self, onion: OnionV3, timeout: float) -> bytes:
        errors: list[str] = []
        replicas = max(1, int(self.params.get("hsdir_n_replicas", 2)))
        spread = max(1, int(self.params.get("hsdir_spread_fetch", 3)))
        attempts = 0

        for replica in range(1, replicas + 1):
            hsdirs = self.responsible_hsdirs(onion, replica)
            if not hsdirs:
                errors.append(f"no responsible HSDir for replica {replica}")
                continue

            for hsdir in hsdirs[: spread + 1]:
                if attempts >= 6:
                    break
                attempts += 1
                circuit = None
                try:
                    circuit = self._build_circuit_to(hsdir)
                    return onion.fetch_descriptor(circuit, timeout)
                except TorError as exc:
                    errors.append(f"{hsdir.nickname} replica {replica}: {exc}")
                finally:
                    if circuit is not None:
                        circuit.close()

        raise TorOnionError(
            f"Could not download the descriptor for {onion.hostname()}: {'; '.join(errors)}"
        )

    # -- HSDir selection ----------------------------------------------------

    @staticmethod
    def _disaster_shared_random(period_num: int, period_length: int) -> bytes:
        return hashlib.sha3_256(
            b"shared-random-disaster"
            + struct.pack(">Q", period_length)
            + struct.pack(">Q", period_num)
        ).digest()

    @staticmethod
    def _hsdir_index(ed25519_id: bytes, shared_random: bytes, period_num: int, period_length: int) -> bytes:
        return hashlib.sha3_256(
            b"node-idx"
            + ed25519_id
            + shared_random
            + struct.pack(">Q", period_num)
            + struct.pack(">Q", period_length)
        ).digest()

    @staticmethod
    def _select_shared_random(
        valid_after: int, period_length: int, current: bytes, previous: bytes | None
    ) -> bytes:
        if previous is None or period_length <= 0:
            return current
        minutes = valid_after // 60
        run_start = (minutes // period_length) * period_length
        return previous if (minutes - run_start) < period_length // 2 else current

    def responsible_hsdirs(self, onion: OnionV3, replica: int) -> list[RelayInfo]:
        if self.shared_random is None:
            shared_random = self._disaster_shared_random(
                onion.period_num, onion.period_length
            )
        else:
            shared_random = self._select_shared_random(
                self.valid_after or int(time.time()),
                self.period_length,
                self.shared_random,
                self.previous_shared_random,
            )

        hsdir_relays = [
            relay
            for relay in self.relays.values()
            if relay.has_flag("HSDir") and relay.or_port > 0
        ]
        if not self._hsdir_identities_loaded and any(
            relay.ed25519_id is None for relay in hsdir_relays
        ):
            self.directory.fetch_microdescriptors(hsdir_relays)
            self._hsdir_identities_loaded = True

        nodes = []
        for relay in hsdir_relays:
            if relay.ed25519_id is None:
                continue
            index = self._hsdir_index(
                relay.ed25519_id,
                shared_random,
                onion.period_num,
                onion.period_length,
            )
            nodes.append((index, relay))

        if not nodes:
            return []
        nodes.sort(key=lambda item: item[0])

        key = onion.hs_index(replica)
        start = 0
        for position, (index, _) in enumerate(nodes):
            if index >= key:
                start = position
                break

        spread = max(1, int(self.params.get("hsdir_spread_fetch", 3)))
        return [
            nodes[(start + offset) % len(nodes)][1]
            for offset in range(min(spread, len(nodes)))
        ]

    # -- link-specifier mapping --------------------------------------------

    def relay_from_link_specifiers(self, specs: list[dict]) -> RelayInfo | None:
        for spec in specs:
            if spec["type"] == 0x02 and len(spec["data"]) == 20:
                relay = self.relays.get(spec["data"].hex().upper())
                if relay is not None:
                    return relay
        for spec in specs:
            if spec["type"] == 0x03 and len(spec["data"]) == 32:
                for relay in self.relays.values():
                    if relay.ed25519_id == spec["data"]:
                        return relay
        return None

    # -- HTTP ---------------------------------------------------------------

    def _http_exchange(
        self,
        circuit: Circuit,
        stream_id: int,
        host: str,
        port: int,
        path: str,
        timeout: float,
        max_bytes: int,
        tls: bool,
    ) -> dict:
        default_port = 443 if tls else 80
        authority = host + ("" if port == default_port else f":{port}")
        request = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {authority}\r\n"
            "User-Agent: torv3-python/1.0\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode()

        stream = CircuitStream(circuit, stream_id)
        tls_stream: TLSStream | None = None
        if tls:
            tls_stream = TLSStream(stream, host, verify=not host.endswith(".onion"), timeout=timeout)
            tls_stream.write(request)
        else:
            circuit.send_data(stream_id, request)

        deadline = time.monotonic() + timeout
        raw = bytearray()
        headers_parsed = False
        content_length: int | None = None
        chunked = False

        while time.monotonic() < deadline:
            remaining = max(0.5, deadline - time.monotonic())
            try:
                if tls_stream is not None:
                    chunk = tls_stream.read(remaining)
                else:
                    chunk = circuit.read_stream_data(stream_id, remaining)
            except TorStreamError:
                break
            if not chunk:
                continue

            raw += chunk
            if len(raw) > max_bytes:
                raise TorError(f"Proxied response exceeds the {max_bytes}-byte limit")

            if not headers_parsed and b"\r\n\r\n" in raw:
                headers_parsed = True
                response = parse_http_response(bytes(raw))
                length_header = (response["headers"].get("content-length") or [None])[0]
                content_length = int(length_header) if length_header is not None else None
                encoding = (response["headers"].get("transfer-encoding") or [""])[0]
                chunked = "chunked" in encoding.lower()

            if headers_parsed and content_length is not None:
                if len(parse_http_response(bytes(raw))["body"]) >= content_length:
                    break
            elif headers_parsed and chunked and raw.endswith(b"0\r\n\r\n"):
                break

        if tls_stream is not None:
            tls_stream.close()
        circuit.close_stream(stream_id)

        return parse_http_response(bytes(raw))


def link_specifiers_for(relay: RelayInfo) -> list[dict]:
    specs: list[dict] = []
    try:
        import ipaddress

        address = ipaddress.ip_address(relay.address)
        if address.version == 4:
            specs.append(
                {"type": 0x00, "data": address.packed + struct.pack(">H", relay.or_port)}
            )
    except ValueError:
        pass
    specs.append({"type": 0x02, "data": relay.identity_digest})
    if relay.ed25519_id is not None:
        specs.append({"type": 0x03, "data": relay.ed25519_id})
    return specs


def fetch(
    url: str,
    follow_redirects: bool = False,
    *,
    allow_clearnet: bool = False,
    cache_file: str | None = None,
    timeout: float = 45.0,
    max_bytes: int = 8 * 1024 * 1024,
    max_redirects: int = 5,
    client_auth_key: str | bytes | None = None,
) -> dict:
    """Convenience wrapper: build a client and fetch one URL."""
    client = TorClient.create(cache_file)
    return client.request(
        url,
        follow_redirects,
        allow_clearnet=allow_clearnet,
        timeout=timeout,
        max_bytes=max_bytes,
        max_redirects=max_redirects,
        client_auth_key=client_auth_key,
    )
