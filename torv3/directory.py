"""Authenticated Tor directory data: consensus, authority certs, microdescriptors."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .certs import CERT_TYPE_ID_SIGNING, parse_ed25519_cert  # noqa: F401  (re-exported)
from .crypto import rsa_pkcs1_der, rsa_verify
from .errors import TorConnectionError, TorDirectoryError

AUTHORITIES: tuple[tuple[str, str, int], ...] = (
    ("tor26", "217.196.147.77", 80),
    ("dannenberg", "193.23.244.244", 80),
    ("gabelmoo", "131.188.40.189", 80),
    ("maatuska", "171.25.193.9", 443),
    ("dizum", "45.66.35.11", 80),
    ("longclaw", "199.58.81.140", 80),
    ("bastet", "204.13.164.118", 80),
    ("faravahar", "216.218.219.41", 80),
    ("moria1", "128.31.0.39", 9231),
)

AUTHORITY_FINGERPRINTS: dict[str, str] = {
    "moria1": "F533C81CEF0BC0267857C99B2F471ADF249FA232",
    "tor26": "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C",
    "dizum": "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
    "gabelmoo": "ED03BB616EB2F60BEC80151114BB25CEF515B226",
    "dannenberg": "0232AF901C31A04EE9848595AF9BB7620D4C5B2E",
    "maatuska": "49015F787433103580E3B66A1707A00E60F2D15B",
    "longclaw": "23D15D965BC35114467363C165C4F724B64B4F66",
    "bastet": "27102BC123E7AF1D4741AE047E160C91ADC76B21",
    "faravahar": "70849B868D606BAECFB6128C5E3D782029AA394F",
}

CONSENSUS_PATH = "/tor/status-vote/current/consensus-microdesc"
MICRODESC_PATH = "/tor/micro/d/"
AUTHORITY_KEYS_PATH = "/tor/keys/all"
MAX_RESPONSE_BYTES = 20 * 1024 * 1024
MAX_MICRODESC_BATCH = 90
CACHE_VERSION = 1
CACHE_MAGIC = b"TORV3CACHE\n"


def _b64(value: str) -> bytes:
    value = value.strip().translate(str.maketrans("-_", "+/"))
    value += "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise TorDirectoryError("Malformed base64 in directory data") from exc


def _b64_nopad(value: bytes) -> str:
    return base64.b64encode(value).decode().rstrip("=")


def parse_http_response(raw: bytes) -> dict:
    """Split an HTTP/1.x response into status, headers, and decoded body."""
    header_end = raw.find(b"\r\n\r\n")
    separator = 4
    if header_end < 0:
        header_end = raw.find(b"\n\n")
        separator = 2
    if header_end < 0:
        return {"status": 0, "headers": {}, "body": raw}

    head = raw[:header_end].decode("latin-1", "replace")
    body = raw[header_end + separator :]
    lines = re.split(r"\r?\n", head)

    status = 0
    if lines:
        match = re.match(r"HTTP/\d\.\d\s+(\d{3})", lines[0])
        if match:
            status = int(match.group(1))

    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())

    encoding = headers.get("transfer-encoding", [""])[0].lower()
    if "chunked" in encoding:
        body = decode_chunked(body)

    return {"status": status, "headers": headers, "body": body}


def decode_chunked(body: bytes) -> bytes:
    output = bytearray()
    offset = 0
    while offset < len(body):
        line_end = body.find(b"\r\n", offset)
        if line_end < 0:
            break
        size_line = body[offset:line_end].split(b";", 1)[0].strip()
        if not re.fullmatch(rb"[0-9a-fA-F]+", size_line):
            break
        size = int(size_line, 16)
        offset = line_end + 2
        if size == 0:
            break
        output += body[offset : offset + size]
        offset += size + 2
    return bytes(output)


def http_get(host: str, port: int, path: str, redirects: int = 3) -> bytes:
    """Plain-HTTP GET against a directory authority."""
    try:
        sock = socket.create_connection((host, port), timeout=8.0)
    except OSError as exc:
        raise TorConnectionError(f"Cannot connect to {host}:{port} ({exc})") from exc

    try:
        sock.settimeout(20.0)
        request = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            "User-Agent: torv3-python/1.0\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(request)

        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise TorDirectoryError("Directory response exceeded the size limit")
    finally:
        sock.close()

    raw = b"".join(chunks)
    if not raw:
        raise TorConnectionError(f"Empty response from {host}:{port}")

    response = parse_http_response(raw)
    status = response["status"]

    if 300 <= status < 400 and redirects > 0:
        location = (response["headers"].get("location") or [None])[0]
        if location:
            from urllib.parse import urljoin, urlparse

            target = urlparse(urljoin(f"http://{host}{path}", location))
            if target.scheme != "http" or not target.hostname:
                raise TorDirectoryError("Directory redirect is not an http URL")
            allowed = {entry[1] for entry in AUTHORITIES}
            if target.hostname != host and target.hostname not in allowed:
                raise TorDirectoryError("Directory redirect to an unpinned host")
            new_path = target.path or "/"
            if target.query:
                new_path += "?" + target.query
            if any(ord(c) < 0x20 or ord(c) == 0x7F for c in new_path):
                raise TorDirectoryError("Directory redirect contains control characters")
            return http_get(target.hostname, target.port or 80, new_path, redirects - 1)

    if status != 200:
        raise TorDirectoryError(f"Directory returned HTTP {status} for {path}")

    return response["body"]


# ---------------------------------------------------------------------------
# Authority key certificates
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class AuthorityCert:
    fingerprint: str
    identity_pem: str
    signing_pem: str
    signing_key_digest: str
    expires: int
    document: str = ""

    @classmethod
    def parse(cls, document: str, pinned: list[str]) -> "AuthorityCert":
        document = document.strip("\r\n")
        if not re.match(r"^dir-key-certificate-version 3\r?\n", document):
            raise TorDirectoryError("Not a version 3 authority key certificate")

        match = re.search(r"^fingerprint ([0-9A-Fa-f]{40})$", document, re.M)
        if not match:
            raise TorDirectoryError("Authority certificate has no fingerprint")
        declared = match.group(1).upper()
        if declared not in pinned:
            raise TorDirectoryError("Authority certificate is not from a pinned authority")

        identity_pem = _pem_field(document, "dir-identity-key")
        signing_pem = _pem_field(document, "dir-signing-key")
        if fingerprint_of(identity_pem) != declared:
            raise TorDirectoryError("Authority certificate fingerprint does not match its identity key")

        expiry = re.search(r"^dir-key-expires (.+)$", document, re.M)
        if not expiry:
            raise TorDirectoryError("Authority certificate has no expiry")
        try:
            expires = int(
                datetime.strptime(expiry.group(1).strip(), "%Y-%m-%d %H:%M:%S")
                .replace(tzinfo=UTC)
                .timestamp()
            )
        except ValueError as exc:
            raise TorDirectoryError("Malformed authority certificate expiry") from exc
        if expires < time.time():
            raise TorDirectoryError("Authority certificate has expired")

        cert_pos = document.find("\ndir-key-certification")
        if cert_pos < 0:
            raise TorDirectoryError("Authority certificate is unsigned")
        line_end = document.find("\n", cert_pos + 1)
        if line_end < 0:
            raise TorDirectoryError("Malformed authority certificate signature line")
        signed = document[: line_end + 1].encode()

        sig_match = re.search(
            r"dir-key-certification.*?-----BEGIN (?:ID )?SIGNATURE-----\s*(.*?)-----END (?:ID )?SIGNATURE-----",
            document,
            re.S,
        )
        if not sig_match:
            raise TorDirectoryError("Authority certificate signature is missing")
        signature = _b64(re.sub(r"\s+", "", sig_match.group(1)))
        if not signature:
            raise TorDirectoryError("Malformed authority certificate signature")
        if not rsa_verify(signed, signature, identity_pem, "sha1"):
            raise TorDirectoryError("Authority certificate self-signature is invalid")

        return cls(
            fingerprint=declared,
            identity_pem=identity_pem,
            signing_pem=signing_pem,
            signing_key_digest=fingerprint_of(signing_pem),
            expires=expires,
            document=document,
        )

    def verify_consensus_signature(self, signed: bytes, signature: bytes, algorithm: str) -> bool:
        return rsa_verify(signed, signature, self.signing_pem, algorithm)


def _pem_field(text: str, field_name: str) -> str:
    pattern = (
        rf"\n{re.escape(field_name)}\s*\r?\n"
        r"(-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----)"
    )
    match = re.search(pattern, text, re.S)
    if not match:
        raise TorDirectoryError(f"Authority certificate is missing {field_name}")
    return match.group(1)


def fingerprint_of(pem: str) -> str:
    return hashlib.sha1(rsa_pkcs1_der(pem)).hexdigest().upper()


# ---------------------------------------------------------------------------
# Relay information
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RelayInfo:
    nickname: str
    fingerprint: str
    identity_digest: bytes
    address: str
    or_port: int
    dir_port: int
    flags: list[str] = field(default_factory=list)
    ntor_onion_key: bytes | None = None
    ed25519_id: bytes | None = None
    bandwidth: int = 0
    microdesc_digest: str | None = None

    def has_flag(self, flag: str) -> bool:
        return flag in self.flags

    def is_selectable(self) -> bool:
        return self.or_port > 0 and len(self.identity_digest) == 20

    def is_usable(self) -> bool:
        return self.is_selectable() and self.ntor_onion_key is not None

    def can_extend(self) -> bool:
        return (
            self.is_selectable()
            and self.ntor_onion_key is not None
            and len(self.ntor_onion_key) == 32
        )

    def endpoint(self) -> str:
        return f"{self.address}:{self.or_port}"


# ---------------------------------------------------------------------------
# Consensus and microdescriptors
# ---------------------------------------------------------------------------


def verify_consensus(text: str, certs: dict[str, AuthorityCert]) -> bool:
    if not re.search(r"^network-status-version 3(?:[ \t]+microdesc)?\r?$", text, re.M):
        return False

    marker = "\ndirectory-signature "
    position = text.find(marker)
    if position < 0:
        return False
    signed = text[: position + len(marker)].encode()

    pattern = re.compile(
        r"directory-signature (?:([a-zA-Z0-9]+) )?([0-9A-Fa-f]{40}) ([0-9A-Fa-f]{40})\s*\r?\n"
        r"-----BEGIN SIGNATURE-----\s*(.*?)-----END SIGNATURE-----",
        re.S,
    )
    valid = 0
    seen: set[str] = set()

    for match in pattern.finditer(text[position + 1 :]):
        algorithm = (match.group(1) or "sha1").lower()
        identity = match.group(2).upper()
        signing_digest = match.group(3).upper()
        if algorithm not in ("sha1", "sha256") or identity in seen:
            continue
        cert = certs.get(identity)
        if cert is None or cert.signing_key_digest != signing_digest:
            continue
        try:
            signature = _b64(re.sub(r"\s+", "", match.group(4)))
        except TorDirectoryError:
            continue
        if not signature:
            continue
        if cert.verify_consensus_signature(signed, signature, algorithm):
            seen.add(identity)
            valid += 1

    return valid >= len(AUTHORITY_FINGERPRINTS) // 2 + 1


def consensus_is_fresh(valid_after: int, fresh_until: int) -> bool:
    now = int(time.time())
    return (
        valid_after > 0
        and valid_after <= now + 3600
        and fresh_until > now - 3600
        and (now - valid_after) < 7 * 86400
    )


def _consensus_time(value: str) -> int:
    try:
        return int(
            datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S")
            .replace(tzinfo=UTC)
            .timestamp()
        )
    except ValueError:
        return 0


def parse_consensus(text: str) -> dict:
    relays: dict[str, RelayInfo] = {}
    params: dict[str, str] = {}
    valid_after = 0
    fresh_until = 0
    shared_random: bytes | None = None
    previous_shared_random: bytes | None = None
    current: RelayInfo | None = None

    for line in re.split(r"\r?\n", text):
        if not line:
            continue

        if line.startswith("shared-rand-current-value ") or line.startswith(
            "shared-rand-previous-value "
        ):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    decoded = _b64(parts[2])
                except TorDirectoryError:
                    decoded = b""
                if len(decoded) == 32:
                    if "previous" in line:
                        previous_shared_random = decoded
                    else:
                        shared_random = decoded
            continue

        if line.startswith("valid-after "):
            valid_after = _consensus_time(line[12:])
            continue
        if line.startswith("fresh-until "):
            fresh_until = _consensus_time(line[12:])
            continue
        if line.startswith("params "):
            for pair in line[7:].split():
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    params[key] = value
            continue

        if line.startswith("r "):
            parts = line.split()
            fields = len(parts)
            if fields == 9:
                address, or_port, dir_port = parts[6], int(parts[7]), int(parts[8])
            elif fields == 8:
                address, or_port, dir_port = parts[5], int(parts[6]), int(parts[7])
            else:
                current = None
                continue

            try:
                identity = _b64(parts[2])
            except TorDirectoryError:
                current = None
                continue
            if len(identity) != 20:
                current = None
                continue

            fingerprint = identity.hex().upper()
            current = RelayInfo(
                nickname=parts[1],
                fingerprint=fingerprint,
                identity_digest=identity,
                address=address,
                or_port=or_port,
                dir_port=dir_port,
            )
            relays[fingerprint] = current
            continue

        if current is None:
            continue

        if line.startswith("m "):
            parts = line.split()
            if len(parts) >= 2:
                digest = re.sub(r"^sha256=", "", parts[1], flags=re.I).rstrip("=")
                if digest:
                    current.microdesc_digest = digest
            continue

        if line.startswith("id ed25519 "):
            encoded = line[11:].strip()
            if encoded != "none":
                try:
                    raw = _b64(encoded)
                except TorDirectoryError:
                    raw = b""
                if len(raw) == 32:
                    current.ed25519_id = raw
            continue

        if line.startswith("s "):
            current.flags = line[2:].split()
            continue

        if line.startswith("w "):
            for pair in line[2:].split():
                if pair.startswith("Bandwidth="):
                    try:
                        current.bandwidth = int(pair[10:])
                    except ValueError:
                        pass

    flavor = "microdesc" if re.search(r"^network-status-version 3 microdesc\b", text, re.M) else "ns"
    return {
        "relays": relays,
        "valid_after": valid_after,
        "fresh_until": fresh_until,
        "params": params,
        "shared_random": shared_random,
        "shared_random_previous": previous_shared_random,
        "flavor": flavor,
    }


def parse_microdescriptors(text: bytes) -> dict[str, dict]:
    text = text.replace(b"\r\n", b"\n")
    result: dict[str, dict] = {}

    blocks = re.split(rb"(?m)(?=^onion-key\n)", text)
    for block in blocks:
        block = block.strip(b"\n")
        if not block or b"\n" not in block:
            continue
        block += b"\n"
        digest = _b64_nopad(hashlib.sha256(block).digest())
        ntor: bytes | None = None
        ed: bytes | None = None
        for line in block.split(b"\n"):
            if line.startswith(b"ntor-onion-key "):
                try:
                    raw = _b64(line[15:].decode())
                except (TorDirectoryError, UnicodeDecodeError):
                    raw = b""
                if len(raw) == 32:
                    ntor = raw
            elif line.startswith(b"id ed25519 "):
                try:
                    raw = _b64(line[11:].decode())
                except (TorDirectoryError, UnicodeDecodeError):
                    raw = b""
                if len(raw) == 32:
                    ed = raw
        result[digest] = {"ntor": ntor, "ed25519": ed}

    return result


# ---------------------------------------------------------------------------
# Fetcher and cache
# ---------------------------------------------------------------------------


class DirectoryFetcher:
    def __init__(self, cache_file: str | None = None) -> None:
        self.cache_file = cache_file
        self._microdesc_authority: tuple[str, int] | None = None
        self._microdesc_cache: dict[str, dict] = {}
        self._microdesc_file = cache_file + ".micro" if cache_file else None
        self._load_microdescs()

    # -- public API ---------------------------------------------------------

    def relays(self, force: bool = False, ttl: int = 3600) -> dict:
        if not force:
            cached = self._read_cache(ttl)
            if cached is not None:
                return cached

        certs = self._fetch_authority_certs()
        consensus, parsed = self._fetch_consensus(certs)
        parsed["relays"] = {
            fp: relay for fp, relay in parsed["relays"].items() if relay.is_selectable()
        }

        self._write_cache(consensus, certs, b"")
        return parsed

    def fetch_microdescriptors(self, relays: list[RelayInfo]) -> None:
        """Fetch the microdescriptors for exactly these relays (one batch)."""
        wanted = {
            relay.microdesc_digest
            for relay in relays
            if relay.microdesc_digest and relay.microdesc_digest not in self._microdesc_cache
        }
        pending = [digest for digest in wanted if digest]

        for start in range(0, len(pending), MAX_MICRODESC_BATCH):
            batch = pending[start : start + MAX_MICRODESC_BATCH]
            body: bytes | None = None
            for _, address, port in self._ordered_authorities():
                try:
                    body = http_get(address, port, MICRODESC_PATH + "-".join(batch))
                    self._microdesc_authority = (address, port)
                    break
                except (OSError, TorConnectionError, TorDirectoryError):
                    continue
            if body is None:
                continue

            blocks = parse_microdescriptors(body)
            self._microdesc_cache.update(blocks)
            missing = [digest for digest in batch if digest not in self._microdesc_cache]
            if missing and len(blocks) == len(batch):
                for index, digest in enumerate(batch):
                    if digest not in self._microdesc_cache and index < len(blocks):
                        self._microdesc_cache[digest] = list(blocks.values())[index]

        for relay in relays:
            if not relay.microdesc_digest:
                continue
            fields = self._microdesc_cache.get(relay.microdesc_digest)
            if fields:
                relay.ntor_onion_key = fields.get("ntor")
                if relay.ed25519_id is None:
                    relay.ed25519_id = fields.get("ed25519")

        self._save_microdescs()

    def _load_microdescs(self) -> None:
        if not self._microdesc_file:
            return
        try:
            with open(self._microdesc_file, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return
        if data.get("version") != 1 or not isinstance(data.get("descriptors"), dict):
            return

        for digest, fields in data["descriptors"].items():
            if not isinstance(fields, dict):
                continue
            try:
                ntor = base64.b64decode(fields["ntor"], validate=True) if fields.get("ntor") else None
                ed = base64.b64decode(fields["ed25519"], validate=True) if fields.get("ed25519") else None
            except (ValueError, KeyError):
                continue
            if ntor is not None and len(ntor) != 32:
                ntor = None
            if ed is not None and len(ed) != 32:
                ed = None
            self._microdesc_cache[digest] = {"ntor": ntor, "ed25519": ed}

    def _save_microdescs(self) -> None:
        if not self._microdesc_file or not self._microdesc_cache:
            return
        try:
            directory = os.path.dirname(os.path.abspath(self._microdesc_file))
            os.makedirs(directory, exist_ok=True)
            payload = {
                "version": 1,
                "descriptors": {
                    digest: {
                        "ntor": base64.b64encode(fields["ntor"]).decode()
                        if fields.get("ntor")
                        else None,
                        "ed25519": base64.b64encode(fields["ed25519"]).decode()
                        if fields.get("ed25519")
                        else None,
                    }
                    for digest, fields in self._microdesc_cache.items()
                },
            }
            temp = self._microdesc_file + ".tmp"
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            os.replace(temp, self._microdesc_file)
        except OSError:
            return

    # -- authority documents ------------------------------------------------

    def _fetch_authority_certs(self) -> dict[str, AuthorityCert]:
        errors: list[str] = []
        certs: dict[str, AuthorityCert] = {}
        required = len(AUTHORITY_FINGERPRINTS) // 2 + 1
        pinned = list(AUTHORITY_FINGERPRINTS.values())

        for nickname, address, port in AUTHORITIES:
            if len(certs) >= required:
                break
            try:
                body = http_get(address, port, AUTHORITY_KEYS_PATH).decode("latin-1")
                for document in re.split(r"\n(?=dir-key-certificate-version 3\r?\n)", body):
                    try:
                        cert = AuthorityCert.parse(document, pinned)
                    except (TorDirectoryError, ValueError, TypeError):
                        continue
                    certs[cert.fingerprint] = cert
            except (OSError, TorConnectionError, TorDirectoryError, ValueError, TypeError) as exc:
                errors.append(f"{nickname} certs: {exc}")

        if len(certs) < required:
            detail = "; ".join(errors[:4])
            raise TorDirectoryError(
                f"Could not obtain {required} authority certificates: {detail}"
            )
        return certs

    def _fetch_consensus(
        self, certs: dict[str, AuthorityCert]
    ) -> tuple[str, dict]:
        errors: list[str] = []

        for nickname, address, port in AUTHORITIES:
            try:
                body = http_get(address, port, CONSENSUS_PATH).decode("latin-1")
                if not verify_consensus(body, certs):
                    raise TorDirectoryError("Consensus lacks a majority of valid signatures")
                parsed = parse_consensus(body)
                if not parsed["relays"]:
                    raise TorDirectoryError("Consensus lists no relays")
                if parsed["flavor"] != "microdesc":
                    raise TorDirectoryError("Authority served the ns flavor, not microdesc")
                if not consensus_is_fresh(parsed["valid_after"], parsed["fresh_until"]):
                    raise TorDirectoryError("Consensus is outside its validity window")
                return body, parsed
            except (OSError, TorConnectionError, TorDirectoryError) as exc:
                errors.append(f"{nickname}: {exc}")

        detail = "; ".join(errors[:4])
        raise TorDirectoryError(f"Could not fetch a consensus from any authority: {detail}")

    def _ordered_authorities(self) -> list[tuple[str, str, int]]:
        if self._microdesc_authority is None:
            return list(AUTHORITIES)
        address, port = self._microdesc_authority
        first = [entry for entry in AUTHORITIES if entry[1] == address and entry[2] == port]
        rest = [entry for entry in AUTHORITIES if entry not in first]
        return first + rest



    # -- cache --------------------------------------------------------------

    def _read_cache(self, ttl: int) -> dict | None:
        if not self.cache_file:
            return None
        try:
            with open(self.cache_file, "rb") as handle:
                raw = handle.read()
        except OSError:
            return None
        if not raw:
            return None

        if raw.startswith(CACHE_MAGIC):
            try:
                raw = gzip.decompress(raw[len(CACHE_MAGIC) :])
            except OSError:
                return None

        try:
            data = json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            return None
        if data.get("version") != CACHE_VERSION:
            return None

        fetched_at = int(data.get("fetched_at", 0))
        fresh_until = int(data.get("fresh_until", 0))
        now = int(time.time())
        if (ttl > 0 and now - fetched_at > ttl) or (fresh_until > 0 and now > fresh_until + 900):
            return None

        try:
            consensus = base64.b64decode(data.get("consensus", ""), validate=True).decode("latin-1")
            microdescs = base64.b64decode(data.get("microdescs", ""), validate=True)
            certs: dict[str, AuthorityCert] = {}
            for encoded in data.get("certs", []):
                document = base64.b64decode(encoded, validate=True).decode("latin-1")
                cert = AuthorityCert.parse(document, list(AUTHORITY_FINGERPRINTS.values()))
                certs[cert.fingerprint] = cert
        except (ValueError, UnicodeDecodeError, TorDirectoryError, TypeError):
            return None

        if not certs or not verify_consensus(consensus, certs):
            return None

        parsed = parse_consensus(consensus)
        if not parsed["relays"] or not consensus_is_fresh(
            parsed["valid_after"], parsed["fresh_until"]
        ):
            return None

        parsed["relays"] = {
            fp: relay for fp, relay in parsed["relays"].items() if relay.is_selectable()
        }
        return parsed

    def _write_cache(
        self, consensus: str, certs: dict[str, AuthorityCert], microdescs: bytes
    ) -> None:
        if not self.cache_file:
            return
        try:
            directory = os.path.dirname(os.path.abspath(self.cache_file))
            os.makedirs(directory, exist_ok=True)
            payload = {
                "version": CACHE_VERSION,
                "fetched_at": int(time.time()),
                "consensus": base64.b64encode(consensus.encode("latin-1")).decode(),
                "certs": [
                    base64.b64encode(cert.document.encode()).decode()
                    for cert in certs.values()
                ],
                "microdescs": base64.b64encode(microdescs).decode(),
            }
            raw = CACHE_MAGIC + gzip.compress(
                json.dumps(payload, separators=(",", ":")).encode(), 6
            )
            temp = self.cache_file + ".tmp"
            with open(temp, "wb") as handle:
                handle.write(raw)
            os.replace(temp, self.cache_file)
        except OSError:
            return
