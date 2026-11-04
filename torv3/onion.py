"""Tor v3 onion services: descriptors, hs-ntor, introduction, rendezvous.

Implements rend-spec-v3 address parsing, key blinding, descriptor fetch and
decryption, INTRODUCE1 construction, and RENDEZVOUS2 key derivation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time

from .cells import Commands
from .certs import cert_key, parse_ed25519_cert
from .circuit import Circuit
from .crypto import (
    AESCTR,
    ed25519_blind_public_key,
    ed25519_verify,
    mac_sha3,
    x25519,
    x25519_generate,
)
from .directory import parse_http_response
from .errors import TorOnionError, TorProtocolError, TorStreamError

PROTOID = b"tor-hs-ntor-curve25519-sha3-256-1"
T_HSENC = PROTOID + b":hs_key_extract"
T_HSVERIFY = PROTOID + b":hs_verify"
T_HSMAC = PROTOID + b":hs_mac"
M_HSEXPAND = PROTOID + b":hs_key_expand"
PERIOD_LENGTH_MINUTES = 1440
MAX_DESCRIPTOR_BYTES = 65536
BLIND_STRING = b"Derive temporary signing key\x00"
# Decimal coordinates of the Ed25519 base point, as tor's hs_common.c uses.
ED25519_BASEPOINT = (
    b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, "
    b"46316835694926478169428394003475163141307993866256225615783033603165251855960)"
)


def _b64(value: str) -> bytes:
    value = value.strip().translate(str.maketrans("-_", "+/"))
    value += "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise TorOnionError("Malformed base64 value") from exc


def parse_address(address: str) -> dict:
    hostname = address.strip().lower()
    if hostname.endswith(".onion"):
        hostname = hostname[:-6]
    if len(hostname) != 56 or not re.fullmatch(r"[a-z2-7]{56}", hostname):
        raise TorOnionError("v3 onion addresses must be 56 base32 characters")

    try:
        raw = base64.b32decode(hostname.upper(), casefold=True)
    except ValueError as exc:
        raise TorOnionError("Malformed v3 onion address") from exc
    if len(raw) != 35:
        raise TorOnionError("Malformed v3 onion address")

    public_key, checksum, version = raw[:32], raw[32:34], raw[34]
    if version != 3:
        raise TorOnionError(f"Unsupported onion address version {version}")

    expected = hashlib.sha3_256(b".onion checksum" + public_key + bytes([version])).digest()[:2]
    if expected != checksum:
        raise TorOnionError("Onion address checksum mismatch")

    return {
        "hostname": hostname + ".onion",
        "public_key": public_key,
        "checksum": checksum,
        "version": version,
    }


def encode_address(public_key: bytes, version: int = 3) -> str:
    if len(public_key) != 32:
        raise TorOnionError("Onion public key must be 32 bytes")
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + bytes([version])).digest()[:2]
    encoded = base64.b32encode(public_key + checksum + bytes([version])).decode().lower()
    return encoded.rstrip("=") + ".onion"


def time_period(timestamp: int, period_length: int = PERIOD_LENGTH_MINUTES) -> int:
    minutes = timestamp // 60
    return (minutes - 12 * 60) // period_length


def blinded_public_key(
    public_key: bytes, period_num: int, period_length: int = PERIOD_LENGTH_MINUTES
) -> bytes:
    if len(public_key) != 32:
        raise TorOnionError("Identity public key must be 32 bytes")
    try:
        return ed25519_blind_public_key(public_key, period_num, period_length)
    except TorProtocolError as exc:
        raise TorOnionError(
            f"Onion service identity key is not a valid Ed25519 point: {exc}"
        ) from exc


def subcredential_for(public_key: bytes, blinded: bytes) -> bytes:
    credential = hashlib.sha3_256(b"credential" + public_key).digest()
    return hashlib.sha3_256(b"subcredential" + credential + blinded).digest()


def store_at_index(blinded: bytes, replica: int, period_num: int, period_length: int) -> bytes:
    return hashlib.sha3_256(
        b"store-at-idx"
        + blinded
        + struct.pack(">Q", replica)
        + struct.pack(">Q", period_length)
        + struct.pack(">Q", period_num)
    ).digest()


class OnionV3:
    def __init__(
        self,
        address: str,
        timestamp: int | None = None,
        period_length: int = PERIOD_LENGTH_MINUTES,
    ) -> None:
        parsed = parse_address(address)
        self.address: str = parsed["hostname"]
        self.public_key: bytes = parsed["public_key"]
        self.period_length = period_length
        if period_length <= 0:
            raise TorOnionError("Descriptor period length must be positive")
        self.period_num = time_period(timestamp if timestamp is not None else int(time.time()), period_length)
        self.blinded = blinded_public_key(self.public_key, self.period_num, period_length)
        self.subcred = subcredential_for(self.public_key, self.blinded)
        self.client_auth_key: bytes | None = None

    def hostname(self) -> str:
        return self.address

    def hs_index(self, replica: int = 1) -> bytes:
        return store_at_index(self.blinded, replica, self.period_num, self.period_length)

    def descriptor_path(self) -> str:
        return "/tor/hs/3/" + base64.b64encode(self.blinded).decode().rstrip("=")

    def set_client_auth_key(self, key: str | bytes) -> None:
        if isinstance(key, bytes):
            if len(key) != 32:
                raise TorOnionError("Client authorization key must be 32 bytes")
            self.client_auth_key = key
            return
        decoded = _b64(key)
        if len(decoded) != 32:
            raise TorOnionError("Client authorization key must be 32 raw bytes or base64")
        self.client_auth_key = decoded

    def fetch_descriptor(self, hsdir_circuit: Circuit, timeout: float = 45.0) -> bytes:
        path = self.descriptor_path()
        stream_id = hsdir_circuit.begin_stream("", 0, begin_dir=True, timeout=timeout)
        hsdir_circuit.send_data(
            stream_id,
            f"GET {path} HTTP/1.0\r\nHost: hsdir\r\nUser-Agent: torv3-python/1.0\r\n"
            "Connection: close\r\n\r\n".encode(),
        )

        deadline = time.monotonic() + timeout
        raw = bytearray()

        while time.monotonic() < deadline:
            try:
                chunk = hsdir_circuit.read_stream_data(
                    stream_id, max(0.5, deadline - time.monotonic())
                )
            except TorStreamError as exc:
                if "timed out" in str(exc).lower():
                    raise TorOnionError("Timed out reading the descriptor from the HSDir") from exc
                break
            if not chunk:
                continue

            raw += chunk
            if len(raw) > MAX_DESCRIPTOR_BYTES:
                raise TorOnionError("HSDir response exceeds the descriptor size limit")

            response = parse_http_response(bytes(raw))
            length_header = (response["headers"].get("content-length") or [None])[0]
            if length_header is not None and len(response["body"]) >= int(length_header):
                break

        hsdir_circuit.close_stream(stream_id)

        if time.monotonic() >= deadline:
            raise TorOnionError("Timed out reading the descriptor from the HSDir")

        response = parse_http_response(bytes(raw))
        if response["status"] != 200:
            raise TorOnionError(f"HSDir returned HTTP {response['status']} for descriptor {path}")
        if not response["body"].strip():
            raise TorOnionError("HSDir returned an empty descriptor")
        return response["body"]

    def decrypt_descriptor(self, descriptor: bytes, cookie: bytes = b"") -> dict:
        text = descriptor.decode("latin-1")
        if "hs-descriptor 3" not in text:
            raise TorOnionError("Not a version 3 hidden service descriptor")

        self._verify_descriptor_signature(text)

        revision_match = re.search(r"^revision-counter (\d+)$", text, re.M)
        revision = int(revision_match.group(1)) if revision_match else 0

        superencrypted = extract_pem_block(text, "superencrypted")
        if superencrypted is None:
            raise TorOnionError("Descriptor has no superencrypted block")

        outer = self._decrypt_layer(
            superencrypted, self.blinded, b"hsdir-superencrypted-data", revision
        ).decode("latin-1")

        lifetime = re.search(r"^descriptor-lifetime (\d+)$", outer, re.M)
        if lifetime and not 30 <= int(lifetime.group(1)) <= 720:
            raise TorOnionError("Descriptor lifetime is outside the permitted 30..720 minutes")

        if not cookie and self.client_auth_key is not None:
            cookie = self._client_descriptor_cookie(outer) or b""

        inner_blob = extract_pem_block(outer, "encrypted")
        if inner_blob is None:
            raise TorOnionError("Descriptor has no encrypted block")

        plaintext = self._decrypt_layer(
            inner_blob,
            self.blinded + cookie,
            b"hsdir-encrypted-data",
            revision,
        ).rstrip(b"\x00").decode("latin-1")

        if intro_auth_required(plaintext) and not cookie:
            raise TorOnionError(
                "This onion service requires client authorization; no matching client key is configured"
            )

        points = parse_intro_points(plaintext)
        if not points:
            raise TorOnionError("Descriptor lists no usable introduction points")

        return {
            "revision": revision,
            "plaintext": plaintext,
            "introduction_points": points,
            "descriptor": descriptor,
        }

    def _client_descriptor_cookie(self, first_layer: str) -> bytes | None:
        if self.client_auth_key is None:
            return None

        type_match = re.search(r"^desc-auth-type\s+(\S+)\s*$", first_layer, re.M)
        if not type_match:
            return None
        if type_match.group(1).lower() != "x25519":
            raise TorOnionError(f"Unsupported descriptor client-auth type: {type_match.group(1)}")

        key_match = re.search(r"^desc-auth-ephemeral-key\s+(\S+)\s*$", first_layer, re.M)
        if not key_match:
            raise TorOnionError("Descriptor has no client-auth ephemeral key")
        ephemeral = _b64(key_match.group(1))
        if len(ephemeral) != 32:
            raise TorOnionError("Descriptor client-auth ephemeral key is invalid")

        secret = x25519(self.client_auth_key, ephemeral)
        keys = hashlib.shake_256(self.subcred + secret).digest(40)
        client_id, cookie_key = keys[:8], keys[8:40]

        for line in first_layer.splitlines():
            if not line.startswith("auth-client "):
                continue
            parts = line.split()
            if len(parts) != 4:
                continue
            try:
                identifier = _b64(parts[1])
                iv = _b64(parts[2])
                encrypted = _b64(parts[3])
            except TorOnionError:
                continue
            if len(iv) != 16 or len(encrypted) != 16 or identifier != client_id:
                continue
            cookie = AESCTR(cookie_key, iv).decrypt(encrypted)
            if len(cookie) != 16:
                raise TorOnionError("Descriptor cookie decryption failed")
            return cookie

        return None

    def _decrypt_layer(
        self, blob: bytes, secret_data: bytes, string_constant: bytes, revision: int
    ) -> bytes:
        if len(blob) < 16 + 32 + 16:
            raise TorOnionError("Descriptor layer is too short")

        salt, mac, ciphertext = blob[:16], blob[-32:], blob[16:-32]
        secret_input = secret_data + self.subcred + struct.pack(">Q", revision)
        keys = hashlib.shake_256(secret_input + salt + string_constant).digest(80)
        key, iv, mac_key = keys[:32], keys[32:48], keys[48:80]

        expected = hashlib.sha3_256(
            struct.pack(">Q", 32) + mac_key + struct.pack(">Q", 16) + salt + ciphertext
        ).digest()
        if not hmac.compare_digest(expected, mac):
            raise TorOnionError("Descriptor MAC verification failed")

        return AESCTR(key, iv).decrypt(ciphertext)

    def _verify_descriptor_signature(self, descriptor: str) -> None:
        match = re.search(
            r"descriptor-signing-key-cert\s*\r?\n"
            r"(-----BEGIN ED25519 CERT-----.*?-----END ED25519 CERT-----)",
            descriptor,
            re.S,
        )
        if not match:
            raise TorOnionError("Descriptor has no signing-key certificate")

        cert = parse_ed25519_cert(match.group(1))
        if cert.type != 8:
            raise TorOnionError(
                f"Descriptor signing certificate has type {cert.type}, expected 8"
            )
        if cert.expires < time.time():
            raise TorOnionError("Descriptor signing certificate has expired")
        if not ed25519_verify(self.blinded, cert.raw[:-64], cert.signature):
            raise TorOnionError("Descriptor signing certificate is not signed by the service blinded key")
        if cert.extensions.get(4) != self.blinded:
            raise TorOnionError("Descriptor signing certificate does not certify the blinded key")

        signature_pos = descriptor.find("\nsignature ")
        if signature_pos < 0:
            raise TorOnionError("Descriptor has no signature line")
        signature_line = descriptor[signature_pos + 1 :]
        sig_match = re.match(r"signature ([A-Za-z0-9+/=]+)", signature_line)
        if not sig_match:
            raise TorOnionError("Malformed descriptor signature line")

        signature = _b64(sig_match.group(1))
        if len(signature) != 64:
            raise TorOnionError("Malformed descriptor signature")

        signed = descriptor[: signature_pos + 1].encode("latin-1")
        if not ed25519_verify(
            cert.key, b"Tor onion service descriptor sig v3" + signed, signature
        ):
            raise TorOnionError("Descriptor signature verification failed")

    def build_introduce1(
        self,
        intro_point: dict,
        rendezvous_public_key: bytes,
        rendezvous_specs: list[dict],
        cookie: bytes,
    ) -> dict:
        if len(cookie) != 20:
            raise TorOnionError("Rendezvous cookie must be 20 bytes")
        if len(rendezvous_public_key) != 32:
            raise TorOnionError("Rendezvous ntor key must be 32 bytes")

        auth_key = intro_point["auth_key"]
        enc_key = intro_point["enc_key"]
        client_private, client_public = x25519_generate()

        exp = x25519(client_private, enc_key)
        secret = exp + auth_key + client_public + enc_key + PROTOID
        keys = hashlib.shake_256(
            secret + T_HSENC + M_HSEXPAND + self.subcred
        ).digest(64)
        hs_enc_key, hs_mac_key = keys[:32], keys[32:64]

        header = (
            b"\x00" * 20
            + b"\x02"
            + struct.pack(">H", 32)
            + auth_key
            + b"\x00"
        )
        plaintext = (
            cookie
            + b"\x00"
            + b"\x01"
            + struct.pack(">H", 32)
            + rendezvous_public_key
            + bytes([len(rendezvous_specs)])
            + encode_lspecs(rendezvous_specs)
        )
        plaintext += secrets.token_bytes((16 - len(plaintext) % 16) % 16)
        ciphertext = AESCTR(hs_enc_key, b"\x00" * 16).encrypt(plaintext)
        mac = hashlib.sha3_256(
            struct.pack(">Q", 32) + hs_mac_key + header + client_public + ciphertext
        ).digest()

        return {
            "body": header + client_public + ciphertext + mac,
            "client_private": client_private,
            "client_public": client_public,
            "enc_key": enc_key,
            "auth_key": auth_key,
            "mac_key": hs_mac_key,
            "plaintext": plaintext,
        }

    def process_rend2(self, context: dict, payload: bytes) -> dict:
        if len(payload) < 64:
            raise TorOnionError("RENDEZVOUS2 payload is too short")

        server_public, auth = payload[:32], payload[32:64]
        exp_service = x25519(context["client_private"], server_public)
        exp_intro = x25519(context["client_private"], context["enc_key"])
        secret = (
            exp_service
            + exp_intro
            + context["auth_key"]
            + context["enc_key"]
            + context["client_public"]
            + server_public
            + PROTOID
        )

        seed = mac_sha3(secret, T_HSENC)
        verify = mac_sha3(secret, T_HSVERIFY)
        auth_input = (
            verify
            + context["auth_key"]
            + context["enc_key"]
            + server_public
            + context["client_public"]
            + PROTOID
            + b"Server"
        )
        if not hmac.compare_digest(mac_sha3(auth_input, T_HSMAC), auth):
            raise TorOnionError("RENDEZVOUS2 handshake authentication failed")

        keys = hashlib.shake_256(seed + M_HSEXPAND).digest(128)
        return {
            "df": keys[:32],
            "db": keys[32:64],
            "kf": keys[64:96],
            "kb": keys[96:128],
            "seed": seed,
        }


def extract_pem_block(text: str, field: str) -> bytes | None:
    keyword = "superencrypted" if field == "superencrypted" else r"(?<!super)encrypted"
    match = re.search(
        keyword + r"\s*\r?\n\s*-----BEGIN MESSAGE-----\s*(.*?)-----END MESSAGE-----",
        text,
        re.S,
    )
    if not match:
        return None
    try:
        decoded = base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True)
    except ValueError:
        return None
    return decoded or None


def intro_auth_required(plaintext: str) -> bool:
    return re.search(r"^intro-auth-required\s+\S+", plaintext, re.M) is not None


def parse_intro_points(plaintext: str) -> list[dict]:
    points: list[dict] = []
    current: dict | None = None
    cert_field: str | None = None
    cert_buffer = ""

    for raw_line in plaintext.splitlines():
        line = raw_line.rstrip("\r\n")

        if cert_field is not None:
            cert_buffer += line + "\n"
            if line.startswith("-----END ED25519 CERT-----"):
                if cert_field == "auth-key" and current is not None:
                    try:
                        current["auth_key"] = cert_key(cert_buffer)
                    except Exception:
                        current["auth_key"] = None
                cert_field = None
                cert_buffer = ""
            continue

        if line.startswith("introduction-point "):
            if current is not None:
                points.append(current)
            current = {
                "link_specifiers": parse_lspecs(line[19:].strip()),
                "auth_key": None,
                "enc_key": None,
                "onion_key": None,
            }
            continue

        if current is None:
            continue

        if line in ("auth-key", "enc-key-cert"):
            cert_field = line
            cert_buffer = ""
            continue

        if line.startswith("auth-key "):
            try:
                current["auth_key"] = cert_key(line[9:])
            except Exception:
                current["auth_key"] = None
            continue

        if line.startswith("onion-key ntor "):
            try:
                current["onion_key"] = _b64(line[15:].strip())
            except TorOnionError:
                pass
            continue

        if line.startswith("enc-key ntor "):
            try:
                current["enc_key"] = _b64(line[13:].strip())
            except TorOnionError:
                pass

    if current is not None:
        points.append(current)

    return [
        point
        for point in points
        if point["auth_key"] is not None and point["enc_key"] is not None
    ]


def parse_lspecs(encoded: str) -> list[dict]:
    try:
        raw = _b64(encoded)
    except TorOnionError as exc:
        raise TorOnionError("Malformed link specifier blob") from exc
    if not raw:
        raise TorOnionError("Malformed link specifier blob")

    count = raw[0]
    specs: list[dict] = []
    offset = 1
    for _ in range(count):
        if offset + 2 > len(raw):
            raise TorOnionError("Truncated link specifier list")
        spec_type = raw[offset]
        length = raw[offset + 1]
        offset += 2
        if offset + length > len(raw):
            raise TorOnionError("Truncated link specifier")
        specs.append({"type": spec_type, "data": raw[offset : offset + length]})
        offset += length
    return specs


def encode_lspecs(specs: list[dict]) -> bytes:
    return b"".join(bytes([spec["type"], len(spec["data"])]) + spec["data"] for spec in specs)
