"""Prop220 ed25519 certificates and Tor link-certificate verification."""

from __future__ import annotations

import base64
import re
import struct
import time
from dataclasses import dataclass, field

from .crypto import ed25519_verify
from .errors import TorProtocolError

CERT_TYPE_ID_SIGNING = 0x04


@dataclass(slots=True)
class Ed25519Cert:
    type: int
    expires: int
    key: bytes
    extensions: dict[int, bytes] = field(default_factory=dict)
    signature: bytes = b""
    raw: bytes = b""


def parse_ed25519_cert(pem: str) -> Ed25519Cert:
    match = re.search(r"-----BEGIN ED25519 CERT-----\s*(.*?)-----END ED25519 CERT-----", pem, re.S)
    if not match:
        raise TorProtocolError("Malformed ed25519 certificate wrapper")

    try:
        raw = base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True)
    except ValueError as exc:
        raise TorProtocolError("Malformed ed25519 certificate") from exc
    if len(raw) < 40 + 64:
        raise TorProtocolError("Malformed ed25519 certificate")

    version = raw[0]
    cert_type = raw[1]
    expires = 3600 * struct.unpack(">I", raw[2:6])[0]
    key_type = raw[6]
    if version != 1 or key_type != 1:
        raise TorProtocolError("Unsupported ed25519 certificate version or key type")

    key = raw[7:39]
    extensions: dict[int, bytes] = {}
    count = raw[39]
    offset = 40
    limit = len(raw) - 64

    for _ in range(count):
        if offset + 4 > limit:
            raise TorProtocolError("Truncated ed25519 certificate extension")
        length = struct.unpack(">H", raw[offset : offset + 2])[0]
        if offset + 4 + length > limit:
            raise TorProtocolError("Malformed ed25519 certificate extension length")
        ext_type = raw[offset + 2]
        extensions[ext_type] = raw[offset + 4 : offset + 4 + length]
        offset += 4 + length

    return Ed25519Cert(
        type=cert_type,
        expires=expires,
        key=key,
        extensions=extensions,
        signature=raw[-64:],
        raw=raw,
    )


def cert_key(certificate: str) -> bytes:
    """Return the 32-byte certified key from a PEM or bare base64 certificate."""
    base64_body = certificate
    match = re.search(r"-----BEGIN ED25519 CERT-----\s*(.*?)-----END ED25519 CERT-----", certificate, re.S)
    if match:
        base64_body = match.group(1)

    try:
        raw = base64.b64decode(re.sub(r"\s+", "", base64_body), validate=True)
    except ValueError as exc:
        raise TorProtocolError("Malformed ed25519 certificate") from exc
    if len(raw) < 39:
        raise TorProtocolError("Malformed ed25519 certificate")
    if raw[0] != 1 or raw[6] != 1:
        raise TorProtocolError("Unexpected ed25519 certificate version or key type")
    return raw[7:39]


def verify_link_certs(certs_payload: bytes, expected_ed25519_id: bytes) -> bool:
    """Verify a CERTS cell body against the relay's consensus ed25519 identity."""
    if not certs_payload:
        return False

    count = certs_payload[0]
    offset = 1
    length = len(certs_payload)

    for _ in range(count):
        if offset + 3 > length:
            return False
        cert_type = certs_payload[offset]
        cert_length = struct.unpack(">H", certs_payload[offset + 1 : offset + 3])[0]
        offset += 3
        if cert_length <= 0 or offset + cert_length > length:
            return False
        raw = certs_payload[offset : offset + cert_length]
        offset += cert_length

        if cert_type != CERT_TYPE_ID_SIGNING:
            continue

        pem = (
            "-----BEGIN ED25519 CERT-----\n"
            + base64.encodebytes(raw).decode()
            + "-----END ED25519 CERT-----\n"
        )
        try:
            cert = parse_ed25519_cert(pem)
        except TorProtocolError:
            continue

        if cert.type != CERT_TYPE_ID_SIGNING or cert.expires < time.time():
            continue
        if ed25519_verify(expected_ed25519_id, cert.raw[:-64], cert.signature):
            return True

    return False
