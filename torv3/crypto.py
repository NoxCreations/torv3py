"""Cryptographic primitives used by the Tor v3 client.

X25519, Ed25519 verification, AES-CTR and RSA verification come from the
``cryptography`` package.  HSv3 key blinding additionally needs Ed25519
point-scalar multiplication, which libsodium/OpenSSL do not expose, so the
group arithmetic is implemented here.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import TorProtocolError

# ---------------------------------------------------------------------------
# X25519 / Ed25519
# ---------------------------------------------------------------------------


def x25519_generate() -> tuple[bytes, bytes]:
    private = X25519PrivateKey.generate()
    return (
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
    )


def x25519(private: bytes, public: bytes) -> bytes:
    if len(private) != 32 or len(public) != 32:
        raise TorProtocolError("X25519 keys must be 32 bytes")
    try:
        return X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(public))
    except ValueError as exc:
        raise TorProtocolError(f"X25519 key agreement failed: {exc}") from exc


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# Ed25519 extended-coordinate group arithmetic (-x^2 + y^2 = 1 + d x^2 y^2).
_ED_P = 2**255 - 19
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_BASE = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")


def _ed_decode(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise TorProtocolError("Ed25519 point must be 32 bytes")
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded[:31] + bytes([encoded[31] & 0x7F]), "little")
    if y >= _ED_P:
        raise TorProtocolError("Ed25519 point has non-canonical y coordinate")

    y2 = (y * y) % _ED_P
    u = (y2 - 1) % _ED_P
    v = (_ED_D * y2 + 1) % _ED_P
    v3 = (v * v * v) % _ED_P
    v7 = (v3 * v3 * v) % _ED_P
    x = (u * v3 * pow((u * v7) % _ED_P, (_ED_P - 5) // 8, _ED_P)) % _ED_P

    check = (v * x * x) % _ED_P
    if check != u:
        if check != (-u) % _ED_P:
            raise TorProtocolError("Ed25519 point is not on the curve")
        x = (x * _ED_I) % _ED_P
    if x == 0 and sign:
        raise TorProtocolError("Ed25519 point has invalid sign bit")
    if (x & 1) != sign:
        x = _ED_P - x
    return x, y, 1, (x * y) % _ED_P


def _ed_add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (t1 * 2 * _ED_D * t2) % _ED_P
    d = (2 * z1 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return (e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P


def _ed_encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zinv = pow(z, _ED_P - 2, _ED_P)
    x = (x * zinv) % _ED_P
    y = (y * zinv) % _ED_P
    out = bytearray(y.to_bytes(32, "little"))
    out[31] = (out[31] & 0x7F) | ((x & 1) << 7)
    return bytes(out)


def ed25519_scalar_mult(scalar: bytes | int, point: bytes) -> bytes:
    """Multiply an encoded point by a scalar (32-byte little-endian or int)."""
    k = int.from_bytes(scalar, "little") if isinstance(scalar, bytes) else scalar
    base = _ed_decode(point)
    result = (0, 1, 1, 0)
    addend = base
    for bit in range(256):
        if (k >> bit) & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
    return _ed_encode(result)


def ed25519_blind_public_key(public_key: bytes, period_num: int, period_length: int) -> bytes:
    """HSv3 key blinding (rend-spec-v3 Appendix A)."""
    nonce = b"key-blind" + struct.pack(">Q", period_num) + struct.pack(">Q", period_length)
    factor = hashlib.sha3_256(
        b"Derive temporary signing key\x00"
        + public_key
        + b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, "
        + b"46316835694926478169428394003475163141307993866256225615783033603165251855960)"
        + nonce
    ).digest()
    factor = bytearray(factor)
    factor[0] &= 248
    factor[31] = (factor[31] & 63) | 64
    try:
        return ed25519_scalar_mult(bytes(factor), public_key)
    except TorProtocolError as exc:
        raise TorProtocolError(f"Onion service identity key is not a valid Ed25519 point: {exc}") from exc


# ---------------------------------------------------------------------------
# AES-CTR
# ---------------------------------------------------------------------------


class AESCTR:
    """Stateful AES-CTR stream (128- or 256-bit key)."""

    def __init__(self, key: bytes, iv: bytes = b"\x00" * 16) -> None:
        if len(key) not in (16, 32):
            raise TorProtocolError(f"AES key must be 16 or 32 bytes, got {len(key)}")
        if len(iv) != 16:
            raise TorProtocolError("AES-CTR IV must be 16 bytes")
        self._encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    def process(self, data: bytes) -> bytes:
        return self._encryptor.update(data)

    encrypt = process
    decrypt = process


# ---------------------------------------------------------------------------
# ntor / HKDF
# ---------------------------------------------------------------------------

NTOR_PROTOID = b"ntor-curve25519-sha256-1"
NTOR_T_MAC = NTOR_PROTOID + b":mac"
NTOR_T_KEY = NTOR_PROTOID + b":key_extract"
NTOR_T_VERIFY = NTOR_PROTOID + b":verify"
NTOR_M_EXPAND = NTOR_PROTOID + b":key_expand"


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        if counter > 255:
            raise TorProtocolError("HKDF output too long")
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
        counter += 1
    return output[:length]


def ntor_client_keys(
    node_id: bytes,
    onion_key: bytes,
    client_private: bytes,
    client_public: bytes,
    server_public: bytes,
    auth: bytes,
) -> dict[str, bytes]:
    if len(auth) != 32:
        raise TorProtocolError("ntor AUTH must be 32 bytes")
    exp_y = x25519(client_private, server_public)
    exp_b = x25519(client_private, onion_key)
    secret = exp_y + exp_b + node_id + onion_key + client_public + server_public + NTOR_PROTOID

    verify = hmac.new(NTOR_T_VERIFY, secret, hashlib.sha256).digest()
    auth_input = verify + node_id + onion_key + server_public + client_public + NTOR_PROTOID + b"Server"
    expected = hmac.new(NTOR_T_MAC, auth_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, auth):
        raise TorProtocolError("ntor handshake AUTH verification failed")

    key_seed = hmac.new(NTOR_T_KEY, secret, hashlib.sha256).digest()
    keys = hkdf_expand(key_seed, NTOR_M_EXPAND, 72)
    return {
        "df": keys[0:20],
        "db": keys[20:40],
        "kf": keys[40:56],
        "kb": keys[56:72],
    }


def ntor_onion_skin(node_id: bytes, onion_key: bytes, client_public: bytes) -> bytes:
    if len(node_id) != 20:
        raise TorProtocolError("Node ID must be 20 bytes")
    if len(onion_key) != 32 or len(client_public) != 32:
        raise TorProtocolError("ntor keys must be 32 bytes")
    return node_id + onion_key + client_public


# ---------------------------------------------------------------------------
# RSA (Tor signs the raw digest, without an ASN.1 DigestInfo wrapper)
# ---------------------------------------------------------------------------


def rsa_verify(data: bytes, signature: bytes, public_key_pem: str, algorithm: str) -> bool:
    if algorithm not in ("sha1", "sha256"):
        return False
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode())
        numbers = key.public_numbers()
    except (ValueError, TypeError):
        return False

    n, e = numbers.n, numbers.e
    size = (n.bit_length() + 7) // 8
    if len(signature) > size:
        return False
    recovered = pow(int.from_bytes(signature, "big"), e, n).to_bytes(size, "big")
    digest = hashlib.new(algorithm, data).digest()
    expected = b"\x00\x01" + b"\xff" * (size - 3 - len(digest)) + b"\x00" + digest
    return hmac.compare_digest(recovered, expected)


def rsa_public_numbers(public_key_pem: str) -> tuple[int, int]:
    key = serialization.load_pem_public_key(public_key_pem.encode())
    numbers = key.public_numbers()
    return numbers.n, numbers.e


def rsa_pkcs1_der(public_key_pem: str) -> bytes:
    """PKCS#1 RSAPublicKey DER, whose SHA-1 is Tor's relay fingerprint."""
    n, e = rsa_public_numbers(public_key_pem)

    def integer(value: int) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + _der_length(len(raw)) + raw

    body = integer(n) + integer(e)
    return b"\x30" + _der_length(len(body)) + body


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


# ---------------------------------------------------------------------------
# HSv3 descriptor helpers
# ---------------------------------------------------------------------------


def mac_sha3(key: bytes, message: bytes) -> bytes:
    """tor's crypto_mac_sha3_256: SHA3-256(htonll(len(key)) | key | message)."""
    return hashlib.sha3_256(struct.pack(">Q", len(key)) + key + message).digest()
