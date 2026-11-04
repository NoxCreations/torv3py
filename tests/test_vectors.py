"""Offline protocol and crypto vectors for torv3."""

from __future__ import annotations

import hashlib
import hmac
import struct
import unittest

from torv3.cells import Cell, Commands, RelayCell
from torv3.crypto import (
    ed25519_scalar_mult,
    hkdf_expand,
    x25519,
)
from torv3.directory import decode_chunked, parse_http_response
from torv3.onion import encode_address, extract_pem_block, parse_address

ED25519_BASE = bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"
)


class CryptoVectors(unittest.TestCase):
    def test_x25519_rfc7748(self) -> None:
        alice_private = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        alice_public = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )
        bob_public = bytes.fromhex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        )
        shared = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        )
        self.assertEqual(x25519(alice_private, bob_public), shared)
        # The public key is the base point multiplied by the private scalar.
        self.assertEqual(
            x25519(
                alice_private,
                bytes([9]) + b"\x00" * 31,
            ),
            alice_public,
        )

    def test_hkdf_rfc5869_case1(self) -> None:
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        self.assertEqual(
            prk.hex(),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        )
        self.assertEqual(
            hkdf_expand(prk, info, 42).hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
        )

    def test_ed25519_scalar_one(self) -> None:
        self.assertEqual(ed25519_scalar_mult(1, ED25519_BASE), ED25519_BASE)
        self.assertEqual(ed25519_scalar_mult(0, ED25519_BASE), b"\x01" + b"\x00" * 31)


class CellVectors(unittest.TestCase):
    def test_fixed_cell_roundtrip(self) -> None:
        cell = Cell.fixed(0x80000001, Commands.RELAY, b"hello")
        encoded = cell.encode(4)
        self.assertEqual(len(encoded), 4 + 1 + 509)
        self.assertEqual(encoded[4], Commands.RELAY)
        self.assertEqual(encoded[5:10], b"hello")

    def test_relay_cell(self) -> None:
        payload = RelayCell.build(Commands.RELAY_DATA, 7, b"abc")
        self.assertEqual(len(payload), Commands.PAYLOAD_LEN)
        self.assertEqual(RelayCell.command(payload), Commands.RELAY_DATA)
        self.assertEqual(RelayCell.stream_id(payload), 7)
        self.assertEqual(RelayCell.length(payload), 3)
        self.assertEqual(RelayCell.data(payload), b"abc")
        zeroed = RelayCell.zero_digest(payload)
        self.assertEqual(zeroed[5:9], b"\x00" * 4)
        with_digest = RelayCell.insert_digest(payload, b"test")
        self.assertEqual(RelayCell.digest(with_digest), b"test")


class HttpVectors(unittest.TestCase):
    def test_content_length(self) -> None:
        raw = b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\nX-Test: a\r\n\r\nhello"
        parsed = parse_http_response(raw)
        self.assertEqual(parsed["status"], 200)
        self.assertEqual(parsed["headers"]["x-test"], ["a"])
        self.assertEqual(parsed["body"], b"hello")

    def test_chunked(self) -> None:
        body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        self.assertEqual(decode_chunked(body), b"hello world")
        raw = b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body
        self.assertEqual(parse_http_response(raw)["body"], b"hello world")


class OnionVectors(unittest.TestCase):
    def test_address_roundtrip(self) -> None:
        public_key = bytes(range(32))
        address = encode_address(public_key)
        self.assertEqual(len(address), 62)
        parsed = parse_address(address)
        self.assertEqual(parsed["public_key"], public_key)
        self.assertEqual(parsed["version"], 3)
        self.assertEqual(parsed["hostname"], address)

    def test_pem_extraction(self) -> None:
        import base64

        payload = b"descriptor layer"
        text = (
            "encrypted\n-----BEGIN MESSAGE-----\n"
            + base64.encodebytes(payload).decode()
            + "-----END MESSAGE-----\n"
        )
        self.assertEqual(extract_pem_block(text, "encrypted"), payload)


if __name__ == "__main__":
    unittest.main()
