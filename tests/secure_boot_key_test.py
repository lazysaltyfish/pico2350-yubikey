#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Offline tests: create disposable host keys; never access a device."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("secure_boot_key", ROOT / "tools/secure_boot_key.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

# secp256k1's standard generator, independently specified coordinates for d=1.
GENERATOR = bytes.fromhex(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


def openssl(*args):
    return subprocess.run(["openssl", *map(str, args)], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout


class SecureBootKeyTests(unittest.TestCase):
    def test_known_private_scalar_one(self):
        # Explicit non-secret test key: SEC1 encoding of scalar one and G.
        der = (bytes.fromhex("30740201010420") + bytes(31) + b"\x01" +
               bytes.fromhex("a00706052b8104000aa14403420004") + GENERATOR)
        with tempfile.TemporaryDirectory() as temporary:
            key = Path(temporary) / "test.pem"
            key.write_bytes(b"-----BEGIN EC PRIVATE KEY-----\n" + base64.encodebytes(der) +
                            b"-----END EC PRIVATE KEY-----\n")
            self.assertEqual(MODULE.public_hash(key), hashlib.sha256(GENERATOR).digest())
            self.assertNotEqual(MODULE.public_hash(key), hashlib.sha256(b"\x04" + GENERATOR).digest())

    def test_custom_keys_and_output_consistency(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            digests = []
            for index in range(2):
                key = folder / f"key-{index}.pem"
                header = folder / "generated/secure_boot_key.h"
                otp = folder / "secure_boot.json"
                openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp256k1", "-out", key)
                MODULE.generate(key, header, otp)
                digest = MODULE.public_hash(key)
                digests.append(digest)
                self.assertEqual(bytes(json.loads(otp.read_text())["bootkey0"]), digest)
                self.assertIn(", ".join(f"0x{x:02x}" for x in digest), header.read_text())
                self.assertIn("PICO_SECURE_BOOT_KEY_CONFIGURED 1", header.read_text())
                self.assertNotIn("PRIVATE KEY", header.read_text() + otp.read_text())
                # Compressed public-point encoding must produce the same hash.
                compressed = folder / "compressed.pem"
                openssl("ec", "-in", key, "-conv_form", "compressed", "-out", compressed)
                self.assertEqual(MODULE.public_hash(compressed), digest)
                pkcs8 = folder / "pkcs8.pem"
                openssl("pkcs8", "-topk8", "-nocrypt", "-in", key, "-out", pkcs8)
                self.assertEqual(MODULE.public_hash(pkcs8), digest)
            self.assertNotEqual(digests[0], digests[1])

    def test_reject_unusable_signing_inputs_without_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            key = folder / "key.pem"
            openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp256k1", "-out", key)
            public = folder / "public.pem"
            openssl("pkey", "-in", key, "-pubout", "-out", public)
            encrypted = folder / "encrypted.pem"
            openssl("pkcs8", "-topk8", "-in", key, "-out", encrypted, "-passout", "pass:test")
            wrong_curve = folder / "p256.pem"
            openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", wrong_curve)
            malformed = folder / "invalid.pem"
            malformed.write_text("invalid private key")
            for invalid in (public, encrypted, wrong_curve, malformed):
                header, otp = folder / "no-header.h", folder / "no-otp.json"
                with self.assertRaises(ValueError):
                    MODULE.generate(invalid, header, otp)
                self.assertFalse(header.exists())
                self.assertFalse(otp.exists())
            with self.assertRaises(FileNotFoundError):
                MODULE.public_hash(folder / "missing.pem")


if __name__ == "__main__":
    unittest.main()
