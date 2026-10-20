#!/usr/bin/env python3
"""Derive RP2350 BOOTKEY metadata from the same private PEM used for signing.

Raspberry Pi picotool read_keys/seal hashes the 32-byte big-endian X followed
by the 32-byte big-endian Y, without the SEC1 0x04 point-format octet.
Only public key material is written to the generated files.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

K1_SPKI_PREFIX = bytes.fromhex("3056301006072a8648ce3d020106052b8104000a03420004")


def public_hash(key):
    """Validate a private secp256k1 key and return picotool's BOOTKEY digest."""
    key = Path(key).resolve(strict=True)
    # A fixed empty password prevents interactive prompts for encrypted keys.
    # The check also rejects invalid or public-only inputs before generating
    # artifacts. Do not relay OpenSSL diagnostics or private key contents.
    try:
        subprocess.run(
            ["openssl", "ec", "-in", str(key), "-passin", "pass:", "-check", "-noout"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        result = subprocess.run(
            ["openssl", "ec", "-in", str(key), "-passin", "pass:", "-pubout",
             "-conv_form", "uncompressed", "-outform", "DER"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError("secure boot requires a valid unencrypted secp256k1 private PEM key") from error
    der = result.stdout
    if len(der) != len(K1_SPKI_PREFIX) + 64 or not der.startswith(K1_SPKI_PREFIX):
        raise ValueError("secure boot requires the secp256k1 curve")
    return hashlib.sha256(der[len(K1_SPKI_PREFIX):]).digest()


def generate(key, header, otp_json):
    digest = public_hash(key)
    header = Path(header)
    otp_json = Path(otp_json)
    # CMake invokes this at configure time and tracks the key and script as
    # configure dependencies. These outputs contain no private scalar.
    header.parent.mkdir(parents=True, exist_ok=True)
    otp_json.parent.mkdir(parents=True, exist_ok=True)
    header.write_text(
        "/* Generated from SECURE_BOOT_PKEY; public digest only. */\n"
        "#ifndef PICO_SECURE_BOOT_KEY_H\n#define PICO_SECURE_BOOT_KEY_H\n"
        "#define PICO_SECURE_BOOT_KEY_CONFIGURED 1\n"
        "static const unsigned char pico_secure_boot_key_hash[32] = { " +
        ", ".join(f"0x{x:02x}" for x in digest) + " };\n#endif\n",
        encoding="utf-8",
    )
    otp_json.write_text(json.dumps({
        "boot_flags1": {"key_valid": 1},
        "bootkey0": list(digest),
        "crit1": {"secure_boot_enable": 1},
    }, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", required=True)
    parser.add_argument("--header", required=True)
    parser.add_argument("--json", required=True)
    args = parser.parse_args()
    try:
        generate(args.key, args.header, args.json)
    except (OSError, ValueError) as error:
        parser.exit(1, f"secure boot metadata generation failed: {error}\n")
