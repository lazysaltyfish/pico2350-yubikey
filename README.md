# Pico-YubiKey (RP2350)

**Pico-YubiKey** is a dedicated **RP2350** hardware security key firmware that implements full protocol and applet alignment with **YubiKey 5 (`0x1050:0x0407`, Firmware 5.7 / 5.8)**.

Unlike the upstream `pico-fido` project (which targeted generic RP2040 and ESP32 boards with partial FIDO/OATH/OTP support), this project is purpose-built for **RP2350** (`waveshare_rp2350_one`, `rp2350-arm-s`) and delivers a complete, multi-transport YubiKey 5 implementation across **USB CCID SmartCard**, **USB HID FIDO2/U2F**, and **USB HID OTP Keyboard** interfaces—fully compatible with **Yubico Authenticator**, **`ykman` (`yubikey-manager`)**, **OpenSC**, **GnuPG**, **OpenSSH (`ed25519-sk` / `ecdsa-sk`)**, and **WebAuthn**.

---

## Supported YubiKey 5 Applets & Capabilities

| Applet | AID / Interface | Version | Key Capabilities |
|--------|-----------------|---------|------------------|
| **Management** | `A0 00 00 05 27 47 11 17`<br>CCID + CTAPHID (`0xC0`/`0xC2`/`0xC3`) + OTP (`0x11`/`0x13`/`0x15`) | 5.7.x | Dynamic USB/NFC capability bitmasks (`CAP_OTP`, `CAP_U2F`, `CAP_FIDO2`, `CAP_OATH`, `CAP_PIV`, `CAP_OPENPGP`, `CAP_HSMAUTH`), 16-byte configuration lock code (`TAG_CONFIG_LOCK` / `TAG_UNLOCK`), auto-eject & challenge-response timeouts, legacy composite mode switching (`INS_SET_MODE`), and device-wide factory reset (`INS_DEVICE_RESET`). |
| **FIDO2 / WebAuthn & U2F** | `A0 00 00 06 47 2F 00 01`<br>USB HID FIDO + CCID | CTAP 2.3 / CTAP 1 | Discoverable credentials (Passkeys), `Ed25519` (`ed25519-sk`), `ES256` (`P-256`), `ES384` (`P-384`), `ES512` (`P-521`), `ES256K` (`secp256k1`), PIN/UV Auth Protocols v1 & v2, `credProtect`, `hmac-secret`, `largeBlobKey` / `largeBlobs`, `credBlob`, `minPinLength`, Enterprise Attestation, Pico Vault authenticated export/import, and seamless in-place migration from legacy Pico FIDO v6.x `EF_MKEK` & resident credentials. |
| **Yubico OATH** | `A0 00 00 05 27 21 01`<br>USB CCID | 5.7.x | TOTP & HOTP credentials, `HMAC-SHA1` / `HMAC-SHA256` / `HMAC-SHA512`, 6 / 7 / 8 digits, PBKDF2-derived access code authentication (`INS_VALIDATE` / `INS_SET_CODE`), per-credential hardware touch requirement with configurable timeout, and both 2-byte (`0x78 <prop>`) and 3-byte (`0x78 0x01 <prop>`) property TLV normalization. |
| **Yubico OTP** | `A0 00 00 05 27 20 01 01`<br>USB HID Keyboard + CCID | 5.7.x | Dual programmable slots (Slot 1 short press `< 1500 ms`, Slot 2 long press `>= 1500 ms`), Yubico AES-128 modhex OTP, HMAC-SHA1 & Yubico OTP Challenge-Response, OATH-HOTP keyboard emission, Static Password scancode emission, `SLOT_SWAP`, 6-byte access codes, NDEF configuration, custom scan maps, and `prog_seq` state tracking. |
| **PIV SmartCard** | `A0 00 00 03 08`<br>USB CCID | 5.7.2 | NIST SP 800-73-4 & Yubico PIV 5.7 extensions: 25 key slots (`9A`, `9C`, `9D`, `9E`, retired `82..95`, `F9` attestation) & 35 data objects; `RSA-1024/2048/3072/4096`, `ECC P-256/P-384`, `Ed25519`, `X25519`; `3DES` / `AES-128` / `AES-192` / `AES-256` 9B Management Key single & mutual auth; X.509 slot attestation (`0xF9`), metadata (`0xF7`), key move/delete (`0xF6`), and PIN (`NEVER`/`ONCE`/`ALWAYS`) & touch (`NEVER`/`ALWAYS`/`CACHED`) policies. |
| **OpenPGP SmartCard** | `D2 76 00 01 24 01`<br>USB CCID | v3.4 (5.7.2) | 4 key slots (`SIG`, `DEC`, `AUT`, `ATT`), algorithm negotiation (`0xFA`) across `RSA-2048/3072/4096`, `secp256r1`, `secp256k1`, `secp384r1`, `secp521r1`, `brainpoolP256r1/P384r1/P512r1`, `Ed25519`, `X25519`; Extended Header List key import (`0xDB`), `PSO:CDS`, `PSO:DECIPHER`, `INTERNAL AUTHENTICATE`; OpenPGP KDF (`0xF9` `KdfNone` & `KdfIterSaltedS2k`), multi-slot certificates (`SELECT DATA` `0xA5`), Private DOs (`0101..0104`), UIF touch policies, X.509 attestation (`0xFB`), and `TERMINATE` / `ACTIVATE`. |
| **YubiHSM Auth** | `A0 00 00 05 27 21 07 01`<br>USB CCID | 5.8.0 | Up to 32 labeled credentials; AES-128 symmetric (`SCP03` CMAC-AES-128 KDF for `S-ENC`, `S-MAC`, `S-RMAC`) and `EC P-256` asymmetric (`SCP11c` mutual ECDH + X9.63 SHA-256 KDF) session key derivation; 16-byte management key & per-credential passwords with 8-attempt retry counters and optional hardware touch enforcement. |
| **Security Domain** | `A0 00 00 01 51 00 00 00`<br>USB CCID | GP 2.3 | GlobalPlatform Security Domain (`SCP03` / `SCP11`): Key Information (`0x00E0`), Card Recognition Data (`0x0066`), `CA-KLOC` / `CA-KLCC` Subject Key Identifiers (`0xFF33` / `0xFF34`), Certificate Store bundles (`0xBF21`), on-card ECC key generation across NIST & Brainpool curves (`0xF1`), key deletion (`0xE4`), and Security Domain reset. |

---

## RP2350 Hardware Security Architecture

- **Target MCU & Board**: Raspberry Pi **RP2350** (`waveshare_rp2350_one`, Cortex-M33 `rp2350-arm-s`, 4 MB Flash).
- **Hardware OTP Master Key Storage**:
  - Uses RP2350 hardware One-Time Programmable (OTP) rows (`0xE90` for `otp_key_1` and `0xE80` for `otp_key_2`, with automatic migration from legacy rows `0xEF0`/`0xED0`) to store hardware-bound root secrets inaccessible to external flash dumps when RP2350 Secure Boot and Secure Lock are enabled.
- **Authenticated Encryption at Rest**:
  - All sensitive applet states and private keys across FIDO2 (`EF_KEY_DEV`, `EF_CRED`, `EF_RP`), OATH, OTP, PIV (`EF_PIV_STATE`, `EF_PIV_KEY_BASE`), OpenPGP (`EF_OPENPGP_KEY_BASE`), and YubiHSM Auth (`EF_HSMAUTH_CRED_BASE`) are wrapped at rest using **AES-256-GCM** with per-applet HKDF/SHA-256 master keys derived from the hardware root key.

---

## Build & Flash Instructions

### Required Build Options

- `-DPICO_BOARD=waveshare_rp2350_one`: Targets the Waveshare RP2350-One board (`rp2350-arm-s`).
- `-DVIDPID=Yubikey`: Maps to `Yubikey5` (`0x1050:0x0407`) composite USB descriptors (HID FIDO + HID OTP Keyboard + CCID SmartCard) for out-of-the-box recognition by Yubico Authenticator and `ykman`.
- `-DENABLE_EDDSA=ON`: **Mandatory** for `Ed25519` support across FIDO2 (`ed25519-sk` Passkeys), PIV (`0xE0`), and OpenPGP v3.4 (`EdDSA`).

### Option 1: Build with Local Docker Container (`pico-rp2350-builder`)

```bash
docker run --rm -v "$PWD":/workspace -w /workspace pico-rp2350-builder bash -c "
  cmake -B build_waveshare \
    -DPICO_BOARD=waveshare_rp2350_one \
    -DPICO_SDK_PATH=/opt/pico-sdk \
    -DVIDPID=Yubikey \
    -DENABLE_EDDSA=ON && \
  cmake --build build_waveshare -j8
"
```

### Option 2: Build with Host CMake & Pico SDK

```bash
git submodule update --init --recursive
cmake -B build_waveshare \
  -DPICO_BOARD=waveshare_rp2350_one \
  -DVIDPID=Yubikey \
  -DENABLE_EDDSA=ON
cmake --build build_waveshare -j8
```

### Flashing

1. Hold the `BOOTSEL` button on the RP2350 board while connecting it via USB (or trigger `bootsel` reboot).
2. Copy `build_waveshare/pico_fido.uf2` to the mounted `RP2350` USB mass storage volume.

---

## Verification & Testing

A full three-layer automated verification suite is included to validate all 8 YubiKey 5 applets across host unit tests, the Yubico Authenticator desktop JSON-RPC backend (`authenticator-helper`), and live hardware `yubikit`/`ykman` end-to-end tests:

```bash
# Run Host C unit tests + authenticator-helper JSON-RPC + live hardware 8-applet verification
python3 tests/verify_yubikey5.py

# Skip Host C unit tests and run live hardware verification only
python3 tests/verify_yubikey5.py --skip-host
```

See [`tests/yubikey5-verification.md`](./tests/yubikey5-verification.md) for detailed test architecture and per-applet verification procedures.

---

## License & Attribution

- **License**: Released under the **GNU Affero General Public License v3.0 (AGPL-3.0-only)**. See [`LICENSE`](./LICENSE) for full terms.
- **Copyright**:
  - Copyright (c) 2026 `lazysaltyfish` (RP2350 architecture focus, YubiKey 5 Management, PIV 5.7, OpenPGP v3.4, YubiHSM Auth 5.8, GlobalPlatform Security Domain, OATH/OTP alignment, and legacy v6.x migration).
  - Derived from [polhenarejos/pico-fido](https://github.com/polhenarejos/pico-fido) — Copyright (c) 2022 Pol Henarejos.
