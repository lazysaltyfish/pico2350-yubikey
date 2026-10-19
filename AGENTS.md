# AGENTS.md — Pico FIDO Workspace Guide

## Hardware & Target Configuration

- **Board**: `waveshare_rp2350_one` (RP2350, `rp2350-arm-s` platform, 4 MB Flash)
- **USB VID/PID**: `Yubikey` (`0x1050:0x0407`) for Yubico Authenticator compatibility
- **Required Crypto Option**: `-DENABLE_EDDSA=ON` (**Mandatory**)

> **IMPORTANT (`ENABLE_EDDSA=ON`)**:
> This device stores resident credentials using `Ed25519` (`FIDO2_CURVE_ED25519` / `FIDO2_ALG_EDDSA`, e.g. OpenSSH `ed25519-sk` keys under `ssh:`).
> By default, `pico-keys-sdk/cmake/options.cmake` sets `ENABLE_EDDSA` to `OFF`. If compiled without `-DENABLE_EDDSA=ON`, `fido_load_key()` returns `CTAP2_ERR_UNSUPPORTED_ALGORITHM` (`0x26`), which `cbor_cred_mgmt()` maps to `CTAP2_ERR_NOT_ALLOWED` (`0x30`), breaking credential enumeration and causing Yubico Authenticator to hang when loading Passkeys.

---

## Standard Build Instructions

### Using Local Docker Builder (`pico-rp2350-builder`)

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

### Using Host CMake Directly

```bash
cmake -B build_waveshare \
  -DPICO_BOARD=waveshare_rp2350_one \
  -DVIDPID=Yubikey \
  -DENABLE_EDDSA=ON
cmake --build build_waveshare -j8
```

Output firmware: `build_waveshare/pico_fido.uf2`

---

## Architecture & Migration Notes

1. **RP2350 Hardware OTP Key Layout (`pico-keys-sdk/src/otp/otp_rp2350.c`)**:
   - Pico FIDO v8.0+ runs `otp_migrate_chaff()`, which migrates `otp_key_1` from OTP row `0xEF0` (`0x40131de0`) to `0xE90` (`0x40131d20`) and `otp_key_2` from `0xED0` (`0x40131da0`) to `0xE80` (`0x40131d00`), and overwrites the old OTP rows with `0xFF`.
2. **Legacy v6.x Compatibility (`dev` branch)**:
   - Supports legacy `EF_MKEK` (`0xCC0F`) unwrapping for 32-byte `EF_KEY_DEV` (`0xCC00`) and automatic migration to v8.0 format (`0x01`/`0x03`) + encrypted `EF_RP` (`0xD000+`).
   - Preserves full `cred_id` as `cred->residentId` for legacy v6.x resident credentials (`EF_CRED`, `0xCF00+`) that do not have a 42-byte `cred_idr` prefix.
   - Preserves `apdu.rdata`, `apdu.header`, and `ctap_req` across `driver_init_hid()` inside `cmd_cbor()` and `cmd_vendor()` for CCID-wrapped CTAP CBOR commands.

---

## YubiKey 5 Full Applet Verification Guide

To run the complete automated verification suite (Host C unit tests + `authenticator-helper` JSON-RPC + live hardware end-to-end tests across all 8 YubiKey 5 applets), run:

```bash
python3 tests/verify_yubikey5.py
```

For the detailed architecture, commands, and individual applet test breakdown, see [`tests/yubikey5-verification.md`](./tests/yubikey5-verification.md).
