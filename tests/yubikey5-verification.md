# Pico FIDO host and hardware verification

The runner defaults to **read-only host commands** against hardware. It does not
reset applets, guess PINs, overwrite OTP slots or replace OpenPGP/PIV keys. Security
Domain is disabled and reported as SKIP.

## Commands

```bash
# Host regressions plus read-only checks of an explicitly selected device:
python3 tests/verify_yubikey5.py --serial 12345678

# Read-only hardware checks, without rebuilding host tests:
python3 tests/verify_yubikey5.py --skip-host --serial 12345678

# Host tests only; opens no hardware/helper connection:
python3 tests/verify_yubikey5.py --skip-hardware

# Temporary writes: use only one connected, expendable test device.
python3 tests/verify_yubikey5.py --allow-destructive --serial 12345678
```

Without `--serial`, read checks proceed only when exactly one identifiable device
is found. Write checks require both `--allow-destructive` and a matching serial,
with exactly one device connected. The serial is checked again through Management
on each CCID connection. HID interfaces use yubikey-manager's serial-bound
composite device, rather than selecting the first HID device in an enumeration.

Do not use a daily-use authenticator for write checks. A failed write or cleanup
can leave temporary records or consume management retry counts. Existing HSM Auth
credentials cause write checks to be skipped. Temporary OATH names are random and
checked against existing device IDs; cleanup deletes only credentials created by
the current run. No applet factory reset is automated.

## Coverage and results

- Host layer builds and runs all CTest cases, including applet security, storage
  fault injection, counter durability, USB transport and Python runner regressions.
- Optional macOS `authenticator-helper` layer uses only JSON-RPC `get` operations
  against the selected device. It does not terminate/restart the desktop GUI.
  Close the GUI manually if it holds an exclusive device connection.
- Hardware reads cover Management info, OATH listing when unlocked, OTP state,
  PIV version, OpenPGP key inventory, HSM Auth inventory, FIDO getInfo and OTP HID.
- Explicit write mode covers a temporary OATH TOTP credential and temporary
  symmetric/asymmetric HSM Auth credentials. HSM card cryptograms/receipts and
  session keys are independently derived with CMAC/X9.63, then compared.
- Destructive PIV/OTP/OpenPGP provisioning is a separate manual workflow on a
  dedicated test device. It is reported as SKIP by this runner.
- Each executed check prints PASS. Locked/unavailable/de-scoped checks print SKIP.
  Exceptions and failed assertions exit nonzero. A successful exit means executed
  checks passed; it never implies that skipped checks were covered.

Install `yubikey-manager`/`fido2` and their platform transport dependencies for the
system Python. On macOS, the runner can fall back to Yubico Authenticator's bundled
runtime through its existing small C launcher (requires clang). Missing helper
support is reported as SKIP; missing hardware dependencies fail hardware checks.

For static regression checks without any hardware:

```bash
python3 tests/verification_runner_test.py
```

## Host C Unit Tests (`ctest`)

In addition to live hardware testing, the repository includes 12 host C test suites. Eight cover storage containers, encryption providers, policy engines, and authorization state machines (`fido_object_provider_test`, `fido_object_authorization_test`, `fido_resident_container_test`, `fido_oath_container_test`, `fido_otp_container_test`, `object_store_test`, `object_crypto_provider_test`, `object_policy_test`). Four exercise production command handlers or parsers with host fixtures:

| Suite | Regression coverage |
| --- | --- |
| `piv_security_test` | Management authentication reflection, replay, malformed state transitions, touch policy, and valid 3DES/AES exchanges; F9 signing/ECDH and MOVE restrictions, ordinary key operations, and verified attestation certificate signatures. |
| `fido_client_pin_test` | Protocol 1/2 ciphertext lengths and output capacities, rejection before retry changes, in-place decryption, and valid PIN token requests. |
| `fido_oath_put_test` | Repeated-field overflow payloads, duplicate singleton fields, malformed TLVs, legacy Property/IMF compatibility, and maximum normalized lengths. |
| `hsmauth_list_test` | Complete 32-credential lists, bounded GET RESPONSE chunks, short/extended Le, snapshot invalidation, malformed stored labels, and existing inline responses. |

```bash
cmake -B build_emul -DENABLE_EMULATION=1 -DVIDPID=Yubikey -DENABLE_EDDSA=ON
cmake --build build_emul -j8
ctest --test-dir build_emul --output-on-failure
```

To run only these security regressions, use the same configured build and:

```bash
ctest --test-dir build_emul --output-on-failure \
  -R '^(piv_security_test|fido_client_pin_test|fido_oath_put_test|hsmauth_list_test)$'
```

For AddressSanitizer and UndefinedBehaviorSanitizer checks with GCC or Clang:

```bash
cmake -B build_sanitizers -DENABLE_EMULATION=1 -DVIDPID=Yubikey -DENABLE_EDDSA=ON \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build_sanitizers -j8
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build_sanitizers --output-on-failure
```

Leak detection is disabled above for compatibility with Apple's sanitizer runtime. The host fixtures replace persistent storage, hardware timing, user presence, and transport callbacks; they do not access a device. HSM LIST covers CCID/WCID dispatch and generic HID callback offsets, but does not establish HSM applet interoperability through the real HID router. Live hardware validation remains a separate layer.
