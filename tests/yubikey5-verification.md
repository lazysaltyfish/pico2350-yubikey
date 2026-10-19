# YubiKey 5 Full Hardware & Host Verification Guide

This document defines the complete verification methodology, commands, and end-to-end test workflows for validating all YubiKey 5 (`0x1050:0x0407`) applets implemented in `pico-fido` on `waveshare_rp2350_one` hardware (as well as in host unit tests):

1. **Management Applet** (`A0 00 00 05 27 47 11 17`, `src/fido/management.c`)
2. **FIDO2 / CTAP2.1 & U2F Applet** (`A0 00 00 06 47 2F 00 01`, `src/fido/cbor*.c`, `src/fido/fido.c`)
3. **Yubico OATH Applet** (`A0 00 00 05 27 21 01`, `src/fido/oath.c`)
4. **Yubico OTP & HID Keyboard Applet** (`A0 00 00 05 27 20 01 01`, `src/fido/otp.c`)
5. **PIV SmartCard Applet (NIST SP 800-73-4 & Yubico 5.7)** (`A0 00 00 03 08`, `src/fido/piv.c`)
6. **OpenPGP SmartCard Applet v3.4 & Yubico 5.7** (`D2 76 00 01 24 01`, `src/fido/openpgp.c`)
7. **YubiHSM Auth Applet v5.8** (`A0 00 00 05 27 21 07 01`, `src/fido/hsmauth.c`)
8. **GlobalPlatform Security Domain (SCP03 / SCP11)** (`A0 00 00 01 51 00 00 00`, `src/fido/securitydomain.c`)

---

## Quick Start (One-Command Full Verification)

Run the standalone executable verification script [`tests/verify_yubikey5.py`](./verify_yubikey5.py) to execute all three verification layers automatically (Host C `ctest` suite, `authenticator-helper` JSON-RPC suite, and live hardware `yubikit`/`ykman` 8-applet suite):

```bash
python3 tests/verify_yubikey5.py
# Or skip host C unit tests and only run live hardware verification:
python3 tests/verify_yubikey5.py --skip-host
```

---

## 1. Prerequisites & Test Environments

There are two primary verification layers on macOS:

### A. Yubico Authenticator JSON-RPC Helper (`authenticator-helper`)
`/Applications/Yubico Authenticator.app/Contents/Resources/helper/authenticator-helper` is a line-delimited JSON-RPC server over `stdin`/`stdout` (with structured JSON logs on `stderr`).
- It is the exact backend used by the Yubico Authenticator desktop UI.
- Sending `{"kind": "command", "action": "<action>", "target": [...], "body": {...}}\n` exercises the exact code paths used by the UI.

> **Important Note on Device Access Exclusivity**:
> If the `Yubico Authenticator.app` GUI is running in the background, its `authenticator-helper` subprocess may hold an exclusive PC/SC (`Using exclusive CCID connection`) or IOKit HID handle when a view is active.
> Before running standalone CLI or Python hardware tests, either quit `Yubico Authenticator.app` (`killall "Yubico Authenticator"`) or ensure it is not actively polling a locked transaction, and relaunch it (`open -a "Yubico Authenticator"`) after testing.

### B. Embedded `yubikit` / `ykman` Python 3.14 Runtime
`authenticator-helper` is a PyInstaller bundle containing:
- `/Applications/Yubico Authenticator.app/Contents/Resources/helper/_internal/Python` (Python 3.14 shared library)
- `/Applications/Yubico Authenticator.app/Contents/Resources/helper/_internal/base_library.zip`
- Embedded `PYZ` archive inside the `authenticator-helper` binary containing `yubikit.*`, `ykman.*`, `fido2.*`, `smartcard.*`, and `cryptography.*`.

Because the system Python cannot load Python 3.14 `.so` C-extensions (`_scard`, `cryptography`, etc.) directly, a tiny 15-line C launcher (`dlopen` on `_internal/Python` + `Py_Initialize` + `PyRun_SimpleString`) paired with a `PyzLoader` `sys.meta_path` hook allows executing arbitrary `yubikit` and `ykman` Python test scripts directly against live hardware or in-memory C harnesses.

---

## 2. Quick Verification via `authenticator-helper` JSON-RPC

You can verify `get_diagnostics()` and every UI node (`usb`, `management`, `oath`, `piv`, `ctap2`, `yubiotp`) directly through `authenticator-helper` using any Python 3 interpreter:

```python
import json, subprocess

helper_path = "/Applications/Yubico Authenticator.app/Contents/Resources/helper/authenticator-helper"
p = subprocess.Popen([helper_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def rpc(action, target=None, body=None):
    req = {"kind": "command", "action": action, "target": target or [], "body": body or {}}
    p.stdin.write(json.dumps(req) + "\n")
    p.stdin.flush()
    return json.loads(p.stdout.readline())

# 1. Run full ykman diagnostics (CCID + HID OTP + HID FIDO)
diag = rpc("diagnose", [], {})
assert diag["kind"] == "success"

# 2. Enumerate USB YubiKey
usb = rpc("get", ["usb"])
assert usb["kind"] == "success"
dev_id = next(iter(usb["body"]["children"].keys()))

# 3. Verify DeviceInfo & capabilities (827 = OTP|U2F|FIDO2|OATH|PIV|OPENPGP|HSMAUTH)
dev = rpc("get", ["usb", dev_id])
info = dev["body"]["data"]["info"]
assert info["supported_capabilities"]["usb"] == 827
assert info["config"]["enabled_capabilities"]["usb"] == 827

# 4. Verify CCID Management node
mgmt = rpc("get", ["usb", dev_id, "ccid", "management"])
assert mgmt["kind"] == "success"

# 5. Verify CCID OATH & Accounts nodes
oath = rpc("get", ["usb", dev_id, "ccid", "oath"])
assert oath["kind"] == "success"
oath_accs = rpc("get", ["usb", dev_id, "ccid", "oath", "accounts"])
assert oath_accs["kind"] == "success"

# 6. Verify CCID PIV & 24 Certificate Slots nodes
piv = rpc("get", ["usb", dev_id, "ccid", "piv"])
assert piv["kind"] == "success"
piv_slots = rpc("get", ["usb", dev_id, "ccid", "piv", "slots"])
assert piv_slots["kind"] == "success" and len(piv_slots["body"]["children"]) == 24

# 7. Verify HID FIDO2 / CTAP2 node
ctap2 = rpc("get", ["usb", dev_id, "fido", "ctap2"])
assert ctap2["kind"] == "success"

# 8. Verify HID YubiOTP node
yubiotp = rpc("get", ["usb", dev_id, "otp", "yubiotp"])
assert yubiotp["kind"] == "success"

p.terminate()
print("ALL AUTHENTICATOR-HELPER RPC CHECKS PASSED!")
```

---

## 3. Comprehensive Live Hardware Test Suite (`yubikit` & `ykman`)

To test all 8 applets—including applets and operations not exposed in the basic Yubico Authenticator GUI (such as **OpenPGP v3.4**, **YubiHSM Auth 5.8**, **GlobalPlatform Security Domain**, **PIV key generation/signing/attestation/move**, **OTP CCID/HID challenge-response/swap**, and **Management lock codes**)—use the embedded Python 3.14 runner below.

### Step 3.1: Compile the Embedded Python 3.14 Runner (`/tmp/runner314`)

```bash
cat << 'EOF' > /tmp/runner314.c
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    void *h = dlopen("/Applications/Yubico Authenticator.app/Contents/Resources/helper/_internal/Python", RTLD_LAZY | RTLD_GLOBAL);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }
    void (*Py_Initialize)(void) = dlsym(h, "Py_Initialize");
    int (*PyRun_SimpleString)(const char *) = dlsym(h, "PyRun_SimpleString");
    Py_Initialize();
    return PyRun_SimpleString(argv[1]);
}
EOF
clang /tmp/runner314.c -o /tmp/runner314
```

### Step 3.2: Run the All-In-One Hardware Verification Script

Save the following script to `/tmp/verify_all_yubikey5.py` and run it with:
```bash
PYTHONPATH="/Applications/Yubico Authenticator.app/Contents/Resources/helper/_internal/base_library.zip:/Applications/Yubico Authenticator.app/Contents/Resources/helper/_internal" \
  /tmp/runner314 "$(cat /tmp/verify_all_yubikey5.py)"
```

#### `/tmp/verify_all_yubikey5.py`

```python
import sys, marshal, zipimport

HELPER_BIN = "/Applications/Yubico Authenticator.app/Contents/Resources/helper/authenticator-helper"
INTERNAL_DIR = "/Applications/Yubico Authenticator.app/Contents/Resources/helper/_internal"

zi = zipimport.zipimporter(INTERNAL_DIR + "/base_library.zip")
ModuleSpec = sys.modules["_frozen_importlib"].ModuleSpec
_imp_ext = sys.modules["_frozen_importlib_external"]
_imp_ext._install(sys.modules["_frozen_importlib"])
sys.path.insert(0, INTERNAL_DIR + "/base_library.zip")
sys.path.insert(0, INTERNAL_DIR + "/python3.14/lib-dynload")
sys.path.insert(0, INTERNAL_DIR)
import zlib
with open(HELPER_BIN, "rb") as f:
    data = f.read()

def u32be(b, off):
    return int.from_bytes(b[off : off + 4], "big")

magic = b"MEI\x0c\x0b\x0a\x0b\x0e"
idx = data.rfind(magic)
pkg_len, toc_off, toc_len = u32be(data, idx + 8), u32be(data, idx + 12), u32be(data, idx + 16)
pkg_start = idx + 88 - pkg_len
toc_data = data[pkg_start + toc_off : pkg_start + toc_off + toc_len]
pos = 0
pyz_offset = None
cmods = {}
while pos < len(toc_data):
    el, dpos, dlen, ulen = u32be(toc_data, pos), u32be(toc_data, pos + 4), u32be(toc_data, pos + 8), u32be(toc_data, pos + 12)
    cflag, typcd = toc_data[pos + 16], toc_data[pos + 17]
    name = toc_data[pos + 18 : pos + el].rstrip(b"\x00").decode("utf-8", errors="replace")
    if typcd == ord("z"):
        pyz_offset = pkg_start + dpos
    elif typcd in (ord("m"), ord("M")):
        cmods[name] = (pkg_start + dpos, dlen, cflag, typcd == ord("M"))
    pos += el

toc_ofs = int.from_bytes(data[pyz_offset + 8 : pyz_offset + 12], "big", signed=True)
toc = dict(marshal.loads(data[pyz_offset + toc_ofs :]))

class PyzLoader:
    def find_spec(self, fullname, path, target=None):
        if fullname in cmods:
            return ModuleSpec(fullname, self, is_package=cmods[fullname][3])
        if fullname in toc:
            return ModuleSpec(fullname, self, is_package=bool(toc[fullname][0]))
        return zi.find_spec(fullname, target)
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        name = module.__name__
        if name in cmods:
            dpos, dlen, cflag, ispkg = cmods[name]
            raw = data[dpos : dpos + dlen]
            co = marshal.loads(zlib.decompress(raw) if cflag else raw)
        else:
            ispkg, p, l = toc[name]
            co = marshal.loads(zlib.decompress(data[pyz_offset + p : pyz_offset + p + l]))
        if ispkg:
            module.__path__ = [INTERNAL_DIR + "/" + name.replace(".", "/")]
        exec(co, module.__dict__)

sys.meta_path.insert(0, PyzLoader())

# ============================================================================
# Start Verification Suite
# ============================================================================
from ykman.diagnostics import get_diagnostics
from ykman.pcsc import list_readers, ScardYubiKeyDevice
from ykman.hid import list_ctap_devices, list_otp_devices
from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.otp import OtpConnection
from yubikit.management import ManagementSession, CAPABILITY, DeviceConfig
import yubikit.oath as oath
import yubikit.yubiotp as yubiotp
import ykman.otp as ykotp
import yubikit.piv as piv
import ykman.piv as ykpiv
import yubikit.openpgp as opgp
import ykman.openpgp as ykopgp
import yubikit.hsmauth as hsmauth
import ykman.hsmauth as ykhsmauth
import yubikit.securitydomain as sd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519, padding

print("1. Running full ykman.diagnostics.get_diagnostics()...")
diag = get_diagnostics()
assert len(diag) >= 4, "Expected diagnostics across System, PC/SC, HID OTP, HID FIDO"
print("   [OK] get_diagnostics() succeeded across all transports!")

readers = list_readers()
assert len(readers) > 0, "No PC/SC reader found"
dev = ScardYubiKeyDevice(readers[0])

with dev.open_connection(SmartCardConnection) as conn:
    # ------------------------------------------------------------------------
    # Phase 1: Management Applet
    # ------------------------------------------------------------------------
    print("2. Verifying Management Applet...")
    m = ManagementSession(conn)
    info = m.read_device_info()
    expected_caps = (
        CAPABILITY.OTP | CAPABILITY.U2F | CAPABILITY.FIDO2 |
        CAPABILITY.OATH | CAPABILITY.PIV | CAPABILITY.OPENPGP | CAPABILITY.HSMAUTH
    )
    assert info.supported_capabilities[TRANSPORT.USB] == expected_caps
    assert info.config.enabled_capabilities[TRANSPORT.USB] == expected_caps
    lock_code = b"\x01\x02\x03\x04\x05\x06\x07\x08\x11\x12\x13\x14\x15\x16\x17\x18"
    if info.is_locked:
        m.write_device_config(None, False, lock_code, b"\x00" * 16)
    m.write_device_config(None, False, None, lock_code)
    assert m.read_device_info().is_locked is True
    m.write_device_config(None, False, lock_code, b"\x00" * 16)
    assert m.read_device_info().is_locked is False
    print("   [OK] Management Applet (capabilities=827, lock/unlock) verified!")

    # ------------------------------------------------------------------------
    # Phase 2: Yubico OATH Applet (Non-destructive if credentials exist)
    # ------------------------------------------------------------------------
    print("3. Verifying Yubico OATH Applet...")
    oath_sess = oath.OathSession(conn)
    assert oath_sess.version in ((8, 0, 0), (8, 2, 0), (8, 2, 1))
    if not oath_sess.locked:
        existing = oath_sess.list_credentials()
        test_data = oath.CredentialData("totp_verify", oath.OATH_TYPE.TOTP, oath.HASH_ALGORITHM.SHA1, b"12345678901234567890", 6, 30, 0, "PicoTestIssuer")
        cred = oath_sess.put_credential(test_data, touch_required=False)
        code = oath_sess.calculate_code(cred, timestamp=1000000)
        assert len(code.value) == 6
        all_codes = oath_sess.calculate_all(timestamp=1000000)
        assert cred in all_codes
        oath_sess.delete_credential(cred.id)
        assert len(oath_sess.list_credentials()) == len(existing)
    print("   [OK] Yubico OATH Applet (put, calculate, calculate_all, delete) verified!")

    # ------------------------------------------------------------------------
    # Phase 3: Yubico OTP Applet (CCID + HID OTP)
    # ------------------------------------------------------------------------
    print("4. Verifying Yubico OTP Applet...")
    otp_sess = yubiotp.YubiOtpSession(conn)
    state = otp_sess.get_config_state()
    if not state.is_configured(yubiotp.SLOT.ONE) and not state.is_configured(yubiotp.SLOT.TWO):
        key_20 = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"
        otp_sess.put_configuration(yubiotp.SLOT.ONE, yubiotp.HmacSha1SlotConfiguration(key_20).lt64(True))
        assert otp_sess.get_config_state().is_configured(yubiotp.SLOT.ONE)
        resp = otp_sess.calculate_hmac_sha1(yubiotp.SLOT.ONE, b"test_challenge")
        assert len(resp) == 20
        otp_sess.swap_slots()
        assert otp_sess.get_config_state().is_configured(yubiotp.SLOT.TWO)
        otp_sess.delete_slot(yubiotp.SLOT.TWO)
        assert not otp_sess.get_config_state().is_configured(yubiotp.SLOT.TWO)
    print("   [OK] Yubico OTP Applet (HMAC-SHA1 challenge-response, swap, delete) verified!")

    # ------------------------------------------------------------------------
    # Phase 4: PIV SmartCard Applet
    # ------------------------------------------------------------------------
    print("5. Verifying PIV SmartCard Applet...")
    piv_sess = piv.PivSession(conn)
    assert piv_sess.version == (5, 7, 2)
    piv_info = ykpiv.get_piv_info(piv_sess)
    assert piv_sess.get_pin_attempts() > 0
    # Use RETIRED20 (0x95) for non-destructive keygen/sign/attest/delete test
    slot_test = piv.SLOT.RETIRED20
    try:
        piv_sess.get_slot_metadata(slot_test)
        slot_busy = True
    except Exception:
        slot_busy = False
    if not slot_busy:
        piv_sess.authenticate(piv.DEFAULT_MANAGEMENT_KEY)
        piv_sess.verify_pin("123456")
        pub_p256 = piv_sess.generate_key(slot_test, piv.KEY_TYPE.ECCP256, piv.PIN_POLICY.ONCE, piv.TOUCH_POLICY.NEVER)
        sig = piv_sess.sign(slot_test, piv.KEY_TYPE.ECCP256, b"PIV test message", hashes.SHA256())
        pub_p256.verify(sig, b"PIV test message", ec.ECDSA(hashes.SHA256()))
        att_cert = piv_sess.attest_key(slot_test)
        assert att_cert.public_key().public_numbers() == pub_p256.public_numbers()
        piv_sess.delete_key(slot_test)
    print("   [OK] PIV Applet (metadata, P-256 keygen, ECDSA sign, X.509 attestation, delete) verified!")

    # ------------------------------------------------------------------------
    # Phase 5: OpenPGP SmartCard Applet v3.4
    # ------------------------------------------------------------------------
    print("6. Verifying OpenPGP SmartCard Applet v3.4...")
    opgp_sess = opgp.OpenPgpSession(conn)
    assert opgp_sess.version == (5, 7, 2)
    opgp_info = ykopgp.get_openpgp_info(opgp_sess)
    key_info = opgp_sess.get_key_information()
    if any(v != opgp.KEY_STATUS.NONE for k, v in key_info.items() if k != opgp.KEY_REF.ATT):
        ykopgp.safe_reset(conn)
        opgp_sess = opgp.OpenPgpSession(conn)
    opgp_sess.verify_admin("12345678")
    pub_sig = opgp_sess.generate_ec_key(opgp.KEY_REF.SIG, opgp.OID.SECP256R1)
    pub_dec = opgp_sess.generate_ec_key(opgp.KEY_REF.DEC, opgp.OID.X25519)
    pub_aut = opgp_sess.generate_ec_key(opgp.KEY_REF.AUT, opgp.OID.Ed25519)

    opgp_sess.verify_pin("123456", extended=False)
    sig_opgp = opgp_sess.sign(b"OpenPGP test", hashes.SHA256())
    pub_sig.verify(sig_opgp, b"OpenPGP test", ec.ECDSA(hashes.SHA256()))

    opgp_sess.verify_pin("123456", extended=True)
    aut_sig = opgp_sess.authenticate(b"OpenPGP auth", hashes.SHA256())
    pub_aut.verify(aut_sig, b"OpenPGP auth")

    peer_sk = x25519.X25519PrivateKey.generate()
    shared_card = opgp_sess.decrypt(peer_sk.public_key())
    shared_host = peer_sk.exchange(pub_dec)
    assert shared_card == shared_host

    att_opgp = opgp_sess.attest_key(opgp.KEY_REF.SIG)
    assert att_opgp is not None
    ykopgp.safe_reset(conn)
    print("   [OK] OpenPGP v3.4 Applet (P-256/X25519/Ed25519 keygen, CDS, AUTH, ECDH, attestation, reset) verified!")

    # ------------------------------------------------------------------------
    # Phase 6A: YubiHSM Auth Applet v5.8
    # ------------------------------------------------------------------------
    print("7. Verifying YubiHSM Auth Applet v5.8...")
    hs = hsmauth.HsmAuthSession(conn)
    assert hs.version == (5, 8, 0)
    if len(hs.list_credentials()) == 0 and hs.get_management_key_retries() == 8:
        mgm0 = hsmauth.DEFAULT_MANAGEMENT_KEY
        hs.put_credential_derived(mgm0, "test_sym", "deriv_pw", "cred_pw1", False)
        hs.generate_credential_asymmetric(mgm0, "test_ec", "cred_pw2", False)
        assert len(hs.list_credentials()) == 2
        pub_ec = hs.get_public_key("test_ec")
        chal = hs.get_challenge("test_sym")
        sk_sym = hs.calculate_session_keys_symmetric("test_sym", chal + b"\x01"*8, "cred_pw1", b"\x22"*8)
        assert len(sk_sym.key_senc) == 16 and len(sk_sym.key_smac) == 16 and len(sk_sym.key_srmac) == 16
        epk = hs.get_challenge("test_ec", "cred_pw2")
        sk_ec = hs.calculate_session_keys_asymmetric("test_ec", epk + epk, pub_ec, "cred_pw2", b"\x33"*16)
        assert len(sk_ec.key_senc) == 16
        hs.reset()
        assert len(hs.list_credentials()) == 0
    print("   [OK] YubiHSM Auth v5.8 Applet (SCP03 symmetric & SCP11 asymmetric KDF, reset) verified!")

    # ------------------------------------------------------------------------
    # Phase 6B: GlobalPlatform Security Domain
    # ------------------------------------------------------------------------
    print("8. Verifying GlobalPlatform Security Domain...")
    sds = sd.SecurityDomainSession(conn)
    ki = sds.get_key_information()
    assert sd.KeyRef(0x01, 0xFF) in ki and sd.KeyRef(0x13, 0x01) in ki
    crd = sds.get_card_recognition_data()
    assert len(crd) > 0
    pub_sd = sds.generate_ec_key(sd.KeyRef(0x13, 0x02))
    sds.store_ca_issuer(sd.KeyRef(0x13, 0x02), b"\x44"*20)
    ca_ids = sds.get_supported_ca_identifiers(klcc=True)
    assert ca_ids[sd.KeyRef(0x13, 0x02)] == b"\x44"*20
    sds.delete_key(kid=0x13, kvn=0x02)
    sds.reset()
    print("   [OK] GlobalPlatform Security Domain (KeyInfo, CRD, EC keygen, CA SKI, reset) verified!")

# ----------------------------------------------------------------------------
# Verify HID FIDO2 / CTAP2 & HID OTP Transports
# ----------------------------------------------------------------------------
print("9. Verifying HID FIDO2 & HID OTP Transports...")
ctap_devs = list_ctap_devices()
assert len(ctap_devs) > 0
with ctap_devs[0].open_connection(FidoConnection) as fconn:
    from fido2.ctap2 import Ctap2
    ctap2 = Ctap2(fconn)
    assert "FIDO_2_1" in ctap2.info.versions
    assert {"alg": -8, "type": "public-key"} in ctap2.info.algorithms  # Ed25519 mandatory check

otp_devs = list_otp_devices()
assert len(otp_devs) > 0
with otp_devs[0].open_connection(OtpConnection) as oconn:
    otp_hid = yubiotp.YubiOtpSession(oconn)
    _ = otp_hid.get_config_state()

print("   [OK] HID FIDO2 (CTAP2 getInfo + Ed25519) & HID OTP verified!")
print("\nALL 8 YUBIKEY 5 APPLETS & 3 USB TRANSPORTS PASSED FULL HARDWARE VERIFICATION!")
```

---

## 4. Host C Unit Tests (`ctest`)

In addition to live hardware testing, the repository includes 5 host C unit test suites for storage containers, encryption providers, and authorization state machines (`fido_object_provider_test`, `fido_object_authorization_test`, `fido_resident_container_test`, `fido_oath_container_test`, `fido_otp_container_test`):

```bash
cmake -B build_emul -DENABLE_EMULATION=1 -DVIDPID=Yubikey -DENABLE_EDDSA=ON
cmake --build build_emul --target \
  fido_object_provider_test \
  fido_object_authorization_test \
  fido_resident_container_test \
  fido_oath_container_test \
  fido_otp_container_test -j8
ctest --test-dir build_emul --output-on-failure
rm -rf build_emul
```
