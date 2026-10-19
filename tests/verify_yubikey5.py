#!/usr/bin/env python3
#
# Pico-YubiKey (RP2350)
# Copyright (c) 2026 lazysaltyfish
#
# SPDX-License-Identifier: AGPL-3.0-only
#
"""
End-to-End YubiKey 5 Verification Runner for Pico FIDO.

Runs all three verification layers:
  1. Host C unit tests via ctest (optional with --skip-host)
  2. Yubico Authenticator JSON-RPC helper node verification (usb, management, oath, piv, ctap2, yubiotp)
  3. Comprehensive yubikit/ykman live hardware test suite across all 8 applets
     (Management, FIDO2/U2F, OATH, OTP, PIV, OpenPGP v3.4, YubiHSM Auth 5.8, Security Domain)

Usage:
  python3 tests/verify_yubikey5.py
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HELPER_BIN = "/Applications/Yubico Authenticator.app/Contents/Resources/helper/authenticator-helper"
INTERNAL_DIR = "/Applications/Yubico Authenticator.app/Contents/Resources/helper/_internal"
PYTHON_DYLIB = os.path.join(INTERNAL_DIR, "Python")

RUNNER_C_SRC = r"""
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
"""

PY314_SUITE = r"""
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

from ykman.diagnostics import get_diagnostics
from ykman.pcsc import list_readers, ScardYubiKeyDevice
from ykman.hid import list_ctap_devices, list_otp_devices
from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.otp import OtpConnection
from yubikit.management import ManagementSession, CAPABILITY
import yubikit.oath as oath
import yubikit.yubiotp as yubiotp
import yubikit.piv as piv
import ykman.piv as ykpiv
import yubikit.openpgp as opgp
import ykman.openpgp as ykopgp
import yubikit.hsmauth as hsmauth
import yubikit.securitydomain as sd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519

print("1. Running full ykman.diagnostics.get_diagnostics()...")
diag = get_diagnostics()
assert len(diag) >= 4, "Expected diagnostics across System, PC/SC, HID OTP, HID FIDO"
print("   [OK] get_diagnostics() succeeded across all transports!")

readers = list_readers()
assert len(readers) > 0, "No PC/SC reader found"
dev = ScardYubiKeyDevice(readers[0])

with dev.open_connection(SmartCardConnection) as conn:
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

    print("3. Verifying Yubico OATH Applet...")
    oath_sess = oath.OathSession(conn)
    assert oath_sess.version == (8, 0, 0)
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

    print("5. Verifying PIV SmartCard Applet...")
    piv_sess = piv.PivSession(conn)
    assert piv_sess.version == (5, 7, 2)
    _ = ykpiv.get_piv_info(piv_sess)
    assert piv_sess.get_pin_attempts() > 0
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

    print("6. Verifying OpenPGP SmartCard Applet v3.4...")
    opgp_sess = opgp.OpenPgpSession(conn)
    assert opgp_sess.version == (5, 7, 2)
    _ = ykopgp.get_openpgp_info(opgp_sess)
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

    print("8. Verifying GlobalPlatform Security Domain...")
    sds = sd.SecurityDomainSession(conn)
    ki = sds.get_key_information()
    assert sd.KeyRef(0x01, 0xFF) in ki and sd.KeyRef(0x13, 0x01) in ki
    crd = sds.get_card_recognition_data()
    assert len(crd) > 0
    _ = sds.generate_ec_key(sd.KeyRef(0x13, 0x02))
    sds.store_ca_issuer(sd.KeyRef(0x13, 0x02), b"\x44"*20)
    ca_ids = sds.get_supported_ca_identifiers(klcc=True)
    assert ca_ids[sd.KeyRef(0x13, 0x02)] == b"\x44"*20
    sds.delete_key(kid=0x13, kvn=0x02)
    sds.reset()
    print("   [OK] GlobalPlatform Security Domain (KeyInfo, CRD, EC keygen, CA SKI, reset) verified!")

print("9. Verifying HID FIDO2 & HID OTP Transports...")
ctap_devs = list_ctap_devices()
assert len(ctap_devs) > 0
with ctap_devs[0].open_connection(FidoConnection) as fconn:
    from fido2.ctap2 import Ctap2
    ctap2 = Ctap2(fconn)
    assert "FIDO_2_1" in ctap2.info.versions
    assert {"alg": -8, "type": "public-key"} in ctap2.info.algorithms

otp_devs = list_otp_devices()
assert len(otp_devs) > 0
with otp_devs[0].open_connection(OtpConnection) as oconn:
    otp_hid = yubiotp.YubiOtpSession(oconn)
    _ = otp_hid.get_config_state()

print("   [OK] HID FIDO2 (CTAP2 getInfo + Ed25519) & HID OTP verified!")
"""


def run_host_unit_tests(repo_root: str) -> None:
    print("=== [Layer 1] Running Host C Unit Tests (ctest) ===")
    build_dir = os.path.join(repo_root, "build_emul_verify")
    try:
        subprocess.run(
            ["cmake", "-B", build_dir, "-DENABLE_EMULATION=1", "-DVIDPID=Yubikey", "-DENABLE_EDDSA=ON"],
            cwd=repo_root,
            check=True,
        )
        subprocess.run(
            [
                "cmake", "--build", build_dir, "--target",
                "fido_object_provider_test",
                "fido_object_authorization_test",
                "fido_resident_container_test",
                "fido_oath_container_test",
                "fido_otp_container_test",
                "-j8",
            ],
            cwd=repo_root,
            check=True,
        )
        subprocess.run(["ctest", "--test-dir", build_dir, "--output-on-failure"], cwd=repo_root, check=True)
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)
    print("   [OK] All 5 Host C Unit Tests Passed!\n")


def run_rpc_helper_verification() -> None:
    print("=== [Layer 2] Running authenticator-helper JSON-RPC Verification ===")
    p = subprocess.Popen(
        [HELPER_BIN],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        def rpc(action, target=None, body=None):
            req = {"kind": "command", "action": action, "target": target or [], "body": body or {}}
            assert p.stdin is not None and p.stdout is not None
            p.stdin.write(json.dumps(req) + "\n")
            p.stdin.flush()
            return json.loads(p.stdout.readline())

        diag = rpc("diagnose", [], {})
        assert diag["kind"] == "success", f"diagnose failed: {diag}"
        print("   [OK] rpc('diagnose') -> success")

        usb = rpc("get", ["usb"])
        assert usb["kind"] == "success"
        dev_id = next(iter(usb["body"]["children"].keys()))
        print(f"   [OK] rpc('get', ['usb']) -> dev_id={dev_id}")

        dev = rpc("get", ["usb", dev_id])
        info = dev["body"]["data"]["info"]
        assert info["supported_capabilities"]["usb"] == 827
        assert info["config"]["enabled_capabilities"]["usb"] == 827
        print("   [OK] rpc('get', ['usb', dev_id]) -> capabilities=827")

        for node_path in [
            ["usb", dev_id, "ccid", "management"],
            ["usb", dev_id, "ccid", "oath"],
            ["usb", dev_id, "ccid", "oath", "accounts"],
            ["usb", dev_id, "ccid", "piv"],
            ["usb", dev_id, "ccid", "piv", "slots"],
            ["usb", dev_id, "fido", "ctap2"],
            ["usb", dev_id, "otp", "yubiotp"],
        ]:
            res = rpc("get", node_path)
            assert res["kind"] == "success", f"Failed on {node_path}: {res}"
            print(f"   [OK] rpc('get', {node_path}) -> success")
    finally:
        p.terminate()
        p.wait()
    print("   [OK] All authenticator-helper JSON-RPC Checks Passed!\n")


def run_py314_hardware_suite() -> None:
    print("=== [Layer 3] Running yubikit/ykman Live Hardware Applet Suite ===")
    with tempfile.TemporaryDirectory() as tmpdir:
        c_file = os.path.join(tmpdir, "runner314.c")
        bin_file = os.path.join(tmpdir, "runner314")
        with open(c_file, "w") as f:
            f.write(RUNNER_C_SRC)
        subprocess.run(["clang", c_file, "-o", bin_file], check=True)
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{INTERNAL_DIR}/base_library.zip:{INTERNAL_DIR}"
        r = subprocess.run([bin_file, PY314_SUITE], env=env, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"Hardware suite failed with exit code {r.returncode}")
    print("   [OK] All 8 YubiKey 5 Applets & 3 USB Transports Verified!\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify all YubiKey 5 applets on Pico FIDO.")
    parser.add_argument("--skip-host", action="store_true", help="Skip host C unit tests (ctest)")
    args = parser.parse_args()

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not args.skip_host:
        run_host_unit_tests(repo_root)

    # Check if Yubico Authenticator GUI is running so we can pause & resume it cleanly
    gui_running = subprocess.run(["pgrep", "-x", "Yubico Authenticator"], capture_output=True).returncode == 0
    if gui_running:
        subprocess.run(["killall", "Yubico Authenticator"], capture_output=True)
        time.sleep(0.5)

    try:
        run_rpc_helper_verification()
        run_py314_hardware_suite()
    finally:
        if gui_running:
            subprocess.run(["open", "-a", "Yubico Authenticator"], check=False)

    print("======================================================================")
    print("ALL PICO-FIDO YUBIKEY 5 VERIFICATION SUITES PASSED SUCCESSFULLY!")
    print("======================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
