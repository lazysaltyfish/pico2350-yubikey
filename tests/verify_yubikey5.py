#!/usr/bin/env python3
#
# Pico-YubiKey (RP2350)
# Copyright (c) 2026 lazysaltyfish
#
# SPDX-License-Identifier: AGPL-3.0-only
#
"""Run host regressions and serial-bound, read-only hardware checks by default.

Writing temporary OATH/HSM Auth credentials requires --allow-destructive --serial.
Use only an isolated, expendable test device for write checks. No applet resets run.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HELPER_BIN = "/Applications/Yubico Authenticator.app/Contents/Resources/helper/authenticator-helper"
INTERNAL_DIR = "/Applications/Yubico Authenticator.app/Contents/Resources/helper/_internal"

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

PY314_BOOTSTRAP = r"""
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

"""

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-host', action='store_true', help='Skip host C/Python regressions')
    parser.add_argument('--skip-hardware', action='store_true', help='Do not open any hardware')
    parser.add_argument('--skip-helper', action='store_true', help='Skip Authenticator JSON-RPC checks')
    parser.add_argument('--serial', type=int, help='Exact device serial number (required for writes)')
    parser.add_argument('--allow-destructive', action='store_true',
                        help='Allow temporary OATH/HSM Auth writes on one isolated expendable device')
    args = parser.parse_args(argv)
    if args.allow_destructive and (not args.serial or args.skip_hardware):
        parser.error('--allow-destructive requires --serial and hardware checks')
    return args


def run_host_unit_tests(repo_root):
    print('[RUN] Host C/Python regression tests', flush=True)
    with tempfile.TemporaryDirectory(prefix='pico-host-verify-') as build_dir:
        subprocess.run(['cmake', '-S', str(repo_root), '-B', build_dir,
                        '-DENABLE_EMULATION=1', '-DENABLE_EDDSA=ON', '-DVIDPID=Yubikey'], check=True)
        subprocess.run(['cmake', '--build', build_dir, '-j8'], check=True)
        subprocess.run(['ctest', '--test-dir', build_dir, '--output-on-failure'], check=True)
    print('[PASS] Host regressions')


def select_rpc_device(rpc, serial):
    from live_applet_verification import select_device
    usb = rpc('get', ['usb'])
    if usb.get('kind') != 'success':
        raise RuntimeError(f'USB enumeration failed: {usb}')
    candidates = []
    for dev_id in usb['body'].get('children', {}):
        reply = rpc('get', ['usb', dev_id])
        if reply.get('kind') != 'success':
            raise RuntimeError(f'Device info unavailable: {dev_id}')
        info = reply['body']['data']['info']
        candidates.append((dev_id, info.get('serial')))
    return select_device(candidates, serial, False)[0]


def run_rpc_helper_verification(serial):
    print('[RUN] Read-only authenticator-helper checks', flush=True)
    with tempfile.TemporaryFile(mode='w+') as error_log:
        p = subprocess.Popen([HELPER_BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=error_log, text=True)
        try:
            def rpc(action, target):
                p.stdin.write(json.dumps({'kind': 'command', 'action': action,
                                          'target': target, 'body': {}}) + '\n')
                p.stdin.flush()
                line = p.stdout.readline()
                if not line:
                    raise RuntimeError('Authenticator helper closed its output')
                return json.loads(line)
            dev_id = select_rpc_device(rpc, serial)
            for path in [('ccid','management'), ('ccid','oath'), ('ccid','piv'),
                         ('fido','ctap2'), ('otp','yubiotp')]:
                reply = rpc('get', ['usb',dev_id,*path])
                if reply.get('kind') != 'success':
                    raise RuntimeError(f'Helper check failed for {path}: {reply}')
                print(f'[PASS] helper {"/".join(path)}')
        finally:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill();p.wait()


def run_hardware_suite(repo_root, args):
    options = {'serial': args.serial, 'allow_destructive': args.allow_destructive}
    # Prefer a normal installed yubikey-manager; the macOS bundle remains a fallback.
    try:
        import ykman  # noqa: F401 -- imports only; no hardware enumeration here
    except ImportError:
        if not Path(INTERNAL_DIR, 'Python').exists():
            raise RuntimeError('Install yubikey-manager or Yubico Authenticator to run hardware checks')
        with tempfile.TemporaryDirectory(prefix='pico-yubikit-') as tmp:
            c_file=Path(tmp,'runner.c'); executable=Path(tmp,'runner')
            c_file.write_text(RUNNER_C_SRC)
            subprocess.run(['clang',str(c_file),'-o',str(executable)],check=True)
            code = PY314_BOOTSTRAP + '\nimport json, os\nsys.path.insert(0, os.environ["PICO_VERIFY_TESTS"])\nfrom live_applet_verification import run_hardware_checks\nrun_hardware_checks(**json.loads(os.environ["PICO_VERIFY_OPTIONS"]))\n'
            env=os.environ.copy()
            env['PYTHONPATH']=f'{INTERNAL_DIR}/base_library.zip:{INTERNAL_DIR}'
            env['PICO_VERIFY_TESTS']=str(repo_root/'tests')
            env['PICO_VERIFY_OPTIONS']=json.dumps(options)
            subprocess.run([str(executable),code],env=env,check=True)
    else:
        from live_applet_verification import run_hardware_checks
        run_hardware_checks(**options)


def main(argv=None):
    args=parse_args(argv);repo_root=Path(__file__).resolve().parents[1]
    if args.skip_host:
        print('[SKIP] Host regressions: --skip-host')
    else:
        run_host_unit_tests(repo_root)
    if args.skip_hardware:
        print('[SKIP] Hardware and helper checks: --skip-hardware')
        return 0
    if args.skip_helper or not Path(HELPER_BIN).exists():
        print('[SKIP] Authenticator helper: unavailable or explicitly skipped')
    else:
        run_rpc_helper_verification(args.serial)
    run_hardware_suite(repo_root,args)
    print('Verification finished. Only checks marked PASS were executed successfully; SKIP is not coverage.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
