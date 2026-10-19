#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import io
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import live_applet_verification as live
import verify_yubikey5 as runner

class VerificationSafetyTests(unittest.TestCase):
    def test_cli_defaults_and_write_gate(self):
        self.assertFalse(runner.parse_args([]).allow_destructive)
        with contextlib.redirect_stderr(io.StringIO()):
            for args in [['--allow-destructive'],['--allow-destructive','--serial','42','--skip-hardware']]:
                with self.assertRaises(SystemExit):runner.parse_args(args)
        self.assertTrue(runner.parse_args(['--allow-destructive','--serial','42']).allow_destructive)

    def test_serial_selection(self):
        items=[('other',12),('target',42)]
        self.assertEqual(live.select_device(items,42),('target',42))
        for candidates,serial,write in [(items,None,False),(items,42,True),
                                        ([('target',None)],None,False),(items,99,False),
                                        ([('a',42),('b',42)],42,False)]:
            with self.assertRaises(RuntimeError):live.select_device(candidates,serial,write)
        self.assertEqual(live.select_device([('target',42)],42,True),('target',42))

    def test_rpc_selection_never_uses_first_device(self):
        def rpc(action,path):
            self.assertEqual(action,'get')
            body={'children':{'first':{},'second':{}}} if path==['usb'] else {
                'data':{'info':{'serial':12 if path[-1]=='first' else 42}}}
            return {'kind':'success','body':body}
        self.assertEqual(runner.select_rpc_device(rpc,42),'second')
        with self.assertRaises(RuntimeError):runner.select_rpc_device(rpc,None)

    def test_random_label_collisions(self):
        with patch.object(live.secrets,'token_hex',side_effect=['taken','free']):
            self.assertEqual(live.unused_name({'pico-verify-taken'}),'pico-verify-free')
        with patch.object(live.secrets,'token_hex',return_value='taken'):
            with self.assertRaises(RuntimeError):live.unused_name({'pico-verify-taken'})

    def test_oath_cleanup_preserves_existing_on_calculation_failure(self):
        class Data:
            def __init__(self,name,*args):self.name=name
            def get_id(self):return self.name.encode()
        class Session:
            locked=False
            def __init__(self):self.items={b'existing':SimpleNamespace(id=b'existing',name='existing')};self.deleted=[]
            def list_credentials(self):return list(self.items.values())
            def put_credential(self,data,**kwargs):
                assert data.get_id() not in self.items
                c=SimpleNamespace(id=data.get_id(),name=data.name);self.items[c.id]=c;return c
            def calculate_code(self,*a,**k):raise RuntimeError('injected failure')
            def delete_credential(self,key):self.deleted.append(key);del self.items[key]
        oath=SimpleNamespace(CredentialData=Data,OATH_TYPE=SimpleNamespace(TOTP=1),HASH_ALGORITHM=SimpleNamespace(SHA1=1))
        session=Session()
        with self.assertRaisesRegex(RuntimeError,'injected'):live.temporary_oath(session,oath)
        self.assertEqual(set(session.items),{b'existing'});self.assertEqual(len(session.deleted),1)
        session.locked=True;self.assertEqual(live.temporary_oath(session,oath)[0],'SKIP')

    def test_readonly_hardware_path_never_calls_write_checks(self):
        class Conn:
            def __enter__(self):return self
            def __exit__(self,*a):pass
        class Device:
            def open_connection(self,kind):return Conn()
            def supports_connection(self,kind):return True
        class ReadSession:
            version=(5,8,0);locked=False
            def __init__(self,*a):pass
            def read_device_info(self):return SimpleNamespace(serial=42,version=(8,2,0))
            def list_credentials(self):return []
            def get_config_state(self):return 'empty'
            def get_key_information(self):return {}
        def mod(**values):
            m=ModuleType('fake');m.__dict__.update(values);return m
        devices=mod(list_all_devices=lambda:[(Device(),SimpleNamespace(serial=42))])
        modules={'ykman':mod(), 'ykman.device':devices,
                 'yubikit.management':mod(ManagementSession=ReadSession),
                 'yubikit.core.smartcard':mod(SmartCardConnection=type('CCID',(),{})),
                 'yubikit.core.fido':mod(FidoConnection=type('FIDO',(),{})),
                 'yubikit.core.otp':mod(OtpConnection=type('OTP',(),{})),
                 'fido2':mod(),'fido2.ctap2':mod(Ctap2=lambda c:SimpleNamespace(info=SimpleNamespace(versions=['FIDO_2_1'])))}
        modules['yubikit']=mod(oath=SimpleNamespace(OathSession=ReadSession),yubiotp=SimpleNamespace(YubiOtpSession=ReadSession),
                               piv=SimpleNamespace(PivSession=ReadSession),openpgp=SimpleNamespace(OpenPgpSession=ReadSession),
                               hsmauth=SimpleNamespace(HsmAuthSession=ReadSession))
        output=io.StringIO()
        with patch.dict(sys.modules,modules),contextlib.redirect_stdout(output),\
             patch.object(live,'temporary_oath',side_effect=AssertionError('write reached')),\
             patch.object(live,'temporary_hsmauth',side_effect=AssertionError('write reached')):
            live.run_hardware_checks(42,False)
        text=output.getvalue();self.assertIn('[SKIP] Security Domain',text);self.assertIn('[SKIP] OATH/HSM Auth writes',text)
        self.assertNotIn('ALL',text)

    def test_skip_hardware_does_not_launch_helper(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output),patch.object(runner,'run_hardware_suite') as hardware,\
             patch.object(runner,'run_rpc_helper_verification') as helper:
            self.assertEqual(runner.main(['--skip-host','--skip-hardware']),0)
            hardware.assert_not_called();helper.assert_not_called()
        self.assertIn('[SKIP]',output.getvalue());self.assertNotIn('PASSED',output.getvalue())

if __name__=='__main__':unittest.main()
