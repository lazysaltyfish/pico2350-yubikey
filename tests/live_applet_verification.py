# SPDX-License-Identifier: AGPL-3.0-only
"""Hardware checks. Imports and enumeration happen only inside run_hardware_checks."""
import secrets


def select_device(candidates, serial=None, allow_destructive=False):
    """Candidates are (device, serial); never use discovery order as identity."""
    if allow_destructive and (serial is None or len(candidates) != 1):
        raise RuntimeError('Writes require an explicit serial and exactly one connected test device')
    matches=[item for item in candidates if serial is None or item[1] == serial]
    if len(matches) != 1 or matches[0][1] is None:
        raise RuntimeError('Select exactly one identifiable device with --serial; none or ambiguous matches')
    return matches[0]


def unused_name(existing, prefix='pico-verify-'):
    for _ in range(16):
        name=prefix+secrets.token_hex(8)
        if name not in existing:
            return name
    raise RuntimeError('Cannot allocate a unique temporary credential label')


def temporary_oath(session, oath):
    if session.locked:
        return 'SKIP', 'OATH is locked; no password guesses performed'
    existing=session.list_credentials()
    ids={c.id for c in existing}
    names={getattr(c,'name','') for c in existing}
    name=unused_name(names)
    data=oath.CredentialData(name,oath.OATH_TYPE.TOTP,oath.HASH_ALGORITHM.SHA1,
                             b'12345678901234567890',6,30,0,None)
    # CredentialData.get_id() is the actual device ID, including period/issuer syntax.
    if data.get_id() in ids:
        raise RuntimeError('Temporary OATH ID collides with an existing credential')
    created=session.put_credential(data,touch_required=False)
    try:
        code=session.calculate_code(created,timestamp=1000000)
        if len(code.value)!=6:
            raise RuntimeError('OATH calculation returned an invalid code')
    finally:
        session.delete_credential(created.id)
    if {c.id for c in session.list_credentials()} != ids:
        raise RuntimeError('OATH credential inventory changed unexpectedly')
    return 'PASS','OATH temporary put/calculate/delete'


def temporary_hsmauth(session, hsmauth):
    from cryptography.hazmat.primitives import hashes, cmac, serialization
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
    existing=session.list_credentials()
    # Never guess management credentials on an occupied or previously used applet.
    if existing or session.get_management_key_retries()!=8:
        return 'SKIP','HSM Auth is occupied or has used management retries'
    names={c.label for c in existing}; sym=unused_name(names); names.add(sym); ecc=unused_name(names)
    password=secrets.token_bytes(16); static=secrets.token_bytes(32); owned=[]
    def mac(key,msg):
        c=cmac.CMAC(algorithms.AES(key));c.update(msg);return c.finalize()
    def derive(key,kind,context,bits=128):
        return mac(key,bytes(11)+bytes([kind,0])+bits.to_bytes(2,'big')+b'\x01'+context)[:bits//8]
    def encoded(pub):
        return pub.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
    try:
        session.put_credential_symmetric(hsmauth.DEFAULT_MANAGEMENT_KEY,sym,static[:16],static[16:],password,False)
        owned.append(sym)
        context=session.get_challenge(sym)+secrets.token_bytes(8)
        expected=derive(static[:16],4,context)+derive(static[16:],6,context)+derive(static[16:],7,context)
        proof=derive(expected[16:32],0,context,64)
        actual=session.calculate_session_keys_symmetric(sym,context,password,proof)
        if b''.join(actual)!=expected:
            raise RuntimeError('SCP03 session keys differ from independent derivation')
        session.generate_credential_asymmetric(hsmauth.DEFAULT_MANAGEMENT_KEY,ecc,password,False)
        owned.append(ecc);public=session.get_public_key(ecc)
        epk=session.get_challenge(ecc,password)
        peer_static=ec.generate_private_key(ec.SECP256R1());peer_ephemeral=ec.generate_private_key(ec.SECP256R1())
        peer_epk=encoded(peer_ephemeral.public_key())
        sh_see=peer_ephemeral.exchange(ec.ECDH(),ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),epk))
        sh_sss=peer_static.exchange(ec.ECDH(),public)
        material=X963KDF(hashes.SHA256(),64,b'\x3c\x88\x10').derive(sh_see+sh_sss)
        receipt=mac(material[:16],peer_epk+epk)
        actual=session.calculate_session_keys_asymmetric(ecc,epk+peer_epk,peer_static.public_key(),password,receipt)
        if b''.join(actual)!=material[16:]:
            raise RuntimeError('SCP11 session keys differ from independent derivation')
    finally:
        for label in reversed(owned):
            session.delete_credential(hsmauth.DEFAULT_MANAGEMENT_KEY,label)
    return 'PASS','HSM Auth symmetric/asymmetric authentication and temporary credential cleanup'


def run_hardware_checks(serial=None, allow_destructive=False):
    from ykman.device import list_all_devices
    from yubikit.management import ManagementSession
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.core.fido import FidoConnection
    from yubikit.core.otp import OtpConnection
    from yubikit import oath, yubiotp, piv, openpgp, hsmauth
    from fido2.ctap2 import Ctap2
    candidates=[(device,info.serial) for device,info in list_all_devices()]
    device,selected=select_device(candidates,serial,allow_destructive)
    print(f'[DEVICE] serial={selected}; mode={"temporary writes enabled" if allow_destructive else "read-only"}')
    def ccid(check):
        with device.open_connection(SmartCardConnection) as conn:
            # Check identity again on this connection before selecting any applet.
            actual=ManagementSession(conn).read_device_info().serial
            if actual!=selected:
                raise RuntimeError('Device serial changed after selection')
            return check(conn)
    def report(name, check):
        status,detail=check();print(f'[{status}] {name}: {detail}')
    report('Management',lambda: ccid(lambda conn: ('PASS',str(ManagementSession(conn).read_device_info().version))))
    def oath_read(conn):
        s=oath.OathSession(conn)
        if s.locked:return 'SKIP','credential listing requires an OATH password'
        s.list_credentials();return 'PASS','version and credential listing'
    report('OATH',lambda:ccid(oath_read))
    report('OTP',lambda:ccid(lambda c: ('PASS',str(yubiotp.YubiOtpSession(c).get_config_state()))))
    report('PIV',lambda:ccid(lambda c: ('PASS',str(piv.PivSession(c).version))))
    report('OpenPGP',lambda:ccid(lambda c: ('PASS',str(openpgp.OpenPgpSession(c).get_key_information()))))
    report('HSM Auth',lambda:ccid(lambda c: ('PASS',str(len(hsmauth.HsmAuthSession(c).list_credentials()))+' credentials')))
    print('[SKIP] Security Domain: disabled until SCP authentication is implemented')
    # Composite YkmanDevice resolves each transport to the selected serial.
    if device.supports_connection(FidoConnection):
        with device.open_connection(FidoConnection) as conn:
            info=Ctap2(conn).info
            if 'FIDO_2_1' not in info.versions:raise RuntimeError('FIDO_2_1 is missing')
            print('[PASS] FIDO HID: getInfo')
    else:print('[SKIP] FIDO HID: transport unavailable')
    if device.supports_connection(OtpConnection):
        with device.open_connection(OtpConnection) as conn:
            yubiotp.YubiOtpSession(conn).get_config_state();print('[PASS] OTP HID: configuration state')
    else:print('[SKIP] OTP HID: transport unavailable')
    if allow_destructive:
        # Recheck isolation immediately before entering write checks.
        select_device([(d,i.serial) for d,i in list_all_devices()],selected,True)
        report('OATH write checks',lambda:ccid(lambda c:temporary_oath(oath.OathSession(c),oath)))
        report('HSM Auth write checks',lambda:ccid(lambda c:temporary_hsmauth(hsmauth.HsmAuthSession(c),hsmauth)))
    else:
        print('[SKIP] OATH/HSM Auth writes: require --allow-destructive --serial')
    print('[SKIP] PIV/OTP/OpenPGP destructive checks: use dedicated manual provisioning; no reset or slot overwrite is automated')
