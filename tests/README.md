# Tests Documentation

This directory contains Pico Fido test code and conformance-related documentation.

## Windows launchers

The top-level test and Docker workflows have `.bat` launchers for Windows.
They use Docker Desktop and mount the checkout at `/workspace` in the Linux
test container. The `.sh` counterparts remain available for Linux and the
Ubuntu GitHub Actions jobs.

## FIDO Alliance conformance results

The current FIDO Alliance Conformance Test App results are documented in
[`fido-alliance-conformance-results.md`](./fido-alliance-conformance-results.md).

Those results show that the tested Pico Fido firmware passed the conformance
tests captured in that report.

## YubiKey 5 full applet verification

The end-to-end hardware and host verification methodology covering all YubiKey 5 applets (Management, FIDO2/U2F, OATH, OTP, PIV, OpenPGP v3.4, YubiHSM Auth 5.8, and GlobalPlatform Security Domain) is documented in [`yubikey5-verification.md`](./yubikey5-verification.md).

## Important limitation

Passing the FIDO Alliance conformance tests does **not** mean Pico Fido is
FIDO Alliance certified.

Official certification requires the separate FIDO Alliance certification
process and any corresponding approval/listing from the FIDO Alliance. This
documentation only states that the firmware passed the conformance tests that
would be used as part of that certification path.
