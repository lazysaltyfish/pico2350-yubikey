# OpenPGP and YubiHSM Auth authenticated storage upgrade

OpenPGP and YubiHSM Auth now store complete records inside a versioned
AES-256-GCM envelope. This includes authentication secrets and PIN verifiers,
retry counters, touch/PIN policies, key origins and algorithm metadata, public
and private key material, OpenPGP private data objects, and certificates.

The envelope authenticates its version, destination file ID, payload length,
nonce, and ciphertext. Each file uses a separate HKDF-derived key rooted in
the verified RP2350 OTP device root. Missing OTP initialization, failed random
number generation, truncated reads, authentication failures, and malformed
record lengths fail closed. Loads use `file_read_at()` rather than assuming
that a Flash-cache pointer spans an entire record.

## Upgrade availability and recovery

The previous OpenPGP state was plaintext, while previous HSM credentials did
not authenticate all policy and retry fields. Their original authenticity
cannot be established after the fact. Consequently this upgrade deliberately
rejects the old formats; it never automatically wraps legacy state or restores
default authentication while old key material remains.

Existing OpenPGP and HSM Auth configurations require reprovisioning. Export
anything exportable through an authenticated workflow before upgrading. Device
generated nonexportable private keys cannot be recovered by this upgrade.
Keep their old device available until applications have replacement credentials.

For an unverifiable OpenPGP applet, the explicit maintenance APDU
`00 44 DE AD` (ACTIVATE, with no data) requests destructive recovery and requires
a fresh physical touch. It erases all OpenPGP key, certificate and private-data
files before installing authenticated defaults. Ordinary ACTIVATE retains its
existing lifecycle behavior for valid state. HSM Auth RESET (`00 06 DE AD`)
also requires physical touch and erases every HSM credential before resetting
its management state. Recovery never exposes the old keys under default PINs.
The host tests simulate these operations entirely in memory.

## Boundaries

Authenticated encryption detects unauthorized modification and copying between
file IDs. It does not prevent replay of an older, authentic snapshot of all
relevant Flash records from the same device. Rollback-resistant counters require
an additional hardware-backed monotonic mechanism or external trusted state.
This upgrade does not claim that property. Flash commit durability and
multi-record transaction recovery are separate guarantees from encryption.

The storage format also does not establish a vendor attestation trust chain or
change which host-visible protocol operations are authorized. HSM symmetric
clients supplying their own host challenge still rely on the caller for
freshness; their card cryptogram is verified before session keys are returned.
