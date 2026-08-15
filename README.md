# Aladdin MEV Engine

Aladdin MEV Engine is a governed, safety-first foundation for authenticated EVM state, exact market mathematics, conservative economics, replayable transaction evidence, and offline verification of externally produced signatures and relay records.

## Current status

**F6 is an offline, recorded-input external-signature and relay-evidence foundation.** It retains accepted F0–F5 authority and adds:

- dependency-free secp256k1 point arithmetic, signature verification, public-key recovery, and Ethereum-address recovery;
- canonical low-s EIP-1559 signature evidence from an external unmodeled signer;
- exact signed type-2 transaction bytes and legacy-Keccak transaction hash;
- unique recovery of the exact F5 authenticated sender;
- signed private bundle evidence preserving the exact F5 bundle identity, order, target range, and validity;
- explicit offline relay endpoint evidence without URL, credential, or production approval;
- immutable canonical normalized relay-request evidence that is never locally dispatched;
- recorded accepted, rejected, or error relay responses that do not claim inclusion;
- a final externally-signed package that recomputes all unsigned, signed, bundle, request, and response identities.

Every F6 output remains within this boundary:

```text
private_key_present = false
local_signing_authority = none
network_access = none
relay_access = none
credential_authority = none
submission_authority = none
execution_authority = none
inclusion_authority = none
signing_eligible = false
submission_eligible = false
execution_eligible = false
inclusion_guarantee = false
```

F6 supports Ethereum and Base evidence because the inherited authenticated opportunity, deployment, sender, and unsigned-package authorities are limited to those governed chains. It does not hold keys, sign, contact a relay, submit transactions or bundles, deploy contracts, move funds, or guarantee inclusion or profit.

## Local validation

Python 3.13 is the governed conformance runtime. F6 has no third-party runtime dependencies.

```bash
make all
```

## Architecture

Start with:

- [`governance/ARCHITECTURE.md`](governance/ARCHITECTURE.md)
- [`governance/F6_SIGNED_RELAY_EVIDENCE.md`](governance/F6_SIGNED_RELAY_EVIDENCE.md)
- [`governance/F6_ACCEPTANCE.md`](governance/F6_ACCEPTANCE.md)
- [`governance/F5_UNSIGNED_EXECUTION_PACKAGE.md`](governance/F5_UNSIGNED_EXECUTION_PACKAGE.md)
- [`governance/THREAT_MODEL.md`](governance/THREAT_MODEL.md)

## Security

Never commit credentials, wallet material, private keys, signing authority, relay URLs/tokens, deployment authority, or production configuration. See [`SECURITY.md`](SECURITY.md).
