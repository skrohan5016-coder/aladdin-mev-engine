# F6 External Signature and Relay Evidence Contract

## Trust flow

```text
F5 unsigned execution package
  + externally observed low-s secp256k1 signature
  -> recover exact authenticated F5 sender
  -> canonical signed EIP-1559 type-2 transaction
  -> signed private bundle retaining exact F5 intent
  -> explicit offline relay-endpoint evidence registry
  -> canonical normalized relay request bytes (not dispatched)
  -> optional recorded relay responses
  -> externally-signed execution-package evidence
```

## Signature rules

`y_parity` is exactly zero or one. `r` and `s` are positive and below the secp256k1 group order, and `s` must be EIP-2 low-s. F6 recovers all valid public-key candidates and requires exactly one candidate to match the sender authenticated by F5. Signature source identity affects evidence identity but cannot change raw transaction bytes.

Public scalar multiplication accepts only the closed range from zero through the secp256k1 group order; larger values fail before curve work. The exact group order remains available for subgroup checks and maps valid subgroup points to infinity.

F6 exposes verification and recovery only. Production modules and scripts may not contain a private-key field or signing function.

## Signed transaction rules

The signed transaction uses the exact F5 type-2 fields in order:

```text
chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
gasLimit, to, value, data, emptyAccessList,
yParity, r, s
```

The raw transaction is `0x02 || RLP(fields)`. The transaction hash is legacy Keccak-256 of those exact bytes. No field may be re-priced, re-ordered, normalized, or inferred during F6.

## Relay evidence rules

A relay endpoint record contains a stable evidence ID, chain, delivery class, protocol, transaction ceiling, replacement support, and authentication requirement. It contains no URL, credential, or production approval.

The normalized relay request is canonical JSON evidence only. The payload is stored as immutable canonical bytes; callers receive a detached parsed copy. F6 does not dispatch it.

Relay responses are recorded inputs with independently unique source IDs and source digests. Accepted responses require a relay reference; rejected and error responses require error fields. Acceptance does not prove inclusion.

## Final authority boundary

```text
network_access                  = none
relay_access                    = none
credential_authority            = none
key_authority                   = none
local_signing_authority         = none
signing_authority               = external-unmodeled
submission_authority            = none
execution_authority             = none
inclusion_authority             = none
signature_verification_authority= offline-secp256k1-recovery-only
relay_response_authority        = recorded-input-only
inclusion_guarantee             = none
```
