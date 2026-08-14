# Aladdin MEV Engine Architecture

## Accepted lineage

F6 is built from accepted F5 landing `f068d1f1ffad9d4c2439dd6f0fa36e333d73817f`, tree `89df1b1bf5d665c1ea1b2abb80320d824b6e7bb4`, and architecture `AMEV-F5-ARCH-v1-4359fcd9d1a2`. F0 supplies canonical evidence, profit policy, and risk controls; F1 supplies recorded observation and replay; F2 supplies authenticated EVM state; F3 supplies exact gross opportunities; F4 supplies deterministic plans and cost-complete shadow economics; F5 supplies authenticated unsigned transaction and transaction-bound simulation packages; F6 verifies externally produced signatures and records offline relay request/response evidence.

## Inherited authority retention

F6 does not weaken or replace F0–F5. Canonical evidence, source contracts, tamper-evident replay, reorg handling, authenticated state proofs, code-hash-bound market mathematics, exact optimization, conservative cost reconciliation, authenticated deployment/sender state, calldata, unsigned EIP-1559 identity, private bundle intent, and transaction-bound simulation authority remain independently locked and tested.

## Trust flow

```text
Recorded observations and authenticated EVM state
  -> exact F3 opportunity and F4 cost-complete shadow decision
  -> F5 authenticated unsigned execution package
  -> externally observed low-s secp256k1 signature
  -> exact authenticated-sender recovery
  -> canonical signed EIP-1559 transaction and signed private bundle
  -> URL-free/credential-free offline relay endpoint evidence
  -> immutable normalized request evidence (not dispatched)
  -> optional recorded relay responses
  -> externally-signed package evidence
```

## F6 authority boundaries

```text
network_access                   = none
relay_access                     = none
credential_authority             = none
key_authority                    = none
local_signing_authority          = none
signing_authority                = external-unmodeled
submission_authority             = none
execution_authority              = none
inclusion_authority              = none
signature_verification_authority = offline-secp256k1-recovery-only
signed_transaction_authority     = offline-external-signature-evidence-only
signed_bundle_authority          = offline-externally-signed-private-intent-only
relay_request_authority          = offline-normalized-request-only
relay_response_authority         = recorded-input-only
inclusion_guarantee              = none
```

An F6 package is not a signing request, network request, relay submission, inclusion proof, execution approval, or permission to move funds.

## F6 hardening invariants

Signature parity is exact, scalars are bounded, and low-s form is mandatory. Recovery must produce exactly one address matching the F5 authenticated sender. Signed transaction bytes preserve every F5 unsigned field and the empty access list, and the transaction hash is legacy Keccak-256 of those bytes. Signed bundle order and identity equal the exact F5 bundle. Relay endpoints contain no URL, credential, or production approval. Normalized request payloads are canonical immutable bytes and caller-visible mappings are detached copies. Recorded relay response source IDs and source digests are independently unique. Accepted relay evidence never implies inclusion, execution, or profit. Production source and scripts expose no private-key, signing, HTTP, or submission function.

The machine-readable architecture manifest and lock are authoritative.
