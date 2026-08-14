# F6 Scope — External Signature Verification and Recorded Relay Evidence

## Accepted parent

- F5 landing commit: `f068d1f1ffad9d4c2439dd6f0fa36e333d73817f`
- F5 tree: `89df1b1bf5d665c1ea1b2abb80320d824b6e7bb4`
- F5 architecture: `AMEV-F5-ARCH-v1-4359fcd9d1a2`

## Mission

F6 converts one exact F5 unsigned package into offline evidence for an externally produced secp256k1 signature, the resulting canonical signed EIP-1559 transaction, a signed private bundle, a normalized relay request that is never dispatched locally, optional recorded relay responses, and one final externally-signed package.

F6 verifies signatures but does not create them. It contains no private key, mnemonic, HSM/KMS client, wallet signer, RPC client, relay URL, authentication token, HTTP transport, transaction submission, bundle submission, deployment, fund movement, or inclusion authority.

## Implemented authority

- dependency-free secp256k1 curve arithmetic, signature verification, public-key recovery, and Ethereum-address recovery;
- low-s external EIP-1559 signature evidence with source identity and observation time;
- exact type-2 signed transaction encoding and legacy-Keccak transaction hash;
- exact authenticated-sender recovery against the F5 sender proof;
- signed private bundle evidence retaining F5 ordering, target range, delivery class, and validity;
- URL-free and credential-free relay endpoint evidence registry for Ethereum builders and Base sequencers;
- immutable normalized private-bundle request payload evidence without dispatch;
- recorded accepted, rejected, or error relay response evidence;
- final externally-signed package evidence that recomputes every F5, signature, bundle, request, and response identity.

## Non-goals

- generating or storing keys;
- local or remote signing;
- RPC, relay, builder, or sequencer connectivity;
- production endpoint approval;
- HTTP or JSON-RPC dispatch;
- transaction or bundle submission;
- relay acceptance polling;
- block inclusion or realized-profit claims;
- execution or fund movement.

## Acceptance contract

Every F6 evidence object is constructor-recomputed, canonical-JSON digest-addressed, closed by JSON Schema, locked by the canonical F6 schema manifest, adversarially tested, and validated on the exact source head and GitHub synthetic merge. Relay acceptance remains recorded evidence only and is never interpreted as inclusion, execution, or profit authority.
