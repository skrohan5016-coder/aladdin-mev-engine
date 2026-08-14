# F5 Scope — Authenticated Deployments, Unsigned EIP-1559 Transactions, and Private Bundle Intent

## Accepted parent

- F4 landing commit: `5e9497695c08ec4bd1ef724b39fb941f100c3e73`
- F4 tree: `d909eb7d378a5c188e71a5c475cb36b8c61099a3`
- F4 architecture: `AMEV-F4-ARCH-v1-36ee2dc379f7`

## Mission

F5 converts an approved F4 shadow economics result into a deterministic, fully replayable **unsigned** EVM execution package. The package binds authenticated executor deployment evidence, exact governed calldata, sender/nonce/balance state, an EIP-1559 signing preimage, a relay-neutral private bundle intent, and independent transaction-bound simulation results.

F5 remains offline and recorded-input-only. It does not connect to an RPC endpoint or relay, hold credentials, access keys, sign, broadcast, submit a bundle, deploy a contract, reserve funds, or move assets.

## Implemented authority

- authenticated stateless executor deployment and interface registry, including exact flash-loan provider, direct-payment, authenticated-sender residual-beneficiary, and canonical empty-storage-root semantics;
- bounded Ethereum ABI encoding for the governed executor call with an independently validated exact route frame, uint64 deadline, and non-expanding exact millisecond validity ceiling;
- exact route-command payload derived from the accepted F4 execution plan;
- F2-proof-bound sender nonce and native balance evidence;
- deterministic unsigned EIP-1559 typed-transaction signing payload, intrinsic-gas gate, and hash;
- target-block/time-bounded private bundle intent beginning at the authenticated nonce, with contiguous nonce rules and aggregate balance coverage;
- independent transaction simulation agreement bound to transaction/bundle identities, explicit block/timestamp/base-fee context, and complete base-token residual delivery to the authenticated sender;
- final single-transaction package-v1 evidence that requires approved F4 economics, binds simulations after bundle creation, inherits deadline validity, and keeps `signing_eligible = false` and `execution_eligible = false`.

## Non-goals

- live state acquisition;
- production RPC, relay, builder, or sequencer connectivity;
- private keys, mnemonic phrases, HSM/KMS access, signing, or signature recovery;
- transaction or bundle submission;
- contract deployment;
- wallet funding or flash-loan execution;
- inclusion or profit guarantees.

## Acceptance contract

Every F5 runtime object is constructor-recomputed, canonical-JSON digest-addressed, closed by JSON Schema, locked by the canonical F5 schema manifest, adversarially tested, and independently validated on the exact source head and GitHub synthetic merge.
