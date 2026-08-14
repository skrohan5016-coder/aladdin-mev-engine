# Aladdin MEV Engine Architecture

## Accepted lineage

F5 is built from accepted F4 landing `5e9497695c08ec4bd1ef724b39fb941f100c3e73`, tree `d909eb7d378a5c188e71a5c475cb36b8c61099a3`, and architecture `AMEV-F4-ARCH-v1-36ee2dc379f7`. F0 supplies canonical evidence, profit policy, and risk controls; F1 supplies recorded observation and replay; F2 supplies authenticated EVM state; F3 supplies exact gross opportunities; F4 supplies deterministic plans and cost-complete shadow economics; F5 adds authenticated executor identity, governed calldata, unsigned EIP-1559 transaction preimages, private bundle intent, and transaction-bound simulation evidence.

## Inherited authority retention

F5 does not weaken or replace F0-F4. Canonical evidence, source contracts, tamper-evident replay, reorg handling, authenticated state proofs, code-hash-bound pool mathematics, exact optimization, recorded cost reconciliation, source-bound context, and F4 profit decisions remain independently locked and tested.

## Trust flow

```text
Recorded observations
  -> authenticated pool, executor, and sender account state
  -> exact F3 opportunity
  -> F4 plan, cost envelope, simulation/context, approved shadow economics
  -> code-hash-bound executor interface and deployment evidence
  -> plan-derived route commands and economic minimum-output floor
  -> canonical unsigned EIP-1559 signing preimage
  -> relay-neutral private bundle intent
  -> distinct implementation/source transaction simulations
  -> unsigned execution-package evidence
```

## F5 authority boundaries

```text
network_access                 = none
signing_authority              = none
submission_authority           = none
execution_authority            = none
deployment_registry_authority  = authenticated-recorded-direct-runtime-shadow-only
calldata_authority             = offline-deterministic-governed-encoding-only
sender_state_authority         = offline-authenticated-eoa-nonce-balance-only
unsigned_transaction_authority = offline-eip1559-signing-preimage-only
private_bundle_intent_authority= offline-relay-neutral-intent-only
execution_package_authority    = offline-unsigned-transaction-bound-shadow-only
inclusion_guarantee            = none
```

An F5 package is not a signature request, a relay submission, a deployment instruction, an inclusion approval, or permission to move funds.

## F5 hardening invariants

A runtime code hash authorizes only one exact executor interface, and every authenticated deployment must be an exact registry member. Executor address, chain, code hash, canonical empty storage root, validity, and proof-observation time bind exact F2 evidence. Route command bytes and calldata are recomputed from the accepted F4 plan; the exported raw encoder independently enforces one simple cycle with unique pools, exact base-token endpoints, exact principal/amount continuity, and an exact final minimum; route and final slippage minima use ceiling division so integer rounding cannot weaken the policy. Sender nonce and balance come from an authenticated EOA proof sharing the exact pool/deployment state anchor, and transaction creation cannot predate that proof. The EIP-1559 type-2 payload is canonical RLP with no signature, and its gas limit cannot be below canonical calldata intrinsic gas. L1-data, OP Stack operator-fee, and direct-payment bounds remain separate evidence; all are included in conservative economics and authenticated sender-balance coverage. Bundle nonces begin at the authenticated sender nonce and remain ordered/contiguous, target blocks are bounded, aggregate worst-case upfront native cost must fit the authenticated balance, and no relay endpoint or credential is retained. Transaction simulations cannot predate the bundle and require distinct engines, implementation digests, and source digests while agreeing on one environment and the exact state anchor, transaction signing hash, bundle, explicit in-range block/timestamp/base-fee context, intrinsic-to-limit-bounded gas, operator fee paid within its recorded upper bound, exact F4 base-token output, flash-loan repayment, authenticated sender beneficiary, complete base-token residual delta, logs, post-state, and payment. Package schema v1 binds exactly one unsigned transaction and inherits the executor-call deadline as a transitive validity limit.

The machine-readable architecture manifest and lock are authoritative.
