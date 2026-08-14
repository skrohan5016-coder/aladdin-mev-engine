# F5 Authenticated Unsigned Execution Package

## Mission

F5 converts an approved F4 shadow-economics result into a deterministic offline EVM package that can be independently replayed and audited without possessing a private key or contacting a chain, relay, builder, or sequencer.

## Executor deployment authority

An executor deployment is accepted only when an exact member of the governed deployment registry and exact F2 account proof agree on chain, address, runtime code hash, state anchor, and valid block range. Empty code, non-empty executor storage roots, unregistered runtime identities, unconsumed storage proofs, overlapping deployment authority, and one-code-hash/multiple-interface conflicts fail closed. F5 v1 requires the canonical empty storage root so recorded interface behavior cannot depend on unauthenticated persistent configuration. A registry may declare only direct-runtime semantics, but F5 does not independently prove that arbitrary bytecode is not upgradeable or proxy-like; recorded deployment evidence remains shadow evidence, not production approval. The same interface identity binds one exact external flash-loan provider ID and source digest, fixed `msg.value` semantics for the recorded conditional direct-payment upper bound, and `msg.sender` as the beneficiary of the complete base-token residual after flash-loan repayment.

## Governed route command and calldata

F5 serializes every F4 route step into one exact 189-byte, big-endian binary command containing its index, raw 20-byte pool/token addresses, exact 32-byte unsigned amounts, and raw 32-byte quote SHA-256. The registry-bound command-schema digest commits to the framing, field order, widths, byte order, and encodings. The public governed ABI encoder independently rejects zero selector/plan identity, nonpositive flash principal, a final minimum below principal, non-`uint64` deadlines, malformed headers, unsupported versions/counts, noncanonical indexes, invalid addresses, zero input/output claims, minimum/expected-output inversions, zero quote digests, and payload-length disagreement. The command sequence is wrapped in one canonical ABI call:

```text
execute(bytes32,address,uint256,uint256,uint64,bytes)
```

Every route minimum and the final slippage floor use ceiling division so integer rounding cannot silently weaken the configured protection. The final minimum output is the maximum of:

1. principal + every F4 conservative cost + the F4 absolute/return requirement; and
2. the governed slippage floor.

Therefore calldata construction cannot silently weaken the F4 economic decision. The ABI deadline remains a uint64 Unix second, while the evidence also binds the exact millisecond minimum of the F4 input expiry and policy horizon; downstream transaction, bundle, and package validity use that exact millisecond ceiling and cannot gain up to an extra second through rounding.

## Authenticated sender and unsigned transaction

The sender must be an F2-authenticated externally owned account with empty runtime code and empty storage. Nonce and native balance come from the same state anchor used by the opportunity and executor. The balance must cover the recorded upper bound for gas, direct payment, and Base L1 data cost. The unsigned transaction value is exactly the recorded direct-payment upper bound under the interface-bound `msg.value` conditional-payment semantics. Transaction creation cannot predate the authenticated sender proof, and the gas limit must cover canonical EIP-1559 intrinsic gas for the exact calldata.

F5 builds the exact EIP-1559 type-2 signing payload:

```text
0x02 || rlp([
  chain_id,
  nonce,
  max_priority_fee_per_gas,
  max_fee_per_gas,
  gas_limit,
  executor_address,
  value,
  calldata,
  []
])
```

It records the legacy-Keccak signing hash but never creates or accepts `v`, `r`, `s`, a private key, or a signed transaction.

## Private bundle intent

A bundle intent is relay-neutral. It stores no endpoint or credential. The intent must be created within a governed one-second window after the authenticated state observation, and that freshness ceiling becomes a transitive bundle/package validity limit. Transactions must share one exact sender-state proof, chain, sender, and anchor; the first nonce must equal the authenticated sender nonce; later nonces must be contiguous; signing hashes must be unique; the sender balance must cover the aggregate worst-case upfront requirement for the complete bundle; and target and maximum blocks must remain within the governed distance from the authenticated state block.

## Transaction simulation evidence

Two or more successful simulations must use distinct engine identities, implementation digests, and result-source digests. They must agree on one environment and the exact state anchor, unsigned transaction, signing hash, bundle, explicit simulated block number, block timestamp, base fee, gas, exact F4 base-token identity, gross route output, flash-loan principal repayment, flash fee paid, base-token residual before external costs, authenticated sender beneficiary, complete beneficiary delta, token-delta digest, log digest, post-state digest, and direct payment. Successful results reconcile `output = principal + flash fee + residual`; failed results cannot claim economic outputs. The principal, fee, and residual must equal the exact F4 funding and execution-plan authority, and the complete residual must be delivered to the authenticated transaction sender. The simulated block must lie inside the bundle range, its timestamp must strictly follow the authenticated anchor block timestamp and cannot exceed the executor deadline, and its base fee cannot exceed the unsigned transaction max fee. A simulation cannot predate the bundle intent it claims to evaluate. Simulation validity is rechecked when the final package is created.

## Final authority

```text
signature_present       = false
relay_credentials_present = false
signing_eligible        = false
submission_eligible     = false
execution_eligible      = false
inclusion_guarantee     = false
```

F5 package schema v1 intentionally binds exactly one unsigned transaction even though the lower-level bundle-intent type can validate bounded multi-transaction intents. A later milestone must explicitly govern multi-transaction package semantics.

F5 is a deterministic unsigned evidence boundary, not a live trading milestone.
