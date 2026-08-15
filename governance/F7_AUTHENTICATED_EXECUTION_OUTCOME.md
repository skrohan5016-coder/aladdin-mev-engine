# F7 Authenticated Execution-Outcome Contract

## Trust flow

```text
Exact F6 externally signed package
  + recorded canonical block header
  + exact F2 block/state anchor
  + exact F2 executor post-state account proof
  + indexed transaction-trie proof
  + indexed receipt-trie proof
  + previous receipt proof when transaction_index > 0
  -> authenticated signed-transaction inclusion
  -> authenticated receipt and exact per-transaction gas
  -> code-hash-bound executor settlement event
  + recorded rollup fee evidence
  -> authenticated execution-outcome evidence
```

## Block and trie rules

The canonical raw block header must hash to the recorded block hash with Ethereum legacy Keccak-256. Parent hash, state root, transactions root, receipts root, number, gas used, timestamp, and base fee are re-decoded and cross-checked. The same block hash and state root must already be bound by the exact F2 state anchor.

The executor post-state proof must share the exact inclusion-block state anchor, authenticate the F5/F6 executor address and runtime code hash, retain the canonical empty storage root, and carry no unused storage proofs. It detects persistent deployment drift at the authenticated post-state; it is not an intra-block execution trace and does not independently prove the runtime code at every earlier transaction index. Settlement interpretation therefore remains explicit code-hash-bound model authority.

The transaction and receipt proofs use `RLP(transaction_index)` as the trie key and must authenticate exact values under the header roots. The transaction bytes must equal the exact F6 signed transaction and reproduce its transaction hash. The receipt must be a canonical type-2 receipt. A nonzero transaction index requires the immediately preceding authenticated receipt so individual gas is the exact cumulative-gas difference.

## Receipt and fee rules

Receipt status is exactly zero or one. Receipt log-count and per-log topic-count ceilings are enforced before canonicalization or topic materialization. Canonical log-array hashing is incremental and rejects the collection before whole-array materialization when the global canonical JSON byte ceiling would be exceeded. Log emitters are consensus `Bytes20` values and may be zero; nonzero identity rules apply only where a governed deployment or token contract requires them. Logs, log topics, data, bloom, raw receipt bytes, and canonical log digests are recomputed. Every target-receipt bloom bit must also be present in the authenticated block-header bloom. Gas must remain between the F6 intrinsic-gas floor and transaction gas limit. Effective gas price is:

```text
base_fee + min(max_priority_fee, max_fee - base_fee)
```

All arithmetic is exact checked integer arithmetic. Recorded L1-data and OP Stack operator fees are separate inputs. Ethereum requires both to be zero. Actual recorded native costs may not exceed the inherited F4 conservative upper bounds.

## Settlement rules

The receipt must contain exactly one governed settlement event from the authenticated executor address. Event interpretation is selected by exact non-empty executor runtime code hash and inclusion-block validity; the canonical empty-code hash cannot authorize a settlement model. The event must reconcile the exact F4 plan, authenticated F5/F6 sender, base token, route output, flash principal, flash fee, residual before external costs, minimum final output, direct payment, and transaction simulation agreement.

The code-hash-bound event model explicitly states that any unused `msg.value` is returned to the authenticated sender; decoded topic0, indexed topics, and ABI data must reconstruct the exact authenticated log. The settlement event is evidence about the governed executor interface. It is not a general token-balance proof and does not by itself establish treasury accounting, fiat value, taxes, or realized profit.

## Authority boundary

```text
network_access            = none
relay_access              = none
credential_authority      = none
key_authority             = none
local_signing_authority   = none
submission_authority      = none
execution_authority       = none
inclusion_authority       = offline-authenticated-transaction-receipt-and-executor-post-state-inclusion-only
settlement_authority      = offline-code-hash-bound-executor-event-reconciliation-only
realized_outcome_authority= authenticated-inclusion-receipt-code-hash-bound-settlement-and-recorded-rollup-fees-only
realized_profit_authority = none
inclusion_guarantee       = none
```

## Schema graph

Every F7 `$ref` is resolved according to JSON Schema 2020-12 URI rules. Relative references must resolve to the target schema's declared `$id`; inherited F2 evidence uses its canonical absolute identifier. A file that merely exists at a matching path is not sufficient authority.
