# F7 Scope — Authenticated Inclusion, Receipt, and Execution-Outcome Evidence

## Accepted parent

- F6 landing commit: `6481e17b2345c54261865125b61523610b7f87af`
- F6 tree: `1115dccd7952225dfa1d58238aa550bf9e0aa995`
- F6 architecture: `AMEV-F6-ARCH-v1-c91039d7d800`

## Mission

F7 takes one exact F6 externally signed package and recorded post-block evidence and determines, offline, whether the exact signed type-2 transaction is authenticated in the block transaction trie, whether its exact receipt is authenticated in the receipt trie, what gas it consumed, and whether one code-hash-bound executor settlement event preserves the inherited hard plan constraints while recording favorable or adverse economic and cost drift.

F7 does not connect to a chain, poll a relay, submit a transaction, hold a key, sign, deploy, move funds, or assert realized profit. All block headers, trie proofs, receipts, settlement logs, and rollup fee values are recorded inputs.

## Implemented authority

- canonical EIP-2718 receipt decoding with exact RLP reconstruction, consensus-exact `Bytes20` log addresses including zero, pre-materialization log/topic work ceilings, and bounded incremental canonical log-array hashing;
- exact receipt-log bloom, authenticated block-bloom subset, and canonical log-digest recomputation;
- block-header legacy-Keccak verification and cross-check of parent, state, transaction, and receipt roots;
- exact F2 state-anchor binding for Ethereum and Base execution blocks;
- exact inclusion-block executor account proof preserving the F5/F6 address, runtime code hash, and canonical empty storage root;
- bounded indexed transactions-trie and receipts-trie proof evidence;
- exact F6 signed-transaction inclusion at one transaction index;
- immediately preceding receipt proof for nonzero indices and exact cumulative-gas delta;
- authenticated EIP-1559 effective-gas-price and execution-gas-cost reconciliation;
- one runtime-code-hash/time-bound executor settlement-event registry that rejects the canonical empty-code hash;
- exact hard settlement binding for plan, beneficiary, base token, principal, flash-loan fee, minimum output, transaction-value cap, internal residual arithmetic, and explicit unused-`msg.value` refund semantics;
- successful output, residual, direct-payment, gas, log, and L1-data/operator-fee drift retained through explicit simulation-match, residual-shortfall, native-cost-overrun, upper-bound, and conservative-floor fields;
- final execution-outcome evidence that preserves adverse historical records but never claims realized profit;
- a standard-resolvable twelve-schema F7 graph whose `$ref` targets match declared canonical `$id` values.

## Non-goals

- live RPC, builder, relay, sequencer, or explorer access;
- block, transaction, receipt, fee, or log polling;
- private keys, signing, HSM/KMS, or wallet custody;
- transaction or bundle submission;
- inclusion guarantees before a recorded authenticated block exists;
- token-balance or treasury-accounting proofs outside the governed executor event;
- realized profit, tax, accounting, or fiat-value claims;
- deployment or execution authority.

## Acceptance contract

Every F7 object is exact-type checked, canonical-JSON digest addressed, byte/work bounded, closed by JSON Schema, bound by the canonical F7 schema lock, adversarially tested, and independently validated on the exact source head and GitHub synthetic merge. A successful F7 outcome proves only the governed recorded facts and remains incapable of signing, submitting, executing, or guaranteeing profit.
