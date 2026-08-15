# F7 Acceptance Contract

F7 is accepted only when one exact source head and its current GitHub synthetic merge independently satisfy every requirement below.

## Required implementation

- exact accepted F6 parent identity;
- canonical typed/legacy receipt decoding, exact raw-byte reconstruction, consensus-exact `Bytes20` log-address handling, pre-materialization receipt log/topic work ceilings, and a global canonical-log-array byte ceiling enforced before whole-array allocation;
- exact log bloom, authenticated block-bloom subset, and canonical log digest;
- canonical block-header hash and root-field cross-check;
- exact F2 execution-block state-anchor binding;
- exact inclusion-block executor account, runtime-code-hash, and canonical-empty-storage proof;
- bounded indexed transaction and receipt trie proofs;
- exact F6 signed-transaction inclusion and transaction-hash identity;
- immediately preceding receipt authority for every nonzero transaction index;
- exact cumulative-gas delta, intrinsic/gas-limit bounds, and EIP-1559 effective gas price;
- non-empty runtime-code-hash and block-validity-bound settlement event registry;
- exact plan, beneficiary, asset, principal, fee, unused-`msg.value` refund-semantics, and decoded-log settlement reconciliation;
- successful output, residual, direct-payment, gas, log, and recorded Ethereum/Base rollup-fee drift preserved as explicit historical mismatch, shortfall, overrun, upper-bound, and floor-preservation evidence;
- hard minimum-output and transaction-value caps remain fail-closed while simulation or conservative-bound drift is recorded instead of dropped;
- exact twelve-file F7 schema lock with standard URI-resolvable `$ref`/`$id` authority;
- no network, credential, key, signing, submission, deployment, execution, or realized-profit authority.

## Required adversarial validation

Wrong header hash or root, wrong source/chain/finality, missing executor account, changed or empty settlement-model code hash, non-empty executor storage, malformed RLP, wrong-width log address, bloom drift, schema-identifier drift, wrong transaction or receipt index, missing or non-adjacent previous receipt, malformed or oversized proof, wrong transaction bytes, failed receipt promotion, gas underflow/overflow, transaction fee-cap violation, ambiguous or empty-code event model, wrong executor/log/topic0/data, wrong plan/beneficiary/token/principal/fee, inconsistent settlement arithmetic, output below the governed minimum, direct payment above transaction value, duplicate event, future observation, and authority escalation must fail closed. Successful economic or conservative-bound drift within those hard constraints must remain recordable and must not be silently discarded.

## Required CI

Exact source head and current synthetic merge must separately pass Python compilation, the complete inherited F0–F7 suite, repository policy, architecture lock, source-contract lock, F2/F3/F4/F5/F6/F7 schema locks, and clean-worktree validation using read-only permissions, immutable action pins, fixed hosted runners, and non-persisted checkout credentials.

F7 acceptance proves no live submission, future inclusion, token-balance accounting, treasury settlement, or realized profit. Those require separately governed evidence and explicit human approval.
