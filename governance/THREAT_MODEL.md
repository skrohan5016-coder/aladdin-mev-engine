# Threat Model

## Protected assets

Inherited F0-F4 evidence and economics; executor interface/deployment identity; calldata and route-command integrity; authenticated sender nonce and balance; EIP-1559 signing-preimage integrity; bundle ordering and target bounds; simulation independence; honest separation of an unsigned package from signing, submission, execution, and inclusion authority; future keys and funds.

## Inherited failure modes remain active

F5 does not replace earlier controls. Canonical-JSON ambiguity, ledger truncation, source drift, reorg errors, malformed RLP/MPT proofs, state-anchor mismatch, pool code-hash/model ambiguity, optimizer errors, valuation/cost errors, stale simulations/context, and false F4 profit approval remain governed by accepted milestone contracts and regression tests.

## F5 failure modes

- an unproved, unregistered, wrong-chain, wrong-address, proxy, empty-code, non-empty-storage, expired, or conflicting executor deployment;
- one runtime code hash assigned conflicting interfaces;
- caller-supplied arbitrary calldata, disconnected/reused route bytes, base-token or principal drift, broken amount flow, funding kind/provider/source, or transaction-value semantics that do not reconcile with F4 and the executor interface;
- floor-rounded minimum output, a deadline, or proof-observation ordering that weakens accepted F4 economics;
- sender nonce, account type, balance, or anchor spoofing;
- non-canonical type-2 transaction encoding, a gas limit below intrinsic gas, fee-field drift, hidden access-list data, or a signature smuggled into evidence;
- underfunding one transaction or the aggregate complete bundle for gas, direct payment, Base L1 cost, or configurable OP Stack operator fee;
- stale-anchor, duplicate, cross-chain, cross-sender, cross-anchor, non-contiguous, or unbounded bundle entries;
- relay endpoints or credentials entering evidence;
- simulations agreeing only by display name while sharing implementation/source authority;
- simulations bound to the wrong anchor, transaction, signing hash, bundle, simulated block/timestamp/base fee, sub-intrinsic or over-limit gas, operator fee, route output asset/amount, principal repayment, flash fee, residual, base-token beneficiary or beneficiary delta, logs, deltas, post-state, payment, validity interval, or created before the bundle intent;
- an unsigned package presented as permission to sign, submit, deploy, or trade;
- CI command, action, runner, shell, environment, permission, condition, timeout, or error-handling bypass.

## Controls

Exact runtime types; closed schemas; constructor-time recomputation; F2 deployment and EOA proofs with proof-time causality; exact registry membership, one-code-hash/one-interface authority, canonical empty executor storage, runtime-bound flash-loan provider/source identity, and fixed `msg.value` direct-payment semantics; fixed selector and ABI layout; plan-derived binary commands; public raw-frame validation for unique pools, exact base-token endpoints, principal/amount continuity, and exact final minimum; ceiling-rounded F4-preserving output floors; checked integer arithmetic; explicit separate L1-data, operator-fee, and direct-payment bounds; canonical intrinsic gas, RLP, and legacy Keccak; empty access list; authenticated-start contiguous nonce, block-distance, and one-second anchor-freshness gates; aggregate bundle balance coverage including the operator-fee upper bound; no endpoint/credential fields; distinct implementation/source simulation agreement with explicit block/timestamp/base-fee and operator-fee context, flash-loan repayment, authenticated-sender beneficiary, and complete residual-delta reconciliation; transitive validity checks; immutable locks; hardened read-only CI.

## Residual risks

F5 uses recorded state, deployment specifications, registry-declared direct-runtime semantics, fee bounds, bundle targets, and simulation results. It does not independently classify arbitrary runtime bytecode as non-proxy or non-upgradeable, prove live lender availability or fee stability, or govern own-inventory ERC-20 balances and allowances. It does not prove a live RPC or relay view, production token behavior, mempool competition, builder/sequencer acceptance, available funds at submission time, key custody, signature correctness, transaction inclusion, or realized profit. Those require later explicitly governed milestones and separate human approval.
