# F4 Atomic Plans and Cost-Complete Shadow Profit Evidence

## Mission

F4 consumes an exact F3 authenticated gross opportunity and produces a deterministic offline evidence chain:

```text
F3 opportunity
  -> exact structural execution plan
  -> explicit funding plan
  -> independently identified route simulations
  -> EIP-1559, L1-data, and OP Stack operator-fee upper bounds
  -> exact directional valuation set
  -> complete cost-category reconciliation
  -> source-bound chain-health and recomputed risk-budget context
  -> F0 profit-policy assessment
  -> shadow net-profit evidence
```

F4 does not create calldata, sign, submit, deploy, fund, or execute anything. A positive assessment is an offline economics result, not an inclusion guarantee or permission to trade.

## Asset and valuation authority

Every amount carries an exact chain-bound asset identity. Native assets have no address; ERC-20 assets require a non-zero 20-byte address. Costs in another asset cannot be subtracted from route profit until an explicit directional rate converts them into the exact F3 base asset.

Rates are source-bound, time-bounded, one-way, and rounded upward. F4 never infers an inverse rate. The valuation book must contain exactly the conversion pairs consumed by the cost envelope—no missing, ambiguous, inverse, cross-chain, or unrelated rates. The `amount * numerator` intermediate is checked against `uint256` before ceiling division.

## Structural execution plan

The plan recomputes every step from the exact F3 route quote and binds the opportunity, state reference, base asset, funding principal and fee, pool sequence, token directions, amounts, and quote digests. It contains no calldata, target authorization, nonce, signature, transaction, or bundle.

## Fee and cost authority

The EIP-1559 envelope records gas units, `max_fee_per_gas`, and `max_priority_fee_per_gas`. Priority fee is contained inside the max-fee cap and is never added again. L1-data cost, OP Stack operator fee, and direct inclusion payment are three separate recorded upper-bound categories. Ethereum requires both the separate L1-data and operator-fee fields to be zero. Base must record each category explicitly; a zero operator-fee configuration is evidence, not an implicit assumption.

Every cost envelope contains exactly one of each reserve category: slippage, stale state, failure risk, infrastructure, and inventory hedge. Gas, L1 data, operator fee, funding, direct inclusion, and reserve amounts are independently converted into the base token before profit assessment.

Funding, fee, reserve, and every required valuation rate must be valid when the cost envelope is formed and again at the final net-evidence timestamp. The envelope publishes its earliest transitive expiry.

## Simulation authority

Each simulation binds:

- exact opportunity, execution plan, and state-reference digests;
- engine identifier and distinct engine-implementation SHA-256;
- environment SHA-256 and distinct result-source SHA-256;
- gas, output, token-delta, and post-state results;
- observed and valid-until timestamps.

At least two successful simulations with distinct engine implementations and result sources must agree exactly. Their order is canonicalized. Matching failures never approve, stale simulations fail, simulated gas cannot exceed the fee upper bound, and output must equal the exact F3 route output.

## Decision context authority

Bare caller booleans have no decision authority. Final evidence requires:

- source-bound, chain-bound, time-valid chain-health evidence; and
- source-bound risk-budget evidence that recomputes the F0 ledger limits from a recorded snapshot and binds the exact execution plan, total execution cost, and notional.

These contexts remain shadow evidence; they do not reserve funds or authorize execution.

## Chain-health and risk-budget context

Final economics never accepts bare `chain_health` or `risk_budget_available` booleans. Chain health is a source-digest-bound, chain-bound, time-bounded evidence object. Risk budget is recomputed from exact limits, realized P&L, reserved cost, concurrent candidates, requested execution cost, and requested notional. Pending-cost, daily-loss, and concurrency aggregation use checked `uint256` arithmetic. The risk snapshot must be observed no earlier than the exact execution-cost envelope it binds.

All F4 profit-policy integer fields are explicitly closed to `uint256` before inherited assessment.

## Final labels

```text
cost_completeness = complete-recorded-upper-bound-no-inclusion-guarantee
execution_eligible = false
signing_authority = none
inclusion_guarantee = false
decision_authority = shadow-economics-only
```
