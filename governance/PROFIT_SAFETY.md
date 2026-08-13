# Profit-Safety Contract

## Non-guarantee

The system cannot guarantee that a market opportunity exists, that a builder or sequencer includes a candidate, or that a fixed hourly income is produced. F0 instead defines enforceable conditions under which a candidate must be rejected.

## Accounting unit

Every field in one assessment is a non-negative integer measured in the same explicitly selected settlement asset atomic unit. Floating-point money is forbidden. Cross-asset normalization belongs to a future authenticated pricing layer and cannot be silently inferred.

## Conservative formula

```text
conservative_net_profit = gross_profit
                        - execution_gas_cost
                        - l1_data_fee
                        - flash_loan_fee
                        - inclusion_bid
                        - slippage_reserve
                        - stale_state_reserve
                        - failure_risk_reserve
                        - infrastructure_cost
                        - inventory_hedge_cost
```

A candidate is approved only when all of the following hold:

- gross profit is positive;
- two or more independently identified simulations all succeed and agree exactly;
- chain health is healthy;
- state age is at or below policy;
- risk budget is available;
- inclusion bid is at or below its fraction of pre-bid surplus;
- conservative net profit meets the absolute threshold;
- conservative net profit meets the return threshold by integer cross-multiplication.

Unknown, missing, stale, contradictory, negative, floating-point, or differently denominated values fail closed.

## No forced trading

No chain, strategy, hour, or day has a required trade count. `no-trade` is the correct result whenever a gate fails. Revenue targets never override the firewall.

## Realized evidence

Later milestones must separate detected, simulated, submitted, landed, and realized values. Hypothetical opportunity value must never be counted as realized profit.
