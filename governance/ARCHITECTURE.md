# Aladdin MEV Engine Architecture

## Accepted lineage

F4 is built from accepted F3 landing `046b6b2e39c06feba8eb77da2f2139663e84e50e`, tree `1c94f705477863b62906f5ec6e5a37ad7a850580`, and architecture `AMEV-F3-ARCH-v1-d2caf73e6121`. F0 supplies canonical evidence, profit policy, and risk controls; F1 supplies recorded observation/replay; F2 supplies authenticated EVM state; F3 supplies exact gross opportunities; F4 adds structural plans and cost-complete shadow economics.

## Inherited authority retention

F4 does not weaken or replace the accepted F0-F3 contracts. Their canonical evidence, source registry, tamper-evident replay, reorg handling, authenticated state proofs, code-hash-bound pool models, exact route math, bounded optimizer, and gross-only authority remain independently locked and tested.

## Trust flow

```text
Recorded observations
  -> authenticated state
  -> exact F3 opportunity
  -> structural plan + funding
  -> distinct-implementation/source simulation agreement in one exact environment
  -> exact fee/reserve/valuation reconciliation
  -> source-bound health + recomputed risk snapshot
  -> F0 profit assessment
```

## F4 authority boundaries

```text
network_access          = none
signing_authority       = none
execution_authority     = none
execution_plan_authority= offline-structural-plan-only
simulation_authority    = recorded-distinct-implementation-exact-agreement-only
cost_evidence_authority = offline-recorded-upper-bound-shadow-only
chain_health_authority  = recorded-source-bound-shadow-context-only
risk_budget_authority   = recorded-recomputed-snapshot-shadow-only
```

The architecture manifest and lock are the machine-readable authority.

## F4 hardening invariants

Valuation uses exact required pairs only and checked `uint256` multiplication before ceiling division. Simulations require distinct implementation and result-source digests, one exact environment digest, exact state binding, canonical order, and final-time validity. Chain health and risk budget are source-bound evidence, not bare caller values. Risk aggregation is checked `uint256`, and the risk snapshot cannot predate the exact cost envelope it binds. F4 closes all profit-policy integer inputs to `uint256`. Funding, fee, reserve, valuation, simulation, health, and risk inputs are revalidated at final evidence creation.
