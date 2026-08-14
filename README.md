# Aladdin MEV Engine

Aladdin MEV Engine is a governed, safety-first foundation for authenticated state, exact market mathematics, conservative cost accounting, and evidence-backed MEV research.

## Current status

**F4 is an offline, recorded-input, cost-complete shadow economics foundation.** It retains accepted F0-F3 authority and adds:

- chain-bound native/ERC-20 asset identities;
- exact directional valuation sets with checked-`uint256` ceiling conversion;
- deterministic plans derived from exact F3 routes;
- explicit inventory or flash-loan funding and fees;
- EIP-1559/Base upper-bound cost accounting;
- time-valid simulations with distinct implementation and result-source identities;
- exact reserve-category and base-token cost reconciliation;
- source-bound chain-health evidence and recomputed risk-budget snapshots;
- transitive final-time validity checks;
- cost-complete shadow net-profit evidence with source-bound chain health and checked, recomputed risk-budget context.

Every F4 output remains:

```text
cost_completeness = complete-recorded-upper-bound-no-inclusion-guarantee
execution_eligible = false
signing_authority = none
inclusion_guarantee = false
```

F4 supports Ethereum and Base cost envelopes because F3 authenticated opportunities are limited to those proof-enabled chains. It does not connect to a network, acquire live state, construct calldata or transactions, hold keys, sign, submit bundles, deploy contracts, move funds, or guarantee profit.

## Local validation

Python 3.13 is the governed conformance runtime. F4 has no third-party runtime dependencies.

```bash
make all
```

## Architecture

Start with:

- [`governance/ARCHITECTURE.md`](governance/ARCHITECTURE.md)
- [`governance/F4_COST_COMPLETE_PROFIT.md`](governance/F4_COST_COMPLETE_PROFIT.md)
- [`governance/F4_ACCEPTANCE.md`](governance/F4_ACCEPTANCE.md)
- [`governance/F3_AUTHENTICATED_OPPORTUNITY_GRAPH.md`](governance/F3_AUTHENTICATED_OPPORTUNITY_GRAPH.md)
- [`governance/THREAT_MODEL.md`](governance/THREAT_MODEL.md)

## Security

Never commit credentials, wallet material, deployment authority, or production configuration. See [`SECURITY.md`](SECURITY.md).
