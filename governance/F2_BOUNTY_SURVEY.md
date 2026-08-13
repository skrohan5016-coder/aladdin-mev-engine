# F2 Bounty and Keeper Opportunity Survey

Research cut: 2026-08-13. This survey distinguishes protocol-defined rewards from executable, net-profitable opportunities.

## Implemented first: permissionless liquidation discovery

### Aave V3

Aave liquidations are permissionless. A liquidator repays debt and receives collateral plus a liquidation bonus when the account is below the liquidation threshold. The official documentation also describes the market as highly competitive. The current Aave V3.7 Origin source is pinned because source code, not a prose approximation, controls the equality boundary.

**F2 decision:** implement offline eligibility and gross-edge discovery. Defer deployment authentication, borrower enumeration, state proofs, simulation, and execution.

### Morpho Blue

Morpho Blue allows a third party to repay debt and seize discounted collateral. The core source makes equality healthy after protocol-favoring rounding, so F2 uses `borrowed > maxBorrow`, not a loose `>=` prose approximation. Morpho's own liquidation-bot repository warns that gas, failed transactions, malicious markets, and pricing can produce losses.

**F2 decision:** implement offline eligibility and gross-edge discovery with exact source semantics. Require external deployment and valuation evidence.

## High-value next candidate: Beefy harvest caller fees

Beefy documents decentralized `harvest()` calls where callers can receive a portion of harvested yield, and its Cowllector compares expected caller reward against gas before acting. This is closer to a low-capital “action-cost fee” than lending liquidation.

**Deferred reason:** the current strategy allowlist has no keeper/harvest-call strategy, and F1 does not yet ingest vault reward, pending harvest, or strategy simulation state. Adding it silently under `liquidation` would violate governance. A dedicated future milestone should add a `keeper-call-fee` policy contract and Beefy-specific recorded-source/state contracts.

## Additional liquidation reward candidate: Liquity V2

Liquity V2 documents gas compensation for a liquidation initiator. Its Stability Pool, branch-specific collateral, redistribution, and liquidation ordering require a dedicated protocol state model.

**Deferred reason:** bespoke state and transaction semantics are not represented by the generic Aave/Morpho metric contract.

## Deferred legacy keeper market: Synthetix Perps V2

Published V2 documentation describes keeper rewards for order execution and liquidations, but the material is legacy-version specific. Current deployment and market status must be authenticated before engineering against it.

## Not treated as hourly bot bounty

- security bug-bounty programs reward vulnerability reports, not routine on-chain actions;
- bridge relaying can earn fees but requires inventory and carries fill, rebalancing, and finality risk;
- advertised reward size alone is insufficient without gas, slippage, inclusion competition, revert probability, capital lock, and opportunity frequency.

## Ranking for the roadmap

1. Aave V3 and Morpho Blue liquidation discovery — now implemented in F2.
2. Beefy caller-fee keeper discovery — strongest next low-capital research candidate, but requires a governed strategy addition.
3. Liquity V2 liquidation initiator compensation — protocol-specific adapter after proof-backed state interpretation.
4. Other keeper markets — only after current deployment and source contracts are authenticated.

No item in this survey is an income guarantee.
