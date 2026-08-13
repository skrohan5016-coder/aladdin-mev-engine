# Strategy Policy

## F0 allowlist

The following strategy identifiers may be researched in **shadow mode only**:

- `atomic-dex-arbitrage`
- `consensual-backrun`
- `liquidation`
- `inventory-assisted-arbitrage`
- `cross-chain-inventory-rebalancing`

No F0 strategy may submit, sign, deploy, or broadcast anything.

## Prohibited

The following strategy classes are outside the project mandate:

- sandwich attacks;
- harmful frontrunning;
- oracle manipulation;
- protocol exploitation;
- mempool spam;
- malicious token deployment;
- stolen-key use.

Unknown strategies fail closed. A later strategy cannot become allowed merely by appearing in data; the closed enum, machine-readable architecture manifest, documentation, tests, and threat model must all change in one governed review.

## Cross-chain rule

Cross-chain activity is modeled as inventory management and later controlled rebalancing. A non-atomic bridge is never treated as an atomic flash-loan leg.
