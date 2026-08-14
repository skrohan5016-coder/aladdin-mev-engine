# Strategy Policy

The governed shadow research identifiers remain:

- `atomic-dex-arbitrage`
- `consensual-backrun`
- `liquidation`
- `inventory-assisted-arbitrage`
- `cross-chain-inventory-rebalancing`

F3 implements only authenticated, model-bound, gross-only constant-product `atomic-dex-arbitrage` opportunity construction. No F3 strategy may submit, sign, deploy, broadcast, or execute anything.

Prohibited classes remain sandwich attacks, harmful frontrunning, oracle manipulation, protocol exploitation, mempool spam, malicious token deployment, and stolen-key use. Unknown strategies fail closed.

An explicit model registry is evidence identity, not production approval. A positive F3 result is exact gross mathematics under authenticated reserves and explicit assumptions; it is never net profit or execution authority.
