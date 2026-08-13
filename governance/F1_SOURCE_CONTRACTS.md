# F1 Multi-Chain Recorded-Source Contracts

## Scope

F1 defines which recorded upstream observations may enter the Aladdin MEV evidence system. It does not open a socket, authenticate to a provider, poll an endpoint, sign a request, submit a transaction, or infer unavailable private data.

Every observation binds both a `source_id` and the SHA-256 digest of that source contract. A source contract fixes:

- chain and source family;
- transport family;
- an exact allowlist of `(event kind, finality, visibility)` triples;
- canonical payload and clock-skew ceilings;
- whether partial payloads are expected;
- the official specification used to design the contract;
- `network_authority = none-recorded-input-only`.

Allowed event triples are explicit rather than a Cartesian product. For example, a source that permits confirmed full block heads and pending hash-only transactions does not thereby permit confirmed hash-only block heads or finalized pending transactions.

## Governed source set

| Source ID | Chain | Recorded authority | Important boundary |
| --- | --- | --- | --- |
| `ethereum-json-rpc` | Ethereum | Confirmed/finalized heads and pending transaction observations | No provider or mempool-completeness claim |
| `ethereum-mev-share` | Ethereum | Pending MEV-Share transaction hints | Hints may be full, partial, or hash-only; missing fields are never invented |
| `base-json-rpc` | Base | Confirmed/finalized heads and pending transaction observations | Sealed and preconfirmed authorities remain separate |
| `base-flashblocks` | Base | Preconfirmed blocks, transactions, and pending logs | Preconfirmation is not finality |
| `arbitrum-json-rpc` | Arbitrum | Confirmed/finalized heads from general-purpose HTTP JSON-RPC | The official public RPC does not provide WebSocket support |
| `arbitrum-sequencer-feed` | Arbitrum | Preconfirmed sequencer batches | Feed order is recorded; F1 gains no express-lane or submission authority |
| `arbitrum-timeboost-auction` | Arbitrum | Timeboost round/controller metadata | Metadata is not proof of express-lane use or inclusion |
| `bnb-json-rpc` | BNB Smart Chain | Confirmed/finalized heads and pending transaction observations | No public-mempool-completeness claim |
| `bnb-pbs-metadata` | BNB Smart Chain | Builder/PBS status metadata | Builder metadata is not block-inclusion or profitability authority |

Every source also permits the closed metadata controls `source-gap` and `source-heartbeat`. Solana remains outside F1 and fails closed instead of being forced through an EVM source contract.

## Official research references

- Ethereum JSON-RPC: https://ethereum.org/en/developers/apis/json-rpc/
- Flashbots MEV-Share event stream: https://docs.flashbots.net/flashbots-mev-share/searchers/getting-started
- Flashbots MEV-Share hint semantics: https://docs.flashbots.net/flashbots-mev-share/searchers/understanding-bundles
- Base WebSocket subscriptions: https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_subscribe
- Base Flashblocks API: https://docs.base.org/base-chain/api-reference/flashblocks-api/flashblocks-api-overview
- Arbitrum chain/RPC information: https://docs.arbitrum.io/for-devs/dev-tools-and-resources/chain-info
- Arbitrum feed relay: https://docs.arbitrum.io/run-arbitrum-node/run-feed-relay
- Arbitrum Timeboost: https://docs.arbitrum.io/how-arbitrum-works/timeboost/gentle-introduction
- BNB Smart Chain JSON-RPC: https://docs.bnbchain.org/bnb-smart-chain/developers/json_rpc/json-rpc-endpoint/
- BNB builder integration: https://docs.bnbchain.org/bnb-smart-chain/validator/mev/builder-integration/

These are design references, not enabled integrations. A future live adapter must re-verify the then-current official specification and pass a separate governed milestone.
