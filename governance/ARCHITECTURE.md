# F1 Governed Observation and Replay Architecture

## Mission

F1 extends the accepted F0 policy, profit, risk, canonicalization, and CI authorities with a deterministic offline authority for recorded multi-chain observations. It does not acquire data from a network and cannot sign, submit, or execute a transaction.

## Trust boundaries

```text
Untrusted recorded upstream JSON
        │
        ▼
Governed source contract ── exact chain + event/finality/visibility triple + limits
        │
        ▼
Canonical observation envelope ── detached payload + sequence + time + digests
        │
        ▼
Per-segment record hash chain ── ordinal + previous digest + envelope digest
        │
        ▼
Cross-segment checkpoint chain ── previous segment + starting/ending source state
        │
        ▼
Sealed immutable file ── no-follow + exclusive publish + read-only + single-link
        │
        ▼
Deterministic replay and EVM head transitions
        │
        ▼
F0 profit/risk/simulation gates
        │
        ▼
No executor in F1
```

## Components

1. **Inherited F0 authority** — strict canonical JSON, exact-integer profit accounting, dual-simulation evidence, strategy policy, risk governor, identity-bound reservations, and repository policy.
2. **Source-contract registry** — nine digest-locked recorded-input contracts for Ethereum, Base, Arbitrum, and BNB Smart Chain.
3. **Exact event-shape authority** — each source permits explicit `(kind, finality, visibility)` triples; independent allowlists cannot combine into unintended permissions.
4. **Observation envelopes** — source identity, chain, source kind, unsigned-64-bit sequence/time, payload bytes, payload digest, and source-contract digest are immutable and canonical.
5. **Control evidence** — source gaps and heartbeats are closed metadata records; unavailable upstream content is never synthesized.
6. **Record chain** — every segment is an ordered SHA-256 chain of closed ledger records.
7. **Segment chain** — each manifest binds the previous segment digest plus complete starting and ending source checkpoints, preserving continuity across files.
8. **Stable storage** — Linux no-follow path traversal, exclusive temporary creation, data/directory `fsync`, no-overwrite publication, read-only mode, single-link checks, stable pathname identity, and optional external payload-digest verification.
9. **Deterministic replay** — mutation, reordering, truncation, excessive record lines, wrong parent, missing prefix, source restart, time regression, framing drift, and authority drift fail closed.
10. **EVM head tracker** — every tracker is bound to one exact source, head kind, finality, and full-visibility stream. Bootstrap, extension, reorg, duplicate, and orphan transitions bind the triggering observation digest and source sequence. Unknown-parent topology is not retained, and rejected inputs are transactional.
11. **Source/architecture locks** — in-process registries, machine-readable governance, and exact SHA-256 identities must agree.
12. **Exact-head CI** — the immutable pull-request source head and GitHub synthetic merge revision are validated independently with read-only permissions.

## Observation scope

F1 governs recorded observations for:

- Ethereum JSON-RPC and Flashbots MEV-Share;
- Base JSON-RPC and Flashblocks;
- Arbitrum HTTP JSON-RPC, sequencer feed, and Timeboost metadata;
- BNB Smart Chain JSON-RPC and PBS metadata.

Solana is intentionally absent. A later non-EVM milestone must define its own slot, account-lock, transaction, and Jito-specific contracts.

## Authority limits

The terms `transport`, `JSON-RPC`, `WebSocket`, `SSE`, `sequencer feed`, and `auction` describe the provenance contract of recorded bytes. They do not enable a client. F1 has:

```text
network_access       = none
signing_authority    = none
execution_authority  = none
observation_authority = recorded-input-only
```

A future collector must be isolated behind these schemas and must not redefine finality, visibility, ordering, or source completeness.

## External capability research anchors

- Ethereum JSON-RPC: https://ethereum.org/en/developers/apis/json-rpc/
- Flashbots MEV-Share: https://docs.flashbots.net/flashbots-mev-share/searchers/getting-started
- Base Flashblocks: https://docs.base.org/base-chain/api-reference/flashblocks-api/flashblocks-api-overview
- Arbitrum chain information: https://docs.arbitrum.io/for-devs/dev-tools-and-resources/chain-info
- Arbitrum feed relay: https://docs.arbitrum.io/run-arbitrum-node/run-feed-relay
- Arbitrum Timeboost: https://docs.arbitrum.io/how-arbitrum-works/timeboost/gentle-introduction
- BNB Smart Chain JSON-RPC: https://docs.bnbchain.org/bnb-smart-chain/developers/json_rpc/json-rpc-endpoint/
- BNB builder integration: https://docs.bnbchain.org/bnb-smart-chain/validator/mev/builder-integration/

Every live adapter must re-verify current official documentation in its own milestone.
