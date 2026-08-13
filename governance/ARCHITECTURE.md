# F0 Governed Architecture

## Mission

F0 establishes a deterministic, offline authority for strategy policy, conservative profit assessment, risk-state transitions, evidence canonicalization, and repository safety. It does not observe a live chain and cannot sign or submit a transaction.

## Trust boundaries

```text
Untrusted candidate JSON
        │
        ▼
Bounded stable reader ── duplicate/float/depth/size rejection
        │
        ▼
Canonical domain model ── known chain + known strategy + exact integers
        │
        ▼
Independent simulation evidence
        │
        ▼
Profit firewall ── freshness + health + risk + bid + return gates
        │
        ▼
Digest-addressed evidence ledger
        │
        ▼
No executor in F0
```

## Components

1. **Domain authority** — closed enums for chains, strategies, health, and operating modes.
2. **Canonical JSON authority** — strict UTF-8, duplicate-key rejection, no floats, governed depth/item/byte ceilings that callers cannot raise, deterministic key ordering, SHA-256 identity.
3. **Profit firewall** — all values are exact integers in one declared settlement asset; every modeled cost and reserve is deducted before approval.
4. **Risk governor** — every instance starts in `STOPPED`; promotion requires exact governed event/context types, human approval, and acceptance evidence; critical events halt immediately; neither recovery nor stop-and-restart may bypass closed incident evidence.
5. **Strategy policy** — allowlisted strategies are shadow-only in F0; harmful and unknown strategies fail closed.
6. **Evidence authority** — every decision is recomputed from the bound costs, policy, state age, chain health, risk budget, and successful independent simulations; callers cannot inject an approval.
7. **Reservation authority** — pending execution-cost budgets are bound to unique reservation identities and can only be released by settling that exact identity.
8. **Repository policy gate** — rejects workflow secrets, non-allowlisted or unpinned actions, write permissions, network/publication commands, signing/network dependencies, suspicious credential material, invalid schemas, and architecture-lock drift. Pull requests test their immutable source head and GitHub merge revision independently.

## Future implementation boundary

Production observation and low-latency execution are expected to use a Rust core with chain-specific adapters. Those later components must implement the F0 schemas and invariants rather than redefining them. Solana is a separate non-EVM adapter and must not be represented as an EVM compatibility layer.

## External capability research anchors

These links are research inputs, not enabled integrations:

- Flashbots searcher documentation: https://docs.flashbots.net/
- Base Flashblocks API: https://docs.base.org/base-chain/api-reference/flashblocks-api/flashblocks-api-overview
- Arbitrum Timeboost: https://docs.arbitrum.io/how-arbitrum-works/timeboost/gentle-introduction
- BNB Smart Chain proposer-builder separation: https://docs.bnbchain.org/bnb-smart-chain/validator/mev/overview/
- Jito low-latency transaction send: https://docs.jito.wtf/lowlatencytxnsend/

Every future adapter must re-verify current official documentation at implementation time.
