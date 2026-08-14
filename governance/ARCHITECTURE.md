# F3 Governed Authenticated Opportunity Architecture

## Mission

F3 extends accepted F0 policy/profit/risk authority, accepted F1 observation/replay authority, and accepted F2 authenticated EVM state with deterministic offline construction of model-bound constant-product pool universes, simple arbitrage routes, exact integer route optimization, and gross-only shadow opportunities.

All chain inputs remain recorded observations. F3 does not connect to a chain, establish token semantics, estimate gas or inclusion, sign, submit a bundle, deploy a contract, or execute a trade.

## Trust boundaries

```text
F2 authenticated account + storage evidence
        │
        ├── exact address + runtime code hash
        ├── authenticated token identities
        └── authenticated packed reserves
        ▼
Explicit one-code-hash/one-model registry
        │
        ▼
Exact snapshot-bound pool universe
        │
        ▼
Deterministic simple-cycle graph (2..4 hops, no pool reuse)
        │
        ▼
Exact per-hop integer floor quotes
        │
        ├── continuous upper bound for pruning only
        └── bounded deterministic exact optimizer
        ▼
Complete positive gross-only shadow opportunity
        │
        ▼
execution_eligible = false
```

## Components

1. Inherited F0 canonical, profit, evidence, policy, risk, and CI authority.
2. Inherited F1 source-contract, ledger, replay, and head authority.
3. Inherited F2 legacy Keccak, canonical RLP/MPT, proof, anchor, and snapshot authority.
4. Runtime-code-hash-bound constant-product implementation models.
5. One-code-hash/one-model registry with exact fee and storage-layout identity.
6. Authenticated token and packed-reserve decoding from exact F2 evidence.
7. Checked `uint256` and packed-reserve input-domain gates.
8. Exact-snapshot pool universe with no missing or extra accounts.
9. Deterministic two-to-four-hop simple-cycle enumeration with bounded traversal work.
10. Exact per-hop floor route quoting.
11. Concave `A*x/(B+C*x)` upper bounds used only for pruning.
12. Bounded exact optimizer with smaller-input tie-breaking.
13. Opportunity and search-report evidence that recompute authoritative results.
14. Ten-file F3 schema lock including the inherited opportunity schema dependency.
15. Separate exact-head and synthetic-merge CI, locked to the hosted `ubuntu-latest` runner, exact action inputs, one exact top-level environment, default shell semantics, one merge-job condition, and ten-minute timeouts. Custom shells, defaults, containers, services, job/step environments, strategies, dependencies, working directories, job permissions, and `continue-on-error` are forbidden.

## Authority limits

```text
network_access         = none
signing_authority      = none
execution_authority    = none
observation_authority  = recorded-input-only
state_proof_authority  = offline-recorded-input-only
opportunity_authority  = offline-authenticated-model-bound-gross-shadow-only
production_model_lock  = none
```

An explicit model registry is evidence identity, not production approval. A later milestone must govern deployed model identities, token behavior, EVM simulation, gas, inclusion, funding, signing, and execution before any F3 result can influence a transaction.

## Chain scope

| Chain | F2 authenticated proof | F3 pool opportunity | Execution |
|---|---:|---:|---:|
| Ethereum | Enabled | Model-bound shadow only | Disabled |
| Base | Enabled | Model-bound shadow only | Disabled |
| Arbitrum | Disabled | Disabled | Disabled |
| BNB Smart Chain | Disabled | Disabled | Disabled |
| Solana | Separate scope | Disabled | Disabled |

## Exact mathematics

```text
amount_in_with_fee = amount_in * fee_numerator
amount_out = floor(
    amount_in_with_fee * reserve_out
    / (reserve_in * fee_denominator + amount_in_with_fee)
)
```

Every modeled multiplication and addition must fit checked `uint256`; the post-input reserve must fit its authenticated packed field. Floating-point values never enter authoritative money math.
