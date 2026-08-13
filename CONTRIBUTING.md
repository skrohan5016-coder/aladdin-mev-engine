# Contributing

All changes must preserve the governed architecture and fail-closed behavior.

## Required before opening a pull request

```bash
make all
```

A pull request must state its base commit, head commit, changed-file scope, security impact, authority impact, and validation evidence.

## Hard rules

- No live network client, signing, broadcasting, deployment, or execution capability may enter F2.
- No secret may be committed, even as a test fixture.
- Monetary values use non-negative integers in one explicitly named settlement asset.
- JSON evidence never uses floating-point numbers.
- Strategy promotion is always human-gated.
- Unknown chains, strategies, fields, states, proof forms, reason codes, transition objects, and raised parser ceilings fail closed.
- Risk governors always start stopped; no constructor or restore shortcut may create an active mode.
- EVM proof code must use Ethereum legacy Keccak-256, canonical RLP, and exact MPT semantics.
- Derived state-proof evidence must be recomputed from exact bound observations.
- State-proof capability is chain-specific; EVM compatibility alone never enables it.
- CI actions are pinned to full commit SHAs and run with read-only repository permissions.
