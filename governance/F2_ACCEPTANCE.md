# F2 Acceptance Contract

## Identity

- Repository: `skrohan5016-coder/aladdin-mev-engine`
- Accepted starting main: `f1ce79430bf6d4d4857e4c6ee83fca766b68082c`
- Accepted starting tree: `855a53af31cca7fdae064377309c756b048c0654`
- Accepted parent architecture: `AMEV-F1-ARCH-v1-e0cc085585eb`
- Working branch: `agent/f2-authenticated-evm-state-v1`
- Milestone: `F2 — Authenticated EVM State Proofs and Canonical State Snapshots`

## Required gates

- All inherited F0/F1 and F2 unit/adversarial tests pass.
- Ethereum legacy Keccak-256 matches governed known vectors and differs from NIST SHA3-256 where expected.
- RLP rejects nonminimal, malformed, oversized, over-deep, over-item, and trailing-byte inputs.
- MPT verification accepts governed inclusion/non-inclusion fixtures and rejects missing, duplicate, reordered, extraneous, malformed, and tampered nodes.
- Block-state anchors bind one exact source, chain, finality, block number/hash, source sequence, observation time, and state root.
- Account and storage evidence is recomputed from exact bound observations; derived authority cannot be injected.
- Zero storage is accepted only by authenticated non-inclusion.
- Ethereum/Base proof capability is enabled; Arbitrum/BNB/Solana proof capability fails closed.
- Four F2 schemas and both updated inherited schemas pass the closed-schema verifier and match `governance/f2-schemas.lock.json`.
- Source-contract registry, architecture manifest, and their SHA-256 locks agree.
- Runtime dependencies remain empty.
- Repository policy rejects credentials, network/signing/execution dependencies, mutable actions, write permissions, and unapproved workflow commands.
- Exact source-head and GitHub synthetic-merge revisions are validated independently.

## Explicit non-acceptance

Passing F2 does not authorize live data collection, RPC credentials, signing, wallet access, transaction or bundle submission, deployment, canary trading, live trading, or profitability claims.
