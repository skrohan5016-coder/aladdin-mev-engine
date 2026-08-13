# Aladdin MEV Engine

Aladdin MEV Engine is a governed, safety-first foundation for multi-chain opportunity discovery, deterministic replay, authenticated EVM state analysis, conservative profit accounting, and evidence-backed strategy development.

## Current status

**F2 is an offline, recorded-input, authenticated-state foundation.** It retains the accepted F0 safety contracts and F1 observation ledger, then adds:

- Ethereum legacy Keccak-256 implemented without a runtime dependency and locked by known vectors;
- canonical bounded Recursive Length Prefix encoding and decoding;
- canonical Merkle Patricia Trie inclusion and non-inclusion proof verification;
- exact block-number, block-hash, finality, source, sequence, timestamp, and state-root anchors;
- EIP-1186-shaped account and storage proof verification for governed Ethereum and Base sources;
- proof evidence that is always recomputed from the exact bound anchor and proof observation;
- deterministic, digest-addressed multi-account state snapshots;
- explicit fail-closed capability gating for unsupported chains;
- separate exact-source-head and GitHub merge-integration CI.

F2 records block state roots for Ethereum, Base, Arbitrum, and BNB Smart Chain. Authenticated account/storage proofs are enabled only for the governed Ethereum and Base JSON-RPC sources. Arbitrum and BNB proof verification remain disabled until their official proof capability and semantics are governed in a later milestone. Solana remains a separate non-EVM adapter.

This repository still contains no live RPC client, endpoint credential, transaction signer, private-key handler, bundle submitter, contract deployer, or mainnet execution path.

The system does not promise hourly income or guaranteed market opportunities. Its enforceable objective is to reject observations, state claims, simulations, and candidate trades that fail integrity, freshness, source, proof, profitability, or risk gates.

## Repository boundaries

`aladdin-mev-engine` is independent from `aladdin-auction-solver`. No wallet, signer, deployment authority, treasury authority, or execution state is shared between the projects.

## Local validation

Python 3.13 is the governed conformance runtime. F2 has no third-party runtime dependencies.

```bash
make all
```

Equivalent commands:

```bash
PYTHONPATH=src python3 -m compileall -q src tests scripts
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/check_repo_policy.py
PYTHONPATH=src python3 scripts/verify_architecture_lock.py
PYTHONPATH=src python3 scripts/verify_source_contracts.py
python3 scripts/verify_f2_schemas.py
```

## Architecture

Start with:

- [`governance/ARCHITECTURE.md`](governance/ARCHITECTURE.md)
- [`governance/F2_AUTHENTICATED_STATE.md`](governance/F2_AUTHENTICATED_STATE.md)
- [`governance/F2_ACCEPTANCE.md`](governance/F2_ACCEPTANCE.md)
- [`governance/F1_SOURCE_CONTRACTS.md`](governance/F1_SOURCE_CONTRACTS.md)
- [`governance/F1_OBSERVATION_LEDGER.md`](governance/F1_OBSERVATION_LEDGER.md)
- [`governance/PROFIT_SAFETY.md`](governance/PROFIT_SAFETY.md)
- [`governance/THREAT_MODEL.md`](governance/THREAT_MODEL.md)
- [`governance/STRATEGY_POLICY.md`](governance/STRATEGY_POLICY.md)

## Security

Never commit credentials, RPC secrets, private keys, seed phrases, builder authentication material, deployment authority, or production configuration. See [`SECURITY.md`](SECURITY.md).
