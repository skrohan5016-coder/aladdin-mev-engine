# Aladdin MEV Engine

Aladdin MEV Engine is a governed, safety-first foundation for multi-chain opportunity discovery, deterministic replay, conservative profit analysis, and evidence-backed strategy development.

## Current status

**F1 is an offline, recorded-input, shadow-observation foundation.** It extends the accepted F0 safety contracts with:

- nine explicit Ethereum, Base, Arbitrum, and BNB Smart Chain recorded-source contracts;
- exact event/finality/visibility authorization rather than permissive cross-products;
- canonical immutable observation envelopes;
- contiguous per-source sequencing across sealed segments;
- per-record and cross-segment SHA-256 chains;
- deterministic JSONL replay;
- no-follow, no-overwrite, read-only, single-link segment storage with stable-path and optional external-digest verification;
- exact-stream, reorg-aware EVM head evidence bound to its triggering observation;
- exact-source-head and merge-integration CI.

This repository still contains no live RPC client, endpoint credentials, transaction signer, private-key handler, bundle submitter, contract deployer, or mainnet execution path.

The system does not promise hourly income or guaranteed market opportunities. Its enforceable objective is to reject untrusted observations and candidates that fail source, integrity, simulation, freshness, profitability, or risk gates.

## Repository boundaries

`aladdin-mev-engine` is independent from `aladdin-auction-solver`. No wallet, signer, deployment authority, treasury authority, or execution state is shared between the projects.

F1 covers recorded EVM-chain observations only. Solana remains a separate future adapter and fails closed in this milestone.

## Local validation

Python 3.13 is the governed conformance runtime. F1 has no third-party runtime dependencies.

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
```

## Architecture

Start with:

- [`governance/ARCHITECTURE.md`](governance/ARCHITECTURE.md)
- [`governance/F1_SOURCE_CONTRACTS.md`](governance/F1_SOURCE_CONTRACTS.md)
- [`governance/F1_OBSERVATION_LEDGER.md`](governance/F1_OBSERVATION_LEDGER.md)
- [`governance/F1_ACCEPTANCE.md`](governance/F1_ACCEPTANCE.md)
- [`governance/PROFIT_SAFETY.md`](governance/PROFIT_SAFETY.md)
- [`governance/THREAT_MODEL.md`](governance/THREAT_MODEL.md)
- [`governance/STRATEGY_POLICY.md`](governance/STRATEGY_POLICY.md)

## Security

Never commit credentials, RPC secrets, private keys, seed phrases, builder authentication material, deployment authority, or production configuration. See [`SECURITY.md`](SECURITY.md).
