# Aladdin MEV Engine

Aladdin MEV Engine is a governed, safety-first foundation for multi-chain opportunity discovery, deterministic simulation, and evidence-backed strategy development.

## Current status

**F0 is shadow-only.** This repository contains no network client, transaction signer, private-key handler, contract deployer, or mainnet execution path. The first milestone establishes the contracts that every later implementation must obey:

- exact integer profit accounting;
- fail-closed strategy authorization;
- human-gated risk-governor transitions;
- canonical, digest-addressed evidence;
- bounded and stable local JSON ingestion;
- repository and CI security policy;
- explicit ethical strategy boundaries.

The system does not promise hourly income or guaranteed market opportunities. Its safety objective is narrower and enforceable: reject candidates that do not satisfy conservative profit, simulation, freshness, health, and risk-budget gates.

## Repository boundaries

`aladdin-mev-engine` is independent from `aladdin-auction-solver`. No wallet, signer, deployment authority, treasury authority, or execution state is shared between the projects.

## Local validation

Python 3.13 is the governed F0 conformance runtime. F0 has no third-party runtime dependencies.

```bash
make all
```

Equivalent commands:

```bash
PYTHONPATH=src python3 -m compileall -q src tests scripts
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/check_repo_policy.py
PYTHONPATH=src python3 scripts/verify_architecture_lock.py
```

## Architecture

Start with:

- [`governance/ARCHITECTURE.md`](governance/ARCHITECTURE.md)
- [`governance/PROFIT_SAFETY.md`](governance/PROFIT_SAFETY.md)
- [`governance/THREAT_MODEL.md`](governance/THREAT_MODEL.md)
- [`governance/STRATEGY_POLICY.md`](governance/STRATEGY_POLICY.md)
- [`governance/F0_ACCEPTANCE.md`](governance/F0_ACCEPTANCE.md)

## Security

Never commit credentials, RPC secrets, private keys, seed phrases, builder authentication material, deployment authority, or production configuration. See [`SECURITY.md`](SECURITY.md).
