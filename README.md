# Aladdin MEV Engine

Aladdin MEV Engine is a governed, safety-first foundation for multi-chain observation, deterministic replay, opportunity discovery, conservative profit analysis, and evidence-backed strategy development.

## Current status

**F2 is an offline, recorded-input, shadow liquidation-discovery milestone.** It inherits F0 safety contracts and F1 observation/replay, then adds:

- source-pinned Aave V3 and Morpho Blue liquidation mechanism contracts;
- exact integer threshold comparators with source-correct equality behavior;
- provenance-bound liquidation snapshots;
- canonical deployment, state, observation, and valuation evidence identities;
- deterministic candidate/rejection decisions;
- a same-unit positive gross-edge gate;
- candidate identities bound to the complete snapshot and mechanism digests;
- exact-source-head and merge-integration CI.

The repository still contains no live RPC client, endpoint credential, wallet, signer, private-key handler, deployment registry, transaction builder, bundle submitter, contract deployer, or mainnet execution path.

A liquidation candidate is not a profit or execution approval. It must still pass independent simulation, freshness, gas, data fee, flash-loan fee, slippage, inclusion bid, failure-risk, infrastructure-cost, chain-health, and risk-budget gates.

The system does not promise hourly income or guaranteed market opportunities.

## Bounty research result

F2 implements Aave V3 and Morpho Blue liquidation discovery first because liquidation is already on the governed strategy allowlist. The survey also identifies Beefy harvest caller fees as a strong lower-capital next candidate, but it is deliberately deferred until a dedicated keeper strategy and source/state contracts are governed.

See [`governance/F2_BOUNTY_SURVEY.md`](governance/F2_BOUNTY_SURVEY.md).

## Repository boundaries

`aladdin-mev-engine` is independent from `aladdin-auction-solver`. No wallet, signer, deployment authority, treasury authority, or execution state is shared between the projects.

F2 covers recorded EVM-chain state only. Solana remains a separate future adapter and fails closed.

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
PYTHONPATH=src python3 scripts/verify_liquidation_mechanisms.py
```

## Architecture

Start with:

- [`governance/ARCHITECTURE.md`](governance/ARCHITECTURE.md)
- [`governance/F2_LIQUIDATION_DISCOVERY.md`](governance/F2_LIQUIDATION_DISCOVERY.md)
- [`governance/F2_BOUNTY_SURVEY.md`](governance/F2_BOUNTY_SURVEY.md)
- [`governance/F2_ACCEPTANCE.md`](governance/F2_ACCEPTANCE.md)
- [`governance/F1_SOURCE_CONTRACTS.md`](governance/F1_SOURCE_CONTRACTS.md)
- [`governance/F1_OBSERVATION_LEDGER.md`](governance/F1_OBSERVATION_LEDGER.md)
- [`governance/PROFIT_SAFETY.md`](governance/PROFIT_SAFETY.md)
- [`governance/THREAT_MODEL.md`](governance/THREAT_MODEL.md)
- [`governance/STRATEGY_POLICY.md`](governance/STRATEGY_POLICY.md)

## Security

Never commit credentials, RPC secrets, private keys, seed phrases, builder authentication material, deployment authority, or production configuration. See [`SECURITY.md`](SECURITY.md).
