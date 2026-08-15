# Aladdin MEV Engine

Aladdin MEV Engine is a governed, safety-first foundation for authenticated EVM state, exact market mathematics, conservative economics, replayable transaction evidence, external-signature verification, authenticated historical outcomes, and bias-resistant offline performance evaluation.

## Current status

**F8 is an offline authenticated historical-scoreboard and research-promotion foundation.** It retains F0–F7 and adds:

- exact cohort identity across sender/signature source, policy, relay endpoint/response sources, funding, deployment, settlement model, fee/valuation sources, pool model, finality, environment, and simulator sources;
- settled, reverted, settlement-missing, and settlement-evidence-incomplete historical records with explicit scoreability and outcome completeness;
- receipt-derived settlement-event presence so outcome omission cannot relabel an observed event as missing;
- exact source-window manifests and manifest-consuming corpora that prevent declared incomplete/adverse attempts from silently disappearing;
- explicit `global_completeness_guarantee = false` outside each declared source window, propagated through scoreboards, calibration, expected-value, and promotion evidence;
- one shared historical-valuation policy plus inclusion-time policy-matching conservative rates for scoreable records;
- exact historical-surplus/prediction-error evidence and integer scoreboards with explicit disposition/completeness counts;
- positive-bound calibration buckets, guarded empirical means, and conditional historical expected value with explicit zero-sample unavailability;
- scoreable-coverage, unique-block-diversity, error, cost-overrun, calibration-density, and guarded-surplus research gates;
- explicit denial of confidence, realized-profit, production-promotion, signing, submission, and execution authority.

```text
network_access                        = none
credential_authority                  = none
key_authority                         = none
local_signing_authority               = none
submission_authority                  = none
execution_authority                   = none
realized_profit_authority             = none
production_promotion_authority        = none
```

F8 supports offline Ethereum and Base evidence. It does not poll chains, contact relays, hold keys, sign or submit transactions, deploy contracts, move funds, claim realized profit, or guarantee future performance.

## Local validation

Python 3.13 is the governed conformance runtime. F8 has no third-party runtime dependencies.

```bash
make all
```

## Architecture

Start with:

- [`governance/ARCHITECTURE.md`](governance/ARCHITECTURE.md)
- [`governance/F8_SCOPE.md`](governance/F8_SCOPE.md)
- [`governance/F8_HISTORICAL_SCOREBOARD.md`](governance/F8_HISTORICAL_SCOREBOARD.md)
- [`governance/F8_ACCEPTANCE.md`](governance/F8_ACCEPTANCE.md)
- [`governance/THREAT_MODEL.md`](governance/THREAT_MODEL.md)

## Security

Never commit credentials, wallet material, private keys, RPC/relay endpoints or tokens, signing authority, deployment authority, funded-account secrets, or production configuration. See [`SECURITY.md`](SECURITY.md).
