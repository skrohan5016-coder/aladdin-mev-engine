# F8 Scope — Authenticated Historical Scoreboards and Offline Research Promotion

## Accepted parent

- F7 landing commit: `ec4d9a211c204e3363e8a77d8de4ab2199a89be0`
- F7 tree: `42592ed5ce7dc8d87755ff95af4824dc20c9e6fa`
- F7 architecture: `AMEV-F7-ARCH-v1-c611202acf40`

## Mission

F8 converts exact F6 signed-package evidence and F7 authenticated inclusion/outcome evidence into a bias-resistant offline historical corpus bounded by an exact declared source-window manifest. It then produces exact cohort scoreboards, calibration buckets, conditional empirical expected-value evidence, and fail-closed research-promotion decisions.

F8 never interprets a successful F7 settlement as realized profit. It retains reverted, settlement-missing, and settlement-evidence-incomplete attempts, marks their economics unscoreable, and keeps them in attempt and calibration denominators so adverse or incomplete records cannot silently disappear.

## Implemented authority

- exact cohort identity binding chain, strategy, base asset, authenticated sender, signature source, profit policy, relay endpoint/response sources, funding mode/provider/source, executor interface/deployment, settlement registry/spec, rollup-fee source, historical-valuation policy, pool-model registry, simulation environment, and independent engine sets;
- exact declared source-window manifest binding source identity, block window, transaction positions, package identities, and inclusion identities;
- exact historical records for settled, reverted, settlement-missing, and settlement-evidence-incomplete inclusions;
- receipt-derived settlement-event presence so omission of an outcome cannot relabel an observed event as missing;
- explicit historical-valuation policy shared by scoreable and unscoreable attempts, with rate values accepted only for scoreable records;
- inclusion-time conservative native-to-base valuation for scoreable settled records only;
- exact historical conservative surplus and prediction-error accounting;
- one immutable canonical corpus that must consume the manifest reference set exactly, with duplicate transaction and inclusion-position rejection;
- exact integer scoreboards, rates, sums, guarded means, and aggregate returns;
- calibration buckets that retain every attempt while restricting economic error aggregates to scoreable records;
- conditional historical expected-value evidence with explicit zero-sample unavailability, selection-bias disclosure, and no confidence guarantee;
- research-promotion policy and decision evidence requiring scoreable coverage and unique inclusion-block diversity within the scoreable economic sample;
- thirteen closed F8 schemas and an exact canonical schema lock;
- explicit denial of any global source-completeness guarantee beyond the declared manifest window;
- downstream scoreboard, calibration, expected-value, and promotion evidence propagate the same source-manifest digest and completeness limitation.

## Non-goals

- live data collection, RPC, relay, builder, sequencer, or explorer access;
- credentials, private keys, local signing, HSM/KMS, wallet custody, or funded accounts;
- transaction construction beyond inherited offline evidence, bundle submission, deployment, or execution;
- production strategy approval or automatic promotion;
- causal inference, independent-identically-distributed sample claims, confidence intervals, hypothesis-test guarantees, or profitability guarantees;
- treasury, tax, accounting, fiat-value, or realized-profit statements.

## Authority boundary

```text
network_access                        = none
credential_authority                  = none
key_authority                         = none
local_signing_authority               = none
submission_authority                  = none
execution_authority                   = none
realized_profit_authority             = none
historical_source_manifest_authority  = offline-declared-source-window-reference-set-only
historical_corpus_authority           = offline-exact-declared-source-window-inclusion-conditioned-history-only
historical_scoreboard_authority       = offline-exact-cohort-scoreboard-only
calibration_authority                 = offline-empirical-no-confidence-guarantee
conditional_expected_value_authority  = offline-historical-conditional-estimate-only
research_promotion_authority          = offline-research-evidence-only
production_promotion_authority        = none
```
