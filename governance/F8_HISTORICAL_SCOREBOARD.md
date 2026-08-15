# F8 Authenticated Historical Scoreboard

## Trust flow

```text
F6 externally signed package
  + F7 authenticated transaction/receipt inclusion
  + exact registry-resolved settlement-event policy
  + recorded rollup fee
  + optional successful F7 settlement outcome
  + exact historical-valuation policy
  + exact inclusion-time conservative rate when scoreable
      -> historical execution record
      -> exact declared source-window manifest
      -> exact manifest-consuming canonical corpus
      -> exact cohort scoreboard
      -> calibration report
      -> conditional empirical expected-value evidence
      -> offline research-promotion decision
```

## Dispositions and scoreability

Every included attempt has one derived disposition:

- `settled`: successful receipt plus governed settlement outcome; economic fields are scoreable;
- `reverted`: failed receipt; retained but economic fields are unscoreable;
- `settlement-missing`: successful receipt without the governed settlement event; retained but economic fields are unscoreable;
- `settlement-evidence-incomplete`: the authenticated receipt contains exactly one valid governed event, but complete F7 outcome evidence is absent; retained, explicitly marked, and unscoreable.

Event presence is derived from the authenticated receipt under the exact registry-resolved event spec. A caller cannot downgrade an observed event to `settlement-missing` merely by omitting the outcome object. Unscoreable records cannot carry an unused valuation book or synthetic economic values. They remain in attempt counts, execution-success rates, outcome-completeness rates, scoreable-coverage rates, all-attempt unique-block counts, and calibration bucket attempt counts. A separate unique-scoreable-block count is derived only from scoreable economic records.


## Source-window completeness boundary

A corpus is valid only when every record maps to one exact `HistoricalAttemptReference` and the resulting reference set equals the declared source manifest exactly. The manifest binds the source ID and digest, chain, block window, package digest, inclusion digest, transaction hash, and inclusion position. Missing, extra, duplicate, cross-chain, or out-of-window references fail closed.

This control prevents selective omission relative to the declared export. It does not prove that the upstream provider observed every possible chain opportunity or that the declared source window itself is globally complete. Both manifest and corpus therefore publish `global_completeness_guarantee = false`. Downstream scoreboard, calibration, expected-value, and promotion evidence repeat the same source-manifest digest, completeness scope, and false global guarantee so the limitation cannot disappear when evidence is viewed independently.

## Historical conservative surplus

Every record carries one explicit historical-valuation policy. This policy binds native/base asset identity, identity-versus-directional mode, ceiling rounding, and the governed rate source. Unscoreable and scoreable records therefore remain in the same cohort even though unscoreable records carry no unused rate value. For a settled record, the exact rate must match the policy source and be valid at the inclusion block time. F8 then computes:

```text
historical conservative surplus
  = authenticated base-token residual before external costs
  - inclusion-time conservative external-cost conversion
  - retained slippage reserve
  - retained stale-state reserve
  - retained failure-risk reserve
  - retained infrastructure reserve
  - retained inventory-hedge reserve
```

This value is an offline research estimate. It is not a token-balance proof, treasury statement, fiat conversion, accounting record, tax record, or realized-profit claim.

## Exact cohort identity

A scoreboard never mixes records unless their exact cohort digest matches. The digest includes:

- chain, strategy, base asset, and inclusion finality;
- authenticated sender and external signature source;
- profit policy and execution constraints;
- relay endpoint and relay-response source set;
- funding kind, provider identity, and source digest;
- executor interface and deployment identity;
- settlement-event registry and spec;
- rollup-fee source identity and historical-valuation policy;
- pool model registry;
- route-simulation and transaction-simulation engine/source sets;
- transaction-simulation environment.

## Scoreboards and calibration

All authoritative statistics use exact integers. Rates use floor basis points; conservative error measures use ceiling division. Binary floating point is forbidden.

Calibration buckets partition every cohort attempt by predicted return. Unscoreable records stay in bucket attempt counts but never enter predicted-versus-historical economic error aggregates.

## Conditional expected value and promotion

F8 expected value is conditioned on authenticated successful settled records with scoreable economics. It exposes the sample mean, mean absolute prediction error, a guarded sample mean, and aggregate return. A zero-scoreable cohort produces explicit `available = false` evidence rather than disappearing or fabricating a mean. It explicitly grants no confidence guarantee.

Research promotion is a nonproduction evidence gate. Its attempt, scoreable-record, unique-scoreable-block, and nonempty-bucket sample minima are strictly positive. It can also require scoreable rate, execution success, conservative-floor preservation, cost-bound compliance, positive-surplus rate, bounded error, and bounded cost-overrun rate. Unscoreable records cannot pad the scoreable inclusion-block diversity gate. An unavailable expected value is an explicit failure reason. All confirmed failures are returned together. Passing grants no production, signing, submission, deployment, execution, or profit authority.
