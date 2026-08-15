# Aladdin MEV Engine Architecture

## Accepted lineage

F8 is built from accepted F7 landing `ec4d9a211c204e3363e8a77d8de4ab2199a89be0`, tree `42592ed5ce7dc8d87755ff95af4824dc20c9e6fa`, and architecture `AMEV-F7-ARCH-v1-c611202acf40`.

F0 supplies canonical evidence, policy, and risk controls; F1 supplies recorded observation and replay; F2 supplies authenticated EVM state; F3 supplies exact gross opportunities; F4 supplies deterministic plans and conservative cost-complete shadow economics; F5 supplies authenticated unsigned transaction packages; F6 verifies externally produced signatures and records relay evidence; F7 authenticates historical inclusion and settlement; F8 supplies bias-resistant historical corpora, exact scoreboards, calibration, conditional expected-value evidence, and offline research-promotion gates.

## Inherited authority retention

F8 does not weaken F0–F7. Earlier canonical, proof, model, optimization, cost, transaction, signature, relay, inclusion, settlement, drift, and authority-denial contracts remain independently locked and tested.

## Trust flow

```text
Recorded observations + authenticated state
  -> F3 opportunity + F4 conservative shadow decision
  -> F5 unsigned package + F6 external signature/relay evidence
  -> F7 authenticated inclusion/receipt/settlement outcome
  -> exact settlement registry/spec + historical valuation policy
  -> F8 receipt-derived disposition, outcome completeness, and scoreability
  -> exact declared source-window manifest and reference-set consumption
  -> exact cohort-bound canonical corpus
  -> exact integer scoreboard + calibration
  -> conditional empirical expected-value evidence
  -> fail-closed offline research-promotion decision
```

## F8 authority boundaries

```text
network_access                        = none
relay_access                          = none
credential_authority                  = none
key_authority                         = none
local_signing_authority               = none
signing_authority                     = external-unmodeled
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

## F8 hardening invariants

All authenticated included attempts are retained. Successful outcomes can be economically scoreable; reverted, settlement-missing, and settlement-evidence-incomplete attempts remain unscoreable but stay in coverage and calibration denominators. Settlement-event presence is derived from the authenticated receipt under the exact registry-resolved spec, so omitting the outcome object cannot relabel an observed event as missing. Cohorts bind exact sender/signature source, policy, relay endpoint/response sources, funding, deployment, settlement model, rollup-fee source, historical-valuation policy, pool model, finality, environment, and independent simulation identities. The valuation policy is shared by scoreable and unscoreable attempts; only scoreable records may carry the exact policy-matching inclusion-time rate. All statistics use exact integers. Calibration partitions every attempt with strictly positive boundaries. Zero-scoreable expected-value evidence is explicitly unavailable. Promotion requires positive sample/diversity minima, scoreable coverage, and unique inclusion-block diversity within the scoreable economic sample. All-attempt and scoreable-sample block counts are published separately so unscoreable records cannot pad the diversity gate. Promotion reports every confirmed failure and grants no production or transaction authority.

The machine-readable architecture manifest, architecture lock, inherited locks, and F8 schema lock are authoritative.

F8 completeness is relative only to an exact declared source-window reference set. It grants no global source completeness guarantee.

Downstream scoreboard, calibration, expected-value, and promotion evidence repeat the exact source-manifest digest and completeness boundary, including `global_completeness_guarantee = false`.
