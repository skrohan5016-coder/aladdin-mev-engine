# Threat Model

## Protected assets

Inherited F0–F7 evidence and authority boundaries; complete historical attempt retention; exact cohort identity; honest scoreability; inclusion-time valuation; exact integer scoreboard/calibration math; honest separation between historical research estimates and realized profit or production authority; future keys, accounts, and funds.

## Inherited failure modes remain active

Canonical-JSON ambiguity, ledger tampering, source drift, reorg errors, malformed state proofs, model ambiguity, optimizer errors, conservative-cost drift, unsigned/signed transaction drift, relay-evidence spoofing, block/receipt/settlement spoofing, historical drift filtering, and CI bypasses remain governed by inherited contracts and tests.

## F8 failure modes

- dropping a reference declared by the source-window manifest, or injecting an undeclared reference, to inflate apparent performance;
- dropping reverted, settlement-missing, or settlement-evidence-incomplete included attempts to inflate apparent performance;
- omitting complete outcome evidence after a governed settlement event was already authenticated, then relabeling the attempt as settlement-missing;
- mixing unscoreable records into economic sums or silently treating them as zero-profit outcomes;
- mixing different senders, signature sources, policies, relay endpoints/response sources, funding sources/providers, deployments, settlement models, rollup-fee sources, historical-valuation policies, pool models, finality, environments, or simulator identities in one cohort;
- assigning empty valuation-source identity to unscoreable records so they leave the scoreable cohort denominator;
- stale, inverse, cross-chain, extra, or caller-injected valuation authority;
- converting actual external costs at a time other than the authenticated inclusion block;
- duplicate transaction or inclusion position counted more than once;
- integer overflow, floating-point drift, unsafe rounding, denominator errors, or rate/count cross-field inconsistency;
- calibration buckets that overlap, omit attempts, or discard unscoreable records from attempt counts;
- conditional settled-only expected value presented as unconditional, causal, independent, or confidence-guaranteed;
- repeated attempts in one block presented as independent sample diversity;
- a permissive policy promoting tiny, sparse, zero-scoreable, or low-coverage samples;
- unscoreable records on distinct blocks padding a diversity gate while scoreable economics remain concentrated in one block;
- promotion failure reporting short-circuited so confirmed risks disappear;
- historical conservative surplus or guarded sample mean presented as realized profit;
- offline research promotion presented as production strategy approval;
- network, credential, key, signing, submission, deployment, or execution capability entering production source;
- CI command, action, runner, shell, environment, permission, condition, timeout, or error-handling bypass.

## Controls

Exact runtime types; canonical digest identities; exact F6/F7 evidence binding; exact registry-resolved settlement-event detection; derived four-state dispositions; explicit scoreability and outcome completeness; shared historical-valuation policy with exact-pair/source inclusion-time validation only when scoreable; exact source-window reference-set consumption; downstream source-manifest/completeness propagation; explicit no-global-completeness guarantee; duplicate transaction/position rejection; closed cohort identity; bounded 128-record corpus; exact integer sums, floor rates, ceiling errors, and uint256-saturated error-rate evidence; all-attempt calibration partitioning; positive calibration boundaries; explicit zero-sample expected-value unavailability; positive sample/diversity policy minima; explicit conditional/selection-bias disclosure; minimum scoreable coverage; separate all-attempt and scoreable-sample block-diversity metrics; unique scoreable inclusion-block diversity; all-failure promotion reasons; false confidence/profit/production fields; thirteen closed schemas with immutable lock; hardened read-only exact-head and merge CI.

## Residual risks

F8 remains observational and conditional. Its completeness claim is limited to the exact declared source-window reference set and does not prove global provider, mempool, opportunity, or chain completeness. It does not prove causal profitability, independent samples, stationarity, future inclusion, current market competitiveness, token-balance accounting, treasury custody, fiat conversion, taxes, or realized profit. One cohort can still contain temporal dependence and regime shifts. Historical promotion is only a research-screening signal. Live collection, production endpoint/model registries, key custody, submission, execution, monitoring, incident response, and financial accounting require separate milestones and explicit approval.
