# F8 Acceptance Contract

F8 is accepted only when one exact source head and its current GitHub synthetic merge independently satisfy every requirement below.

## Required implementation

- exact accepted F7 parent identity;
- exact cohort identity binding sender/signature, policy, relay endpoint/response sources, funding, deployment, settlement model, rollup-fee source, historical-valuation policy, pool model, finality, and independent simulation identities;
- settled, reverted, settlement-missing, and settlement-evidence-incomplete records retained with derived scoreability;
- settlement-event presence derived from the authenticated receipt under the exact registry-resolved event spec;
- an observed governed settlement event cannot be relabeled missing by omitting complete outcome evidence;
- no unscoreable record may carry valuation or economic-score authority;
- one explicit historical-valuation policy shared by scoreable and unscoreable attempts, and an exact inclusion-time policy-matching conservative rate for every scoreable settled record;
- exact source-window manifest binding the declared source, chain, block range, package, inclusion, transaction, and position identities;
- deterministic canonical corpus that consumes the manifest reference set exactly, with duplicate record, transaction, and inclusion-position rejection;
- explicit `global_completeness_guarantee = false`;
- scoreboard, calibration, expected-value, and promotion outputs propagate the exact source-manifest digest and completeness limitation;
- exact-integer scoreboard rates, sums, errors, guarded means, capital-weighted metrics, all-attempt block diversity, and scoreable-sample block diversity;
- calibration buckets partition all attempts and retain unscoreable attempt counts;
- conditional expected-value evidence with explicit zero-sample unavailability, selection-bias disclosure, and no confidence guarantee;
- promotion policies require strictly positive attempt, scoreable-record, unique-scoreable-inclusion-block, and nonempty-bucket minima;
- promotion decisions report all failures and remain offline research evidence only;
- exact thirteen-file F8 schema lock;
- no network, credential, key, signing, submission, deployment, execution, realized-profit, or production-promotion authority.

## Required adversarial validation

Wrong package/inclusion/outcome/settlement-registry/settlement-spec/rollup-fee identity, cohort drift, sender/signature/relay-response/source drift, stale or extra valuation authority, valuation-policy/source mismatch, invalid inclusion-time rate, source-manifest omission/injection/source drift, duplicate transaction or position, hidden reverted/settlement-missing/evidence-incomplete attempt, omitted observed settlement outcome, scoreable-count drift, zero-sample expected-value promotion, integer overflow, inconsistent metric sum/rate, calibration overlap/zero boundary/omission, unscoreable economic aggregation, insufficient coverage, unscoreable-block diversity padding, insufficient unique scoreable blocks, promotion short-circuiting, confidence/profit escalation, live dependency, and CI wrapper bypass must fail closed.

Randomized and hash-seed campaigns must preserve deterministic identities and exact integer reference results.

## Required CI

Exact source head and current synthetic merge must separately pass Python compilation, complete inherited F0–F8 tests, repository policy, architecture lock, source-contract lock, F2/F3/F4/F5/F6/F7/F8 schema locks, and clean-worktree validation using read-only permissions, immutable action pins, fixed hosted runners, and non-persisted checkout credentials.

F8 acceptance authorizes no production deployment or trade. A future milestone must separately govern live observation, production registries, credentials, keys, risk operations, submission, execution, monitoring, and financial accounting.
