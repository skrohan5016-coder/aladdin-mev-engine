# F0 Threat Model

## Protected assets

- strategy policy integrity;
- profit and cost arithmetic;
- risk-limit state;
- evidence identity and reproducibility;
- repository and CI integrity;
- future signer and treasury separation.

## Adversaries and failure modes

1. Malformed, oversized, deeply nested, duplicate-key, non-UTF-8, or floating-point JSON.
2. Stale or internally inconsistent chain state.
3. A simulator disagreement or matching failed simulations hidden behind a successful aggregate result.
4. Cost omission, unit mismatch, rounding loss, or bid escalation consuming all surplus.
5. Automatic promotion from shadow to canary/live without human approval.
6. Recovery after an incident without closed-incident evidence, including a stop-and-restart bypass.
7. Unknown or prohibited strategies entering through permissive parsing.
8. CI supply-chain drift through mutable action tags or excessive token permissions.
9. Credential material committed to a public repository or exposed to CI.
10. Time-of-check/time-of-use file replacement through links or mutation during read.
11. Partial, duplicate, or cross-candidate release of reserved execution-cost budget.
12. Direct governor construction in `CANARY`/`LIVE`, spoofed transition objects, or mutable risk-limit authority.
13. Caller-selected JSON limits above governed ceilings or oversized programmatic canonical evidence.
14. CI action substitution, job-level write permissions, or workflow network/publication commands.

## F0 controls

- bounded descriptor-based stable reads with no-follow behavior;
- strict canonical JSON with duplicate and float rejection plus non-raiseable governed ceilings for input and canonical output;
- closed domain enums and additional-property rejection in schemas;
- exact integer arithmetic and explicit reserve fields;
- two or more successful independent simulator identities for approved evidence;
- governors that can only start stopped, exact-type transition authority, immutable risk limits, and immediate fail-closed risk states;
- human plus evidence gates for every promotion and recovery, with incident closure required across stop-and-restart paths;
- identity-bound risk reservations that release only on exact reservation settlement;
- read-only CI permissions, an exact immutable action allowlist, no workflow secrets or publication commands, and separate source-head/merge-ref validation;
- zero network, signing, deployment, or execution dependencies.

## Residual risks

F0 cannot validate real chain semantics because no chain adapter exists. It also does not authenticate market data, normalize assets, simulate EVM/SVM execution, model reorgs, estimate inclusion, or protect a live signer. Those are mandatory future milestones before canary operation.
