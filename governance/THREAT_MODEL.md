# Threat Model

## Protected assets

Authenticated state/opportunity identity; exact token and amount flow; funding and fee identity; simulation independence; valuation and cost correctness; chain-health/risk context integrity; honest separation between shadow approval and execution authority; future keys and funds.

## Inherited failure modes remain active

F4 does not replace F0-F3 controls. Canonical-JSON ambiguity, ledger truncation or reordering, source-contract drift, reorg misclassification, malformed RLP/MPT proofs, state-anchor mismatch, code-hash/model ambiguity, packed-reserve overflow, unsafe optimizer pruning, and gross-opportunity authority escalation remain governed by their accepted milestone contracts and regression suites.

## F4 failure modes

- treating different assets as one unit or using implicit/inverse/extra/stale valuation;
- floor-rounding a cost or overflowing a governed integer intermediate;
- caller-injected gross profit, funding, route, output, gas, health, or risk approval;
- priority-fee, L1-fee, or direct-payment double counting;
- duplicate simulator implementations or result sources hidden behind different names, or agreement claimed across different environments;
- simulation bound to the wrong state, plan, source, or validity interval;
- missing, duplicate, wrong-chain, or expired reserve categories;
- cost inputs valid at envelope creation but expired at final evidence time;
- risk snapshot not binding the exact plan, total cost, or notional; risk arithmetic overflow; or a risk snapshot observed before its cost envelope;
- positive shadow assessment presented as inclusion, signing, or execution approval;
- CI shell, environment, runner, container, condition, timeout, action-input, or error-handling bypass.

## Controls

Exact runtime types; closed schemas; constructor-time recomputation; exact required valuation pairs; checked integer products/sums; exact route-step derivation; EIP-1559 semantic separation; distinct implementation/source simulation evidence with one exact environment; source-bound chain health; recomputed risk-budget snapshot with checked aggregation and observation ordering; transitive final-time validity checks; inherited F0 profit policy; immutable locks; hardened read-only CI.

## Residual risks

F4 uses recorded bounds, simulations, health, and risk snapshots. It does not prove live state freshness, production token behavior, builder/sequencer inclusion, available capital at submission time, signer correctness, or transaction landing. Those require later governed milestones.
