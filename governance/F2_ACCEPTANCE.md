# F2 Acceptance Contract

## Identity

- Milestone: F2
- Architecture: `AMEV-F2-ARCH-v1-e3c089f21451`
- Architecture manifest SHA-256: `e3c089f214518fa7171d23ce21059b466313123dbdb4fce619bbc1dc627109ad`
- Stacked parent head: `a16253f6643d9a69e2f92dc79ae1c653e193e964`
- Stacked parent tree: `348eb916ad320ccaad0127dd97c630bab1f3d641`
- Stacked parent architecture: `AMEV-F1-ARCH-v1-e0cc085585eb`
- Liquidation mechanism set SHA-256: `d86a8c761f17820b4b71aa5d7abba9e5eabf1aabd47a183292734705ed1b708c`

## Required implementation

- source-pinned Aave V3 and Morpho Blue mechanism registry;
- exact strict threshold comparators;
- immutable provenance-bound liquidation snapshot;
- deterministic rejection/candidate decision;
- same-unit positive gross-edge gate;
- candidate identity binding state, quote, evidence, deployment evidence, and mechanism;
- closed JSON schemas;
- machine registry verifier;
- repository policy and CI coverage;
- no runtime dependencies.

## Required adversarial proofs

- Aave `health_factor_wad == 1e18` is not liquidatable;
- Aave denominator drift is rejected;
- Morpho `borrowed == maxBorrow` is healthy;
- Morpho `borrowed == maxBorrow + 1` is liquidatable;
- booleans, negatives, zero denominators, and zero action values fail closed;
- Solana and state-chain mismatch fail closed;
- noncanonical and zero EVM addresses fail closed;
- observation digests must be nonempty, unique, and sorted;
- non-positive same-unit edge emits no candidate;
- candidate identity changes when state, metric, valuation evidence, or mechanism evidence changes;
- candidate output uses decimal strings, not floating point;
- a candidate can still be rejected by the inherited F0 profit firewall;
- registry file and in-process registry have one exact digest;
- exact-head and merge-revision CI both run all inherited and F2 gates.

## Landing rule

F2 remains Draft and stacked. Do not merge it before F1 is accepted and landed. After F1 lands, restack F2 onto accepted `main`, rerun all local and GitHub gates on the new exact head, obtain a fresh review, and ask Rohan for explicit merge approval.
