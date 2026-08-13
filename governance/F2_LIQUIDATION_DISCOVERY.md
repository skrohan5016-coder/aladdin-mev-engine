# F2 — Deterministic Liquidation Bounty Discovery

## Purpose

F2 turns recorded, provenance-bound protocol snapshots into deterministic liquidation candidates. It answers only:

> Does this exact recorded state cross the pinned liquidation threshold, and does the supplied same-unit quote have a positive gross edge?

It does not answer whether a transaction will succeed, win competition, be included, or make net profit.

## Supported mechanism families

| Protocol | Pinned source | Eligibility rule used by F2 |
|---|---|---|
| Aave V3 | `aave-dao/aave-v3-origin@cff15de6d1271b0c800fc001f4aea4c263e8a597` | `health_factor_wad < 1e18` |
| Morpho Blue | `morpho-org/morpho-blue@d09dd1c4b9c7d9d05f976faa7ebfdc424dae5e8c` | `borrowed_assets_rounded_up > max_borrow_assets_rounded_down` |

The machine-readable registry is `governance/liquidation-mechanisms.json`. The in-process registry and file must have the same canonical digest.

## Snapshot contract

A snapshot binds:

- protocol and EVM chain;
- canonical deployment address and deployment-evidence digest;
- market identifier, borrower, debt asset, and collateral asset;
- F1 `StateReference`;
- one to sixty-four unique, sorted source-observation digests;
- exact mechanism metric numerator and denominator;
- positive repay and seize token amounts;
- one canonical valuation unit;
- positive repay and seize values in that same unit;
- valuation-evidence digest.

Solana, mixed-case or zero addresses, booleans masquerading as integers, zero action amounts, unsorted evidence, duplicate evidence, wrong Aave denominator, and chain/state mismatch fail closed.

## Deterministic outcomes

F2 produces exactly one reason:

- `not-liquidatable`: the source-pinned strict threshold is not crossed;
- `non-positive-gross-edge`: liquidatable, but quoted seize value is not greater than repay value;
- `candidate`: liquidatable and the same-unit gross edge is positive.

The candidate identifier binds the complete snapshot digest and mechanism-contract digest. Any state, quote, provenance, deployment-evidence, or mechanism change produces a different identity.

## Separation from execution

Every F2 decision and candidate declares `execution_authority: none`. A candidate must still pass:

- proof-backed state reconstruction;
- calldata construction;
- two independent simulations;
- state freshness;
- gas and data fees;
- flash liquidity and fees;
- swap liquidity and slippage;
- inclusion bid and competition;
- failure-risk reserve;
- risk budget and exposure limits;
- human-gated mode transition.

## Threats addressed

- threshold equality mistakes;
- documentation/source disagreement;
- floating-point boundary drift;
- evidence reordering and duplication;
- cross-chain state confusion;
- quote-unit mismatch;
- candidate identifier collisions from omitted evidence;
- treating gross incentive as guaranteed net profit;
- silently treating an arbitrary address as an authenticated deployment.

## Explicit non-goals

- network collection;
- borrower enumeration;
- official deployment discovery;
- storage-proof interpretation;
- oracle reading;
- transaction construction;
- signing or key handling;
- bundle submission;
- live competition;
- revenue guarantees.
