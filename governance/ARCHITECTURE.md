# Aladdin MEV Engine Architecture

## Current milestone

F2 is a stacked, offline, recorded-input liquidation opportunity discovery authority. It inherits the complete F0 profit/risk foundation and F1 observation ledger, then adds source-pinned liquidation mechanism contracts for Aave V3 and Morpho Blue.

F2 does not contain a live RPC client, deployment registry, signer, wallet, bundle submitter, transaction broadcaster, contract deployer, or execution loop. A discovery candidate is evidence for later simulation and profitability analysis; it is never execution approval.

## Authority layers

1. **F1 observation authority** accepts only governed recorded source envelopes and deterministic replay segments.
2. **F2 mechanism authority** pins each supported liquidation threshold to an exact upstream source commit.
3. **F2 snapshot authority** binds protocol, deployment evidence, borrower, assets, state reference, source observation digests, exact eligibility metric, action quote, and same-unit valuation evidence.
4. **F2 discovery authority** recomputes liquidatability and emits a candidate only when the threshold is crossed and the quoted seize value strictly exceeds the quoted repay value.
5. **F0 profit authority** still subtracts gas, L1 data fee, flash-loan fee, inclusion bid, slippage, stale-state, failure-risk, infrastructure, and hedge reserves.
6. **F0 evidence and risk authorities** still require simulation agreement, healthy chain state, freshness, available risk budget, and human-gated operating mode.

No lower layer can bypass a later gate.

## Source-pinned threshold contracts

### Aave V3

The pinned Aave V3.7 Origin validation source requires:

```text
healthFactor < 1e18
```

Equality is healthy for liquidation validation. F2 therefore accepts only the fixed WAD denominator and uses a strict-below comparator.

### Morpho Blue

The pinned Morpho Blue core source calculates borrowed assets with upward rounding, max borrow with downward rounding, and returns healthy when:

```text
maxBorrow >= borrowed
```

F2 therefore emits a liquidation candidate only when:

```text
borrowed > maxBorrow
```

The F2 snapshot receives those already rounded protocol quantities. Reconstructing interest accrual, share conversions, oracle quoting, and market state from raw storage belongs to a later proof-backed state interpreter.

## Candidate economics

`repay_value` and `seize_value` must use one explicit valuation unit and one bound valuation-evidence digest. Gross profit is:

```text
seize_value - repay_value
```

A non-positive gross edge cannot become a candidate. A positive gross edge can still be rejected by the inherited F0 profit firewall.

## Deployment boundary

F2 validates canonical deployment addresses and requires a deployment-evidence digest, but it does not claim that an address is an official current deployment. A future governed deployment registry must authenticate chain/address/code identities before any live adapter can exist.

## Stacked parent

F2 is based on exact F1 source head `a16253f6643d9a69e2f92dc79ae1c653e193e964`, tree `348eb916ad320ccaad0127dd97c630bab1f3d641`, architecture `AMEV-F1-ARCH-v1-e0cc085585eb`. F1 remains a Draft PR and must be accepted and landed before F2 can be restacked for final landing.
