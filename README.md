# Aladdin MEV Engine

Aladdin MEV Engine is a governed, safety-first foundation for authenticated EVM state, exact market mathematics, conservative economics, and replayable unsigned execution research.

## Current status

**F5 is an offline, recorded-input, unsigned execution-package foundation.** It retains accepted F0-F4 authority and adds:

- exact deployment-registry membership plus F2-proof-bound stateless executor code hash, canonical empty storage root, interface identity, flash-loan provider/source, `msg.value` semantics, and authenticated-sender residual-beneficiary semantics;
- one runtime code hash to one exact executor interface;
- deterministic route-command bytes derived from the exact F4 plan;
- canonical ABI calldata with ceiling-rounded route and final economic minimum-output floors;
- F2-authenticated EOA sender nonce and native balance;
- canonical unsigned EIP-1559 type-2 signing payload, intrinsic-gas floor, legacy-Keccak hash, and sender-balance coverage for explicit L1-data and OP Stack operator-fee upper bounds;
- authenticated-anchor-fresh, bounded, relay-neutral private bundle intent beginning at the authenticated nonce, with contiguous nonces and aggregate balance coverage;
- independent transaction simulations bound to the exact state, transaction, signing hash, bundle, in-range block, pre-deadline timestamp, and max-fee-covered base fee, observed after bundle formation, and explicitly reconciling exact base-token identity, flash principal, fee, OP Stack operator fee, base-token residual, authenticated sender beneficiary, and complete beneficiary delta;
- a final single-transaction package-v1 that recomputes all identities and deadline-transitive validity.

Every F5 output remains:

```text
signature_present = false
relay_credentials_present = false
signing_eligible = false
submission_eligible = false
execution_eligible = false
inclusion_guarantee = false
```

F5 package v1 supports Ethereum and Base recorded flash-loan plans because authenticated opportunity, deployment, and sender proofs are limited to those governed EVM chains. Own-inventory transaction packaging remains disabled until ERC-20 funding state is governed. It does not connect to a network, access an RPC or relay, hold keys, sign, submit a transaction or bundle, deploy a contract, move funds, or guarantee profit.

## Local validation

Python 3.13 is the governed conformance runtime. F5 has no third-party runtime dependencies.

```bash
make all
```

## Architecture

Start with:

- [`governance/ARCHITECTURE.md`](governance/ARCHITECTURE.md)
- [`governance/F5_UNSIGNED_EXECUTION_PACKAGE.md`](governance/F5_UNSIGNED_EXECUTION_PACKAGE.md)
- [`governance/F5_ACCEPTANCE.md`](governance/F5_ACCEPTANCE.md)
- [`governance/F4_COST_COMPLETE_PROFIT.md`](governance/F4_COST_COMPLETE_PROFIT.md)
- [`governance/THREAT_MODEL.md`](governance/THREAT_MODEL.md)

## Security

Never commit credentials, wallet material, signing authority, relay configuration, deployment authority, or production configuration. See [`SECURITY.md`](SECURITY.md).
