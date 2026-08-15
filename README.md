# Aladdin MEV Engine

Aladdin MEV Engine is a governed, safety-first foundation for authenticated EVM state, exact market mathematics, conservative economics, replayable transaction evidence, external-signature verification, and offline historical execution-outcome reconciliation.

## Current status

**F7 is an offline, recorded-input authenticated inclusion and execution-outcome foundation.** It retains accepted F0–F6 authority and adds:

- canonical typed/legacy Ethereum receipt decoding and exact raw-byte reconstruction;
- exact receipt-log bloom and log-digest recomputation;
- canonical block-header hash/root/base-fee verification against an F2 state anchor;
- exact inclusion-block executor account proof preserving runtime code hash and canonical empty storage;
- bounded indexed transactions-trie and receipts-trie inclusion proofs;
- exact F6 signed-transaction inclusion and per-transaction gas attribution;
- runtime-code-hash/time-bound executor settlement-event models;
- exact plan, funding, beneficiary, asset, minimum-output, and transaction-value hard constraints;
- successful output, residual, direct-payment, gas, log, and Ethereum/Base fee drift retained through explicit match, shortfall, overrun, upper-bound, and conservative-floor fields;
- adverse historical outcomes remain recordable without claiming realized profit.

Every F7 output remains within this boundary:

```text
network_access = none
relay_access = none
credential_authority = none
key_authority = none
local_signing_authority = none
submission_authority = none
execution_authority = none
realized_profit_authority = none
inclusion_guarantee = none
```

F7 supports Ethereum and Base recorded evidence. It does not poll a chain, contact a relay, sign or submit anything, deploy contracts, move funds, prove every token balance, or guarantee inclusion or profit.

## Local validation

Python 3.13 is the governed conformance runtime. F7 has no third-party runtime dependencies.

```bash
make all
```

## Architecture

Start with:

- [`governance/ARCHITECTURE.md`](governance/ARCHITECTURE.md)
- [`governance/F7_AUTHENTICATED_EXECUTION_OUTCOME.md`](governance/F7_AUTHENTICATED_EXECUTION_OUTCOME.md)
- [`governance/F7_ACCEPTANCE.md`](governance/F7_ACCEPTANCE.md)
- [`governance/F6_SIGNED_RELAY_EVIDENCE.md`](governance/F6_SIGNED_RELAY_EVIDENCE.md)
- [`governance/THREAT_MODEL.md`](governance/THREAT_MODEL.md)

## Security

Never commit credentials, wallet material, private keys, RPC/relay endpoints or tokens, signing authority, deployment authority, or production configuration. See [`SECURITY.md`](SECURITY.md).
