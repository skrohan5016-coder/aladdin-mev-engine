# Aladdin MEV Engine

Aladdin MEV Engine is a governed, safety-first foundation for multi-chain opportunity discovery, deterministic replay, authenticated EVM state analysis, exact integer market mathematics, conservative profit accounting, and evidence-backed strategy development.

## Current status

**F3 is an offline, recorded-input, authenticated constant-product opportunity foundation.** It retains the accepted F0 safety contracts, F1 observation ledger, and F2 account/storage proof authority, then adds:

- explicit constant-product implementation models bound to runtime code hash, storage layout, static fee multiplier, checked `uint256` arithmetic, and declared transfer assumptions;
- a registry that forbids one runtime code hash from authorizing conflicting mathematics;
- authenticated token identity and packed reserve extraction from F2 storage-proof evidence;
- deterministic two-to-four-hop simple-cycle enumeration without pool reuse;
- exact integer route quoting with floor at every hop;
- a continuous rational upper bound used only to prune an exact bounded search;
- deterministic tie-breaking, bounded aggregate search work, and explicit no-trade or budget-exhausted outcomes;
- gross-only shadow opportunity evidence that recomputes its route and optimization;
- closed F3 schemas, a canonical transitive schema lock, and separate exact-source-head and merge-integration CI.

F3 authenticated opportunity construction is limited to the F2 proof-enabled Ethereum and Base sources. Arbitrum and BNB Smart Chain remain disabled for authenticated pool universes until their proof semantics are governed. Solana remains a separate non-EVM adapter.

F3 does **not** claim executable or net profit. It does not verify token transfer behavior, acquire live state, estimate gas, model builder or sequencer inclusion, source funding, construct transactions or bundles, sign, deploy, or execute. Every F3 opportunity is marked `execution_eligible = false` and `gross-only-no-gas-no-inclusion-no-funding`.

This repository contains no live RPC client, endpoint credential, transaction signer, private-key handler, bundle submitter, contract deployer, or mainnet execution path.

## Local validation

Python 3.13 is the governed conformance runtime. F3 has no third-party runtime dependencies.

```bash
make all
```

## Architecture

Start with:

- [`governance/ARCHITECTURE.md`](governance/ARCHITECTURE.md)
- [`governance/F3_AUTHENTICATED_OPPORTUNITY_GRAPH.md`](governance/F3_AUTHENTICATED_OPPORTUNITY_GRAPH.md)
- [`governance/F3_ACCEPTANCE.md`](governance/F3_ACCEPTANCE.md)
- [`governance/F2_AUTHENTICATED_STATE.md`](governance/F2_AUTHENTICATED_STATE.md)
- [`governance/THREAT_MODEL.md`](governance/THREAT_MODEL.md)
- [`governance/STRATEGY_POLICY.md`](governance/STRATEGY_POLICY.md)

## Security

Never commit credentials, RPC secrets, private keys, seed phrases, builder authentication material, deployment authority, or production configuration. See [`SECURITY.md`](SECURITY.md).
