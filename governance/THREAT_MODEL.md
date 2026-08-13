# F2 Threat Model

## Protected assets

- inherited strategy, profit, risk, evidence, ledger, and CI integrity;
- exact block/state-root provenance;
- account and storage proof correctness;
- proof/non-proof capability separation by chain;
- deterministic evidence and snapshot identity;
- future signer, executor, and treasury separation.

## Adversaries and failure modes

1. Malformed, oversized, deeply nested, duplicate-key, non-UTF-8, floating-point, or noncanonical JSON.
2. A state root attached to the wrong block, source, chain, finality, sequence, or observation time.
3. NIST SHA3-256 substituted for Ethereum legacy Keccak-256.
4. Nonminimal or malformed RLP, integer leading zeroes, declared-size abuse, excess nesting, or excess item counts.
5. A missing, reordered, duplicate, extraneous, cyclic, oversized, or hash-mismatched trie proof node.
6. A malformed embedded trie child hidden outside the queried path.
7. Account fields that do not match the authenticated account leaf.
8. Storage keys hashed with the wrong width or storage values that do not match their authenticated leaf.
9. A zero storage value falsely represented as an included trie scalar.
10. An absent account carrying non-empty nonce, balance, storage root, or code hash claims.
11. Caller-injected derived evidence that bypasses cryptographic recomputation.
12. Mixed-anchor or duplicate-account snapshot assembly.
13. Accidental proof enablement for a chain whose official proof semantics are not governed.
14. CI supply-chain drift, unapproved shell/Python network commands, write permissions, secrets, or credential material.
15. Future code silently introducing a network client, signer, broadcaster, deployment path, or execution authority.

## Controls

- strict canonical JSON and stable recorded-input handling inherited from F0/F1;
- exact source-contract event-shape gating;
- known-vector legacy Keccak-256 implementation;
- strict bounded canonical RLP;
- exact hashed-node MPT traversal with recursive embedded-node shape validation;
- inclusion and non-inclusion terminal evidence;
- immutable exact observations retained inside block-state anchors and proof evidence;
- constructor-time cryptographic recomputation;
- unique sorted snapshot accounts bound to one exact anchor;
- explicit Ethereum/Base proof allowlist and fail-closed Arbitrum/BNB/Solana exclusions;
- zero third-party runtime dependencies;
- read-only, exact-command, exact-action, exact-head CI policy.

## Residual risks

F2 does not independently contact a chain, establish network consensus, evaluate provider honesty, or decide whether a recorded state root is economically current. It does not simulate EVM execution, normalize token prices, estimate gas or inclusion, construct bundles, manage nonces, protect a live signer, or execute a trade. Those require later governed milestones and separate acceptance evidence.
