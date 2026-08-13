# F2 Authenticated EVM State Contract

## Purpose

F2 converts recorded state claims into cryptographically checked evidence. A proof is accepted only when the exact recorded block identity, state root, account fields, requested storage slots, trie paths, RLP values, and proof-node traversal agree.

## Recorded observation sequence

For one exact EVM JSON-RPC source and one exact confirmed or finalized stream:

1. `block-head` records block number, block hash, parent hash, and timestamp.
2. `evm-block-state` records the same block number/hash and its non-zero state root.
3. `evm-state-proof` records one account proof and zero or more storage proofs for that same block number/hash/root.

The state observation must follow the head sequence and time. The proof observation must follow the state observation sequence and time. Cross-source, cross-chain, cross-finality, or stale-backwards combinations fail closed.

## Cryptographic rules

- Ethereum legacy Keccak-256 is used, not NIST SHA3-256.
- Account trie key: `Keccak256(address_20_bytes)`.
- Storage trie key: `Keccak256(slot_32_bytes)`.
- Every RLP item must be minimally encoded and bounded.
- The root proof node and every hashed child used by traversal must be present exactly once.
- Embedded child nodes are nested RLP lists whose complete encoding is smaller than 32 bytes; short byte strings are never treated as embedded references. Embedded nodes are decoded and shape-validated recursively.
- Missing, duplicate, reordered, extraneous, oversized, cyclic, malformed, or noncanonical proof material fails closed.
- A proof may terminate by authenticated inclusion or authenticated non-inclusion.

## Account semantics

An included account leaf must decode to exactly four RLP byte strings:

```text
[nonce, balance, storageRoot, codeHash]
```

The decoded values must exactly match the recorded proof response. An absent account must report zero nonce, zero balance, the canonical empty storage-trie root, and the canonical empty-code hash.

## Storage semantics

An included storage leaf contains an RLP-encoded scalar. The authenticated scalar must be non-zero and must equal the recorded value. Ethereum omits zero storage values from the storage trie, so a claimed zero is accepted only through authenticated non-inclusion.

## Evidence identity

`EvmStateProofEvidence` stores the exact `EvmBlockStateAnchor` and exact proof observation. Every construction recomputes the MPT proofs. Derived fields such as `account_exists`, nonce, balance, terminal reason, and used node hashes cannot be supplied by a caller.

`EvmStateSnapshot` requires one exact anchor and a non-empty, unique, address-sorted tuple of evidence. Reused proof identities and mixed anchors fail closed.

## Limits

- JSON/canonical evidence: 1 MiB.
- RLP input/output: 1 MiB, depth 64, 100,000 items.
- MPT key: at most 64 bytes.
- Proof: at most 256 nodes, 65,536 bytes per node, 1 MiB total.
- Storage entries per account proof: at most 128.
- Snapshot accounts: at most 4,096, additionally bounded by canonical JSON size.

## Schema identity

The four F2 schemas plus the two updated inherited schemas are canonical-SHA-256 locked in `governance/f2-schemas.lock.json`. CI recomputes every digest.

## Non-authority

Passing F2 does not authorize a collector, RPC credential, signer, transaction construction, transaction submission, contract deployment, wallet funding, or profit claim.
