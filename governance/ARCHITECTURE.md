# F2 Governed Authenticated-State Architecture

## Mission

F2 extends accepted F0 policy/profit/risk authority and accepted F1 observation/replay authority with deterministic offline verification of EVM account and storage state. All inputs are recorded observations. F2 does not connect to a chain, sign a message, submit a bundle, deploy a contract, or execute a trade.

## Trust boundaries

```text
Recorded full block-head observation
        │
        ├── exact source + finality + sequence + block identity
        ▼
Recorded block-state observation
        │
        ├── exact block number + block hash + non-zero state root
        ▼
Authenticated block-state anchor
        │
        ▼
Recorded EIP-1186-shaped proof observation
        │
        ├── strict canonical JSON + bounded node arrays
        ├── legacy Ethereum Keccak-256
        ├── canonical bounded RLP
        └── canonical MPT inclusion/non-inclusion traversal
        ▼
Recomputed account/storage evidence
        │
        ▼
Unique sorted multi-account state snapshot
        │
        ▼
F0 simulation + profit + risk gates
        │
        ▼
No executor in F2
```

## Components

1. **Inherited F0 authority** — exact-integer profit accounting, simulation agreement, strategy policy, risk governor, canonical JSON, and repository/CI controls.
2. **Inherited F1 authority** — governed source contracts, immutable observation envelopes, source sequencing, tamper-evident ledgers, deterministic replay, stable storage, and reorg-aware heads.
3. **Legacy Keccak-256 authority** — a dependency-free implementation of the Ethereum hash function, explicitly distinct from NIST SHA3-256 and locked by known vectors.
4. **Canonical RLP authority** — strict minimal encoding/decoding with byte, depth, item, integer-width, and framing ceilings.
5. **Canonical MPT authority** — exact root-to-terminal verification for branch, extension, and leaf nodes; both inclusion and non-inclusion are authenticated.
6. **Block-state anchor** — a full confirmed/finalized block head and a later full state-root observation must share one exact chain/source/finality stream and the same block identity.
7. **Account proof authority** — the account path is Keccak-256 of the exact 20-byte address, and the authenticated leaf must decode to exactly nonce, balance, storage root, and code hash.
8. **Storage proof authority** — each storage path is Keccak-256 of the normalized exact 32-byte slot; zero values require authenticated non-inclusion.
9. **Evidence recomputation** — callers cannot inject derived approval fields. Evidence stores the exact anchor and proof observation, then re-runs verification during construction.
10. **Snapshot authority** — account evidence is unique, sorted by address, bound to one exact anchor, and digest-addressed.
11. **Capability gating** — block-state observations are governed for all four EVM chains; authenticated account/storage proofs are enabled only for Ethereum and Base in F2.
12. **Exact-head CI** — source-head and synthetic-merge revisions independently run the inherited and F2 conformance suites under read-only permissions.

## Authority limits

```text
network_access        = none
signing_authority     = none
execution_authority   = none
observation_authority = recorded-input-only
state_proof_authority = offline-recorded-input-only
```

F2 proves only that supplied proof material authenticates the supplied state root under the governed algorithms. It does not independently acquire a canonical state root from a network. That provenance remains bound to the recorded source contract and observation ledger.

## Chain scope

| Chain | Block-state anchor | Account/storage proof |
|---|---:|---:|
| Ethereum | Enabled | Enabled |
| Base | Enabled | Enabled |
| Arbitrum | Enabled | Disabled |
| BNB Smart Chain | Enabled | Disabled |
| Solana | Not an EVM scope | Not an EVM scope |

## External specification anchors

- EIP-1186 account and storage proof response contract.
- Ethereum Merkle Patricia Trie path and node semantics.
- Ethereum Recursive Length Prefix encoding.
- Go-ethereum proof generation and verification behavior.
- Base official `eth_getProof` and historical-proof node documentation.

These references constrain the offline verifier. They do not grant network authority.
