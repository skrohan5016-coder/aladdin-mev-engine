# Chain Capability Matrix

| Chain | Recorded observation | Authenticated proof | F3/F4 opportunity economics | F5 unsigned package | Live execution |
|---|---:|---:|---:|---:|---:|
| Ethereum | Enabled | Enabled | Enabled, explicit-model shadow only | Enabled, authenticated unsigned only | Disabled |
| Base | Enabled | Enabled | Enabled, explicit-model shadow only with explicit L1-data/operator-fee bounds | Enabled, authenticated unsigned only | Disabled |
| Arbitrum | Enabled | Disabled | Disabled | Disabled | Disabled |
| BNB Smart Chain | Enabled | Disabled | Disabled | Disabled | Disabled |
| Solana | Separate design | Separate future authority | Disabled | Disabled | Disabled |

No generic adapter may claim support based only on EVM compatibility. Proof, deployment, token, fee, nonce, transaction, ordering, simulation, relay, and inclusion semantics are chain-specific.
