# Security

Never commit private keys, mnemonic or seed phrases, HSM/KMS credentials, wallet files, RPC URLs/tokens, relay or builder URLs/tokens, authentication headers, deployment authority, funded-account secrets, or production configuration.

F7 verifies recorded block headers, trie proofs, receipts, executor events, and fee evidence offline. Production source and scripts must not generate signatures, access keys, open network connections, poll chain or relay state, dispatch requests, submit transactions or bundles, deploy contracts, or move funds. Test-only deterministic signing and trie fixtures must remain under `tests/` and contain no real secrets.

A successful receipt or executor event is not automatically a realized-profit, treasury, accounting, tax, or fiat-value record. Report suspected secret exposure or authority escalation privately before opening a public issue.
