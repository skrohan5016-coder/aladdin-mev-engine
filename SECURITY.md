# Security

Never commit private keys, mnemonic or seed phrases, HSM/KMS credentials, wallet files, RPC URLs/tokens, relay or builder URLs/tokens, authentication headers, deployment authority, funded-account secrets, or production configuration.

F6 verifies externally produced secp256k1 signatures and records offline relay request/response evidence. Production source and scripts must not generate signatures, access keys, open network connections, dispatch requests, submit transactions or bundles, deploy contracts, or move funds. Test-only deterministic signing fixtures must remain under `tests/` and contain no real key material.

Report suspected secret exposure or authority escalation privately before opening a public issue.
