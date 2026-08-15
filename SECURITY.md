# Security

Never commit private keys, mnemonic or seed phrases, HSM/KMS credentials, wallet files, RPC URLs/tokens, relay or builder URLs/tokens, authentication headers, deployment authority, funded-account secrets, or production configuration.

F8 evaluates recorded F6/F7 evidence offline. Production source and scripts must not generate signatures, access keys, open network connections, poll chain or relay state, dispatch requests, submit transactions or bundles, deploy contracts, move funds, auto-promote a production strategy, or claim realized profit. Test-only deterministic signing, trie, outcome, and scoreboard fixtures must remain under `tests/` and contain no real secrets.

A passing research-promotion decision is not production approval, a trading instruction, a confidence guarantee, or a profit promise. Report suspected secret exposure, dataset bias, score manipulation, or authority escalation privately before opening a public issue.
