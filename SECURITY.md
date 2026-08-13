# Security Policy

## F2 security posture

F2 is offline and recorded-input only. It intentionally has:

- no network client or RPC credential path;
- no transaction or bundle broadcaster;
- no signing implementation;
- no private-key or seed handling;
- no contract deployment script;
- no mainnet execution authority.

It verifies recorded Ethereum/Base account and storage proofs against recorded state roots. It does not independently acquire or trust a network endpoint.

Any change that introduces live observation, credentials, signing, transaction construction/submission, deployment, or execution requires a later governed milestone, explicit threat-model update, adversarial tests, exact-head review, and Rohan's human approval.

## Never commit

Do not commit wallet material, seed phrases, private keys, RPC credentials, builder or relay credentials, Jito credentials, deployment authorities, treasury access, production database credentials, raw `.env` files, or private strategy configuration.

## Reporting

Do not open a public issue containing an exploitable vulnerability or secret. Contact the repository owner privately and include the affected commit, reproduction conditions, impact, and a minimal remediation proposal. Never include live credentials in a report.

## Supported versions

Only the current default branch and the active reviewed pull request are supported during the pre-production phase.
