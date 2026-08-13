# Security Boundaries

## Repository

The repository is public for transparent review and standard hosted CI. Visibility is not permission to publish secrets. Production configuration and operational edge must remain outside version control.

## Future identities

Later milestones must isolate, per chain:

- observation credentials;
- searcher reputation identity;
- executor hot wallet;
- deployment authority;
- emergency governance authority;
- treasury destination.

An AI ranking component may analyze evidence but must never possess keys, sign transactions, modify risk policy, or bypass deterministic authorization.

## CI

CI validates code and evidence contracts. Only the governed immutable checkout and Python-setup actions are allowed; token permissions remain read-only, and workflow commands may not publish or initiate arbitrary network traffic. CI must never become a production bot host, a signer, a deployment authority, or a holder of mainnet credentials.
