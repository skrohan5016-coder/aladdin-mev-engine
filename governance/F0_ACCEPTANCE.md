# F0 Acceptance Contract

## Identity

- Repository: `skrohan5016-coder/aladdin-mev-engine`
- Accepted starting main: `0ef0ef3ddae327cf00f1ca356079da7b26466e3d`
- Starting tree: `cc03ca6ae37d72625775e69cac777acd836e5699`
- Working branch: `agent/f0-governed-architecture-v1`
- Milestone: `F0 — Governed Architecture and Profit-Safety Foundation`

## Required gates

- Python bytecode compilation succeeds.
- All unit and adversarial tests succeed.
- Architecture lock matches canonical manifest content.
- No runtime dependency is declared.
- No network, signing, broadcast, or deployment implementation exists.
- Workflow token permission is read-only.
- Workflow actions are pinned to immutable 40-character commit SHAs.
- Checkout credentials are not persisted.
- Workflow does not reference repository secrets or `pull_request_target`.
- All JSON schemas parse, reject unknown top-level fields, and carry stable identifiers.
- Public documentation states shadow-only and non-guaranteed-profit boundaries.

## Explicit non-acceptance

Passing F0 does not authorize canary or live trading, mainnet deployment, wallet funding, private-key use, RPC credentials, or profit claims.
