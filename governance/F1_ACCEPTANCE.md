# F1 Acceptance Contract

F1 is accepted only when all gates hold on one exact source head and its current GitHub synthetic merge revision.

## Required behavior

- Nine governed recorded-input source contracts exactly match the machine-readable registry and SHA-256 lock.
- Source contracts allow explicit event/finality/visibility triples; accidental Cartesian-product permissions fail closed.
- Observation envelopes are canonical, immutable, unsigned-64-bit bounded, source-contract bound, and digest addressed.
- New sources start at sequence zero; sequences and observation times remain continuous across segment checkpoints.
- Source gaps are explicit closed metadata records.
- Records form deterministic per-segment SHA-256 chains.
- Manifests form a cross-segment SHA-256/checkpoint chain and bind order, count, roots, source-contract authority, and complete source state.
- Replay rejects mutation, reordering, truncation, excessive record lines, missing prefixes, wrong parents, malformed framing, unknown fields, and digest drift.
- Segment storage is no-overwrite, no-follow, read-only, single-link, stable-path, optionally external-digest anchored, and directory-durable.
- Every EVM head tracker is bound to one exact source/kind/finality/full-visibility stream.
- EVM head transitions identify bootstrap, extension, reorg, duplicate, and orphan events deterministically and bind the triggering observation digest and source sequence.
- Filtered head sequences may skip non-head events but never repeat or move backwards.
- Unknown-parent topology is not retained; conflicting duplicate block metadata and rejected-head state mutation fail closed.
- Solana observation remains unsupported instead of being represented as EVM.

## Security boundary

- `network_access = none`
- `execution_authority = none`
- `signing_authority = none`
- runtime dependencies remain empty
- CI uses read-only permissions and only governed immutable actions
- no credential, RPC secret, wallet, private key, bundle submission, endpoint polling, or production deployment is introduced

## Validation gates

- all inherited F0 tests pass;
- all F1 unit and adversarial tests pass;
- compilation, repository policy, architecture lock, and source-contract lock pass;
- repeated hash-seed and Python development-runtime runs pass;
- randomized multi-segment replay and mutation checks pass;
- exact-head and merge-integration GitHub Actions pass;
- fresh review finds no unresolved high-confidence authority gap.
