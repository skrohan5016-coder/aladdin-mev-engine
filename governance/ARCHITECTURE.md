# Aladdin MEV Engine Architecture

## Accepted lineage

F7 is built from accepted F6 landing `6481e17b2345c54261865125b61523610b7f87af`, tree `1115dccd7952225dfa1d58238aa550bf9e0aa995`, and architecture `AMEV-F6-ARCH-v1-c91039d7d800`. F0 supplies canonical evidence, policy, and risk controls; F1 supplies recorded observation and replay; F2 supplies authenticated EVM state; F3 supplies exact gross opportunities; F4 supplies deterministic plans and conservative cost-complete shadow economics; F5 supplies authenticated unsigned transaction packages; F6 verifies externally produced signatures and records relay evidence; F7 authenticates historical transaction/receipt inclusion and reconciles one governed executor settlement event.

## Inherited authority retention

F7 does not weaken F0–F6. All earlier canonical, proof, model, optimization, cost, transaction, signature, relay, and authority-denial contracts remain independently locked and tested.

## Trust flow

```text
Recorded observations + authenticated EVM state
  -> F3 opportunity + F4 conservative shadow decision
  -> F5 unsigned execution package
  -> F6 external signature and relay evidence
  -> recorded canonical block header + exact F2 state anchor
  -> exact inclusion-block executor account/code/storage proof
  -> transaction/receipt trie inclusion + exact gas
  -> code-hash-bound executor settlement event + recorded rollup fees
  -> F7 authenticated execution-outcome evidence
```

## F7 authority boundaries

```text
network_access                   = none
relay_access                     = none
credential_authority             = none
key_authority                    = none
local_signing_authority          = none
signing_authority                = external-unmodeled
submission_authority             = none
execution_authority              = none
inclusion_authority              = offline-authenticated-transaction-receipt-and-executor-post-state-inclusion-only
settlement_authority             = offline-code-hash-bound-executor-event-reconciliation-only
realized_outcome_authority       = authenticated-inclusion-receipt-code-hash-bound-settlement-and-recorded-rollup-fees-only
realized_profit_authority        = none
inclusion_guarantee              = none
```

An F7 outcome is historical authenticated evidence. It is not a network request, inclusion forecast, signing/submission instruction, general token-balance proof, treasury statement, tax record, or profit guarantee.

## F7 hardening invariants

The raw header hash and all governed root/fee fields are recomputed. Receipt log and topic ceilings are enforced before canonicalization or topic materialization, and canonical log-array hashing enforces the global JSON byte ceiling incrementally before whole-array allocation. Receipt log addresses preserve the consensus `Bytes20` domain rather than inheriting deployment-only nonzero policy. The F7 schema graph is checked by declared URI identity, not file presence alone. The executor account is re-authenticated at the inclusion block's exact post-state root: its address and runtime code hash must match F5/F6, its storage root must remain the canonical empty trie, and no unused storage proof is accepted. Transaction and receipt proofs share one exact index and authenticated header roots. Nonzero transaction indices require an exact previous receipt. Individual gas is an exact cumulative delta and remains inside F5 limits. Settlement interpretation is selected by the same authenticated non-empty executor runtime code hash and block validity. The post-state code check detects persistent drift but is explicitly model-bound rather than an intra-block execution trace. One exact event must reconcile inherited plan and simulation economics. Actual recorded native costs may not exceed F4 upper bounds. Simulation drift is reported rather than hidden. No F7 object claims realized profit or gains key, submission, or execution authority.

The machine-readable architecture manifest and lock are authoritative.
