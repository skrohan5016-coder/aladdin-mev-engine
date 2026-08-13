# F3 Threat Model

## Protected assets

Inherited F0–F2 integrity; model-registry identity; authenticated token/reserve correctness; exact arithmetic and route math; optimizer completeness and upper-bound safety; honest separation of gross shadow evidence from executable profit; future signer/executor/treasury separation.

## Failure modes

- wrong code hash, token pair, storage layout, fee, or reserve interpretation;
- conflicting models for one runtime code hash;
- proxy, dynamic-fee, fee-on-transfer, rebasing, hook, or callback behavior misrepresented as a direct static model;
- overlapping or malformed packed fields;
- checked arithmetic or packed-reserve overflow;
- route reuse, disconnection, repeated token, early base return, unbounded enumeration, or multiplicative report-work exhaustion;
- continuous approximation treated as exact or an unsafe bound pruning the optimum;
- budget exhaustion treated as complete;
- caller-injected optimization, quote, identity, or timestamp;
- gross profit mislabeled as net, funded, included, or executable;
- networking, credential, signing, deployment, or execution capability introduced silently.

## Controls

Exact F2 types at every state boundary; one-code-hash/one-model invariant; exact slot/token/reserve binding; checked arithmetic and capacity gates; simple-cycle constraints; exact per-hop floor; tested optimistic bounds; bounded per-route and aggregate exact search; constructor-time recomputation; hardcoded gross-only execution-disabled labels; zero runtime dependencies; read-only exact-head CI.

## Residual risks

F3 does not prove that an explicit model describes a production deployment, that a token has standard transfer behavior, or that authenticated reserves are economically current. It does not execute EVM bytecode, model pending ordering, estimate costs/inclusion, source capital, or construct/sign/submit transactions.

## Final authority hardening


- The canonical empty-code hash cannot be registered as a pool runtime model.
- Optimization result counters, bounds, and status-specific winner fields are cross-validated.
- Route and optimizer input ceilings are closed to exact uint256 values.
- A budget-exhausted result is incomplete and cannot carry a winning input, output, or profit.
- Continuous pruning bounds are themselves bounded to uint256 and remain non-authoritative.
