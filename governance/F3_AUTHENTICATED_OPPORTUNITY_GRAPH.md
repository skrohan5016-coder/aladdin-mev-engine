# F3 Authenticated Constant-Product Opportunity Graph

F3 answers one narrow question: given an exact F2-authenticated snapshot and one explicit constant-product model set, which bounded simple cycles have a complete positive exact **gross** integer result?

## Model and pool identity

A model binds runtime code hash, token/reserve storage fields, fee numerator/denominator, checked arithmetic, and a standard-token assumption. One code hash cannot appear with conflicting mathematics. A pool is accepted only when its exact account, code hash, token fields, reserve fields, slot set, and snapshot anchor authenticate successfully.

## Route rules

- two through four hops;
- exact directional pool edges;
- no pool reuse;
- no repeated intermediate token;
- base token returns only on the final leg;
- at most 4,096 routes and 100,000 traversal steps.

Pool reuse is forbidden because F3 quotes every pool against one immutable pre-state. Reuse requires later stateful execution simulation.

## Optimization

The no-floor route composition is `A*x/(B+C*x)`. It is concave and supplies only an optimistic upper bound. Every candidate input and winning result is evaluated with exact integer floor at every hop. Per-route search work and aggregate report work are both bounded; `budget-exhausted` remains incomplete.

Closed outcomes are `complete`, `no-valid-input`, `no-positive-continuous-edge`, `no-positive-exact-profit`, and `budget-exhausted`.

## Evidence boundary

Intermediate pool quotes, route quotes, and optimization records are diagnostic values, not standalone opportunity authority. Only `AtomicDexOpportunityEvidence` and `OpportunitySearchReport` recompute their complete result from the exact bound universe, route, and limits.

Opportunity construction reruns route optimization and exact quoting. It requires complete positive exact gross profit and always declares:

```text
cost_completeness = gross-only-no-gas-no-inclusion-no-funding
execution_eligible = false
```

F3 does not verify token transfer behavior, pending ordering, EVM execution, gas, inclusion, funding, approvals, calldata, nonces, signing, or submission.

## Final authority hardening


- The canonical empty-code hash cannot be registered as a pool runtime model.
- Optimization result counters, bounds, and status-specific winner fields are cross-validated.
- Route and optimizer input ceilings are closed to exact uint256 values.
- A budget-exhausted result is incomplete and cannot carry a winning input, output, or profit.
- Continuous pruning bounds are themselves bounded to uint256 and remain non-authoritative.
