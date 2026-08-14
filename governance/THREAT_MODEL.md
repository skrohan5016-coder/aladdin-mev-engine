# Threat Model

## Protected assets

Inherited F0–F5 evidence, economics, authenticated sender/deployment state, unsigned transaction and bundle identity, secp256k1 verification correctness, signed transaction bytes, relay evidence identity, honest separation of recorded relay acceptance from inclusion, and future keys and funds.

## Inherited failure modes remain active

F6 does not replace earlier controls. Canonical-JSON ambiguity, ledger truncation, source drift, reorg errors, malformed proofs, state mismatch, market-model ambiguity, optimizer errors, valuation/cost errors, stale simulations, unsigned transaction drift, and false F5 package approval remain governed by accepted contracts and regression tests.

## F6 failure modes

- invalid curve points or signature scalars;
- high-s malleable signatures;
- wrong hash, parity, key, or recovered sender;
- changing an F5 unsigned field while presenting the result as the same signed transaction;
- non-canonical signed RLP or wrong transaction hash;
- signed bundle count, order, target, sender, or validity drift;
- an endpoint ID assigned conflicting chain or protocol semantics;
- URL, credential, token, production approval, or transport capability entering relay evidence;
- request payload mutation after construction;
- a relay response predating its request, arriving after validity, or carrying contradictory accepted/error fields;
- duplicate response authorities hidden behind source aliases;
- relay acceptance presented as inclusion, execution, or realized profit;
- private keys or signing/submission helpers entering production source;
- CI command, action, runner, shell, environment, permission, condition, timeout, or error-handling bypass.

## Controls

Exact runtime types; closed schemas; constructor-time recomputation; dependency-free curve arithmetic; known address vectors and randomized test-only signature round trips; bounded low-s scalars; unique authenticated-sender recovery; canonical type-2 RLP and legacy Keccak; exact F5 identity retention; deterministic endpoint registry; immutable canonical request bytes; detached request payload copies; independently unique response source IDs and digests; transitive time validity; explicit false eligibility/guarantee fields; static production-source denial of keys, signing, networking, and dispatch; immutable locks; hardened read-only CI.

## Residual risks

F6 verifies recorded signature and relay evidence. It does not prove who controlled an external signer, whether a signature source was trustworthy, whether a relay endpoint exists or is available, whether a response was authentic beyond its recorded source authority, whether the relay accepted the exact request live, whether a transaction was included, or whether profit was realized. Those require later separately governed live infrastructure, key custody, submission, inclusion, and settlement milestones with explicit human approval.
