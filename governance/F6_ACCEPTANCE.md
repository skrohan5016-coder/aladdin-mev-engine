# F6 Acceptance Contract

F6 is accepted only when one exact source head and its current synthetic merge independently satisfy all requirements below.

## Required implementation

- exact accepted F5 parent identity;
- dependency-free secp256k1 point, verification, and recovery authority;
- public scalar multiplication rejects values above the secp256k1 group order before curve work;
- exact EIP-2 low-s signature evidence;
- unique recovery of the authenticated F5 sender;
- canonical signed type-2 transaction bytes and exact transaction hash;
- signed bundle identity/order equivalence with the F5 private intent;
- explicit URL-free and credential-free relay endpoint registry;
- immutable canonical normalized request payload with no dispatch path;
- closed recorded relay-response evidence with accepted/rejected/error semantics;
- independent uniqueness of relay response source IDs and source digests;
- final externally-signed package recomputation;
- exact eight-file F6 schema lock;
- no runtime private key, signer, HTTP transport, submission, execution, or inclusion authority.

## Required adversarial validation

Wrong key, hash, parity, scalar, high-s form, sender, timestamp, transaction order, bundle identity, endpoint chain/class, request identity, mutable payload attempt, response cross-field mismatch, duplicate source ID, duplicate source digest, future response, expired evidence, and authority escalation must fail closed. Known Ethereum address vectors and randomized test-only signature round trips must pass.

## Required CI

Exact source head and current GitHub synthetic merge must separately pass Python compilation, the complete inherited F0–F6 test suite, repository policy, architecture lock, source-contract lock, F2/F3/F4/F5/F6 schema locks, and clean-worktree validation with read-only permissions and immutable action pins.

F6 acceptance does not authorize key custody, signing, networking, relay credentials, request dispatch, transaction or bundle submission, execution, inclusion, or profit.
