# Threat Model

## Protected assets

Inherited F0–F6 evidence and authority boundaries; authenticated block, transaction, receipt, gas, log, settlement, and fee identity; honest separation between historical execution evidence and live authority or realized-profit claims; future keys, accounts, and funds.

## Inherited failure modes remain active

Canonical-JSON ambiguity, ledger tampering, source drift, reorg errors, malformed state proofs, model ambiguity, optimizer errors, conservative-cost drift, unsigned/signed transaction drift, relay-evidence spoofing, and CI bypasses remain governed by inherited contracts and tests.

## F7 failure modes

- fabricated block header, hash, roots, base fee, timestamp, source, or finality;
- executor disappearance, runtime-code replacement, or non-empty storage at the inclusion-block post-state;
- malformed or oversized transaction/receipt trie proofs;
- transaction and receipt index mismatch;
- wrong signed transaction bytes under a valid unrelated proof;
- missing or non-adjacent previous receipt causing false gas attribution;
- conflating consensus `Bytes20` log addresses with nonzero governed deployment/token identity rules;
- malformed or work-amplifying receipt, status, typed envelope, log/topic list, aggregate canonical log array, target/block bloom relation, or cumulative gas;
- inclusion outside the signed bundle range or after the executor deadline;
- ambiguous, empty-code, or expired settlement-event model for one runtime code hash;
- event emitted by the wrong address or with wrong topic0/indexed topics/ABI data;
- receipt address-domain narrowing that rejects a consensus-valid zero `Bytes20` log emitter;
- a schema file that exists locally but whose relative `$ref` does not resolve to the target declared `$id`;
- wrong plan, beneficiary, token, principal, fee, decoded-log, or unused-`msg.value` refund semantics;
- successful output, residual, direct-payment, gas, log, or conservative-cost drift silently rejected and thereby removed from historical evidence;
- adverse drift mislabeled as simulation agreement, upper-bound compliance, conservative-floor preservation, or realized profit;
- relay acceptance or a successful receipt presented as a realized-profit proof;
- key, network, signing, submission, deployment, or execution capability entering production source;
- CI command, action, runner, shell, environment, permission, condition, timeout, or error-handling bypass.

## Controls

Exact runtime types; bounded canonical RLP; legacy-Keccak header verification; exact F2 anchor cross-check; authenticated inclusion-block executor account/code/empty-storage proof; bounded MPT proofs; previous-receipt gas attribution; pre-materialization receipt log/topic work gates; incremental globally byte-bounded canonical log-array hashing; canonical receipt/bloom/log reconstruction; checked integer fee math; exact F6 transaction identity; code-hash/time-bound event registry; constructor-time hard plan/identity/arithmetic checks; explicit simulation/economic/cost drift fields; explicit false profit and live-authority fields; closed schemas with standard URI-resolvable identities and immutable locks; hardened read-only exact-head and merge CI.

## Residual risks

F7 depends on recorded source authority and the governed executor-event model. The authenticated executor post-state proves persistent code/storage identity after the block but is not an intra-block execution trace; code semantics remain explicit model authority. It does not independently prove every ERC-20 balance change, external protocol internal accounting, relay authenticity, chain finality beyond the recorded authenticated anchor, treasury custody, fiat conversion, taxes, or realized profit. Live collection, production endpoint approval, key custody, submission, monitoring, and financial accounting require separate milestones and explicit approval.
