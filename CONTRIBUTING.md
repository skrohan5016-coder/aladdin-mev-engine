# Contributing

Run `make all` before opening a pull request. Every PR must state its base, head, scope, authority impact, security impact, and validation evidence.

Hard rules: no live networking, secrets, keys, signing, broadcasting, bundle submission, deployment, funding, or execution in F5; exact integer money and transaction fields only; unknown inputs fail closed; inherited F0-F4 authority remains exact; executor and sender state must be authenticated, and the F5 executor storage root must be canonical empty; one executor code hash cannot authorize conflicting interfaces; the interface must bind the authenticated sender as the complete base-token residual beneficiary; calldata must be derived from F4; no signature or relay credential may enter evidence; all F5 packages remain unsigned, unsubmitted, and execution-disabled; CI actions are immutable SHA-pinned with read-only permissions.
