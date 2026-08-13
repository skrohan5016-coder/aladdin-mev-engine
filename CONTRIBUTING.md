# Contributing

Run `make all` before opening a pull request. Every PR must state its base, head, scope, authority impact, security impact, and validation evidence.

Hard rules: no live networking, secrets, signing, broadcasting, deployment, or execution in F3; exact integer money math only; unknown inputs fail closed; F2 proof authority remains exact; pool tokens/reserves must be authenticated; one code hash cannot authorize conflicting models; continuous math may only upper-bound exact search; incomplete/nonpositive optimization cannot become an opportunity; every F3 opportunity remains gross-only and execution-disabled; CI actions are immutable SHA-pinned with read-only permissions.
