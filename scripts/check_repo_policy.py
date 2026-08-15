from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_WORKFLOW_SHA256 = "0e1ecfd7c5a4cdce24f2ad2d245c00c44a051551efebf655a3b9cd8c4e42c9ff"

PINNED_ACTIONS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
}
EXPECTED_RUN_COMMANDS = {
    'test "$(git rev-parse HEAD)" = "${{ github.event.pull_request.head.sha || github.sha }}"': 1,
    'test "$(git rev-parse HEAD)" = "${{ github.sha }}"': 1,
    "python -m compileall -q src tests scripts": 2,
    "python -m unittest discover -s tests -v": 2,
    "python scripts/check_repo_policy.py": 2,
    "python scripts/verify_architecture_lock.py": 2,
    "python scripts/verify_source_contracts.py": 2,
    "python scripts/verify_f2_schemas.py": 2,
    "python scripts/verify_f3_schemas.py": 2,
    "python scripts/verify_f4_schemas.py": 2,
    "python scripts/verify_f5_schemas.py": 2,
    "python scripts/verify_f6_schemas.py": 2,
    "python scripts/verify_f7_schemas.py": 2,
    "git diff --exit-code": 2,
}
EXPECTED_SOURCE_IDS = (
    "arbitrum-json-rpc",
    "arbitrum-sequencer-feed",
    "arbitrum-timeboost-auction",
    "base-flashblocks",
    "base-json-rpc",
    "bnb-json-rpc",
    "bnb-pbs-metadata",
    "ethereum-json-rpc",
    "ethereum-mev-share",
)
EXPECTED_PARENT = {
    "accepted_parent_architecture_id": "AMEV-F6-ARCH-v1-c91039d7d800",
    "accepted_parent_head": "6481e17b2345c54261865125b61523610b7f87af",
    "accepted_parent_tree": "1115dccd7952225dfa1d58238aa550bf9e0aa995",
}
REQUIRED_COMPONENTS = {
    "explicit-code-hash-bound-constant-product-models",
    "one-code-hash-one-model-registry",
    "authenticated-token-and-packed-reserve-decoder",
    "checked-uint256-exact-input-quote",
    "packed-reserve-capacity-gate",
    "deterministic-simple-cycle-enumerator",
    "bounded-route-enumeration-work",
    "exact-per-hop-integer-floor-routing",
    "continuous-concave-upper-bound",
    "exact-branch-and-bound-optimizer",
    "bounded-optimizer-work",
    "aggregate-opportunity-search-work-gate",
    "deterministic-smaller-input-tie-break",
    "gross-only-opportunity-evidence-recomputation",
    "f3-schema-lock",
    "chain-bound-native-and-erc20-asset-identity",
    "checked-uint256-valuation-intermediate",
    "directional-ceiling-valuation-authority",
    "deterministic-atomic-route-execution-plan",
    "explicit-own-inventory-or-recorded-flash-funding",
    "eip1559-and-base-fee-upper-bound-envelope",
    "explicit-op-stack-operator-fee-upper-bound",
    "independent-route-simulation-binding",
    "source-build-and-time-bound-route-simulation-evidence",
    "canonical-route-simulation-ordering",
    "cost-input-lifetime-revalidation",
    "exact-required-valuation-pair-set",
    "recorded-chain-health-context",
    "recomputed-risk-budget-snapshot",
    "distinct-simulator-implementation-and-result-source-binding",
    "final-evidence-transitive-validity-recheck",
    "exact-state-reference-bound-route-simulation-evidence",
    "exact-complete-reserve-cost-category-set",
    "base-asset-cost-reconciliation",
    "conservative-shadow-net-profit-evidence",
    "exact-simulation-environment-consensus",
    "checked-uint256-risk-budget-aggregation",
    "risk-budget-post-cost-envelope-ordering",
    "uint256-closed-f4-profit-policy",
    "f4-schema-lock",
    "authenticated-executor-direct-runtime-deployment",
    "one-executor-code-hash-one-interface-registry",
    "deterministic-executor-abi-calldata",
    "authenticated-eoa-sender-nonce-and-balance",
    "deterministic-eip1559-signing-preimage",
    "bounded-contiguous-nonce-private-bundle-intent",
    "transaction-and-bundle-bound-independent-simulation",
    "unsigned-execution-package-evidence",
    "operator-fee-sender-balance-and-simulation-reconciliation",
    "f5-schema-lock",
    "closed-route-semantic-public-governed-abi-encoder",
    "authenticated-anchor-relative-simulation-timestamp-gate",
    "exact-millisecond-executor-input-validity",
    "bounded-secp256k1-scalar-multiplication",
    "dependency-free-secp256k1-curve-authority",
    "canonical-low-s-eip1559-signature-evidence",
    "exact-authenticated-sender-public-key-recovery",
    "deterministic-signed-eip1559-transaction-encoding",
    "signed-private-bundle-evidence",
    "explicit-relay-endpoint-evidence-registry",
    "relay-neutral-normalized-private-bundle-request",
    "recorded-relay-response-evidence",
    "externally-signed-execution-package-evidence",
    "immutable-relay-request-payload-evidence",
    "unique-relay-response-source-authority",
    "cached-digest-preserving-evidence-performance",
    "f6-schema-lock",
    "authenticated-block-header-root-cross-check",
    "authenticated-inclusion-executor-post-state-code-and-storage-binding",
    "authenticated-execution-outcome-reconciliation",
    "bounded-indexed-trie-proof-evidence",
    "bounded-canonical-receipt-log-array-digest",
    "canonical-eip2718-transaction-receipt-decoder",
    "code-hash-bound-executor-settlement-event-registry",
    "exact-effective-eip1559-gas-price-reconciliation",
    "exact-receipt-logs-bloom-recomputation",
    "pre-materialization-receipt-structure-work-gates",
    "f7-schema-lock",
    "indexed-receipts-trie-inclusion-proof",
    "indexed-transactions-trie-inclusion-proof",
    "no-realized-profit-claim",
    "previous-receipt-cumulative-gas-reconciliation",
    "recorded-rollup-fee-evidence",
    "consensus-exact-evm-log-address-domain",
    "empty-code-settlement-model-gate",
    "standard-resolvable-f7-schema-graph",
}
REQUIRED_INVARIANTS = {
    "explicit-model-registry-is-evidence-identity-not-production-approval",
    "one-runtime-code-hash-cannot-authorize-conflicting-constant-product-models",
    "empty-runtime-code-hash-cannot-authorize-a-constant-product-model",
    "optimization-result-cross-field-counts-bounds-and-status-authority-are-internally-consistent",
    "pool-code-hash-token-identities-and-reserves-bind-exact-authenticated-account-and-storage-evidence",
    "pool-model-storage-slots-are-exact-authenticated-inclusions",
    "state-freshness-uses-the-block-state-observation-time-not-later-proof-fetch-time",
    "fee-layout-and-transfer-semantics-are-explicit-model-assumptions",
    "exact-input-quotes-use-checked-uint256-and-floor-at-every-hop",
    "packed-reserve-capacity-is-enforced-before-quoting",
    "routes-are-two-to-four-hop-simple-cycles-without-pool-reuse-or-early-base-return",
    "route-enumeration-and-optimizer-work-are-deterministically-bounded",
    "aggregate-opportunity-report-work-is-bounded-before-route-optimization",
    "continuous-mathematics-may-only-upper-bound-and-prune-exact-search",
    "optimizer-ties-select-the-smallest-exact-input",
    "budget-exhaustion-is-incomplete-and-cannot-authorize-an-opportunity",
    "route-optimizer-requested-input-domains-are-closed-to-uint256",
    "incomplete-optimization-evidence-cannot-carry-a-winning-input-output-or-profit",
    "continuous-optimization-upper-bounds-are-closed-to-uint256",
    "nonpositive-exact-gross-profit-cannot-authorize-an-opportunity",
    "opportunity-evidence-recomputes-route-optimization-and-exact-quote-from-bound-inputs",
    "intermediate-route-quote-and-optimization-values-grant-no-standalone-opportunity-authority",
    "f3-opportunities-are-gross-only-cost-incomplete-and-never-execution-eligible",
    "f3-schema-lock-binds-all-new-schemas-and-the-transitive-opportunity-schema-dependency",
    "asset-identities-are-chain-and-kind-bound",
    "valuation-is-directional-explicit-time-bounded-and-rounded-up",
    "valuation-multiplication-is-checked-uint256-before-ceiling-division",
    "implicit-inverse-or-cross-chain-valuation-is-forbidden",
    "execution-plans-recompute-every-step-from-the-exact-f3-route-quote",
    "execution-plans-carry-no-calldata-signing-or-execution-authority",
    "funding-principal-and-asset-equal-the-exact-f3-capital-and-base-token",
    "flash-loan-fees-are-explicit-recorded-inputs-not-hardcoded-protocol-assumptions",
    "eip1559-priority-fee-is-contained-inside-max-fee-and-never-added-again",
    "ethereum-l1-data-fee-is-zero-and-base-l1-security-fee-is-explicit",
    "direct-inclusion-payment-is-separated-from-priority-fee",
    "op-stack-operator-fee-is-explicit-separate-from-eip1559-gas-l1-data-and-direct-payment",
    "ethereum-operator-fee-upper-bound-and-paid-amount-are-zero",
    "base-operator-fee-upper-bound-is-recorded-converted-and-included-in-authenticated-sender-balance",
    "route-simulations-bind-the-exact-opportunity-and-plan-and-require-unique-engines",
    "route-simulation-independence-requires-distinct-engine-implementation-and-result-source-digests",
    "route-simulations-bind-the-exact-state-reference-and-remain-valid-at-final-evidence-time",
    "simulation-order-does-not-change-net-evidence-identity",
    "successful-route-simulations-agree-on-gas-output-token-deltas-and-post-state",
    "every-reserve-cost-category-is-present-exactly-once",
    "all-cost-assets-are-converted-to-the-f3-base-asset-with-conservative-ceiling",
    "gross-profit-and-flash-fee-are-derived-from-bound-f3-and-funding-authority",
    "simulated-gas-cannot-exceed-the-recorded-gas-upper-bound",
    "cost-complete-shadow-approval-never-grants-inclusion-signing-or-execution-authority",
    "funding-fee-reserve-and-valuation-inputs-remain-valid-at-cost-and-net-evidence-times",
    "valuation-book-contains-exactly-the-required-cost-conversion-pairs",
    "chain-health-is-source-bound-time-bound-and-chain-bound",
    "risk-budget-is-recomputed-from-a-source-bound-snapshot-and-binds-plan-cost-and-notional",
    "route-simulation-agreement-requires-one-exact-environment-digest",
    "risk-budget-pending-daily-and-concurrency-aggregation-is-checked-uint256",
    "risk-budget-snapshot-cannot-precede-the-bound-execution-cost-envelope",
    "f4-profit-policy-integer-fields-are-closed-to-uint256",
    "cost-envelope-and-all-transitive-inputs-remain-valid-at-final-net-evidence-time",
    "bare-chain-health-and-risk-budget-values-have-no-decision-authority",
    "f4-schema-lock-binds-all-new-schemas-and-the-inherited-decision-schema",
    "executor-deployment-address-chain-code-hash-and-validity-bind-exact-f2-evidence",
    "executor-deployment-is-direct-runtime-recorded-evidence-not-production-approval",
    "one-executor-runtime-code-hash-cannot-authorize-conflicting-interfaces",
    "executor-calldata-uses-one-exact-selector-and-canonical-abi-layout",
    "executor-minimum-final-output-cannot-weaken-f4-cost-and-profit-policy",
    "executor-deadline-is-bounded-by-f4-input-validity-and-policy-horizon",
    "sender-is-an-authenticated-eoa-with-empty-code-and-storage",
    "unsigned-transaction-nonce-and-balance-come-from-the-exact-shared-state-anchor",
    "unsigned-transaction-upfront-native-requirement-includes-gas-value-and-base-l1-fee",
    "private-bundle-transactions-share-chain-sender-anchor-and-contiguous-nonces",
    "private-bundle-target-block-and-horizon-are-deterministically-bounded",
    "transaction-simulation-independence-requires-distinct-engine-implementation-and-source-digests",
    "transaction-simulations-bind-exact-anchor-transaction-signing-hash-and-bundle",
    "transaction-simulations-agree-on-gas-output-token-deltas-logs-post-state-and-coinbase-payment",
    "transaction-simulation-gas-is-bounded-by-canonical-intrinsic-gas-and-the-unsigned-transaction-gas-limit",
    "transaction-simulation-operator-fee-does-not-exceed-the-recorded-upper-bound",
    "unsigned-execution-package-recomputes-all-f4-call-transaction-bundle-and-simulation-identities",
    "f5-never-grants-signing-submission-execution-or-inclusion-authority",
    "f5-schema-lock-binds-all-new-unsigned-package-schemas",
    "public-governed-abi-encoder-enforces-simple-cycle-unique-pool-base-token-principal-amount-flow-final-minimum-and-bounded-frame-semantics",
    "simulated-block-timestamp-strictly-follows-the-authenticated-anchor-block-timestamp",
    "executor-call-validity-preserves-the-exact-millisecond-policy-and-f4-evidence-ceiling",
    "eip1559-signature-y-parity-is-exactly-zero-or-one",
    "public-secp256k1-scalar-multiplication-rejects-values-above-the-group-order",
    "eip1559-signature-r-and-s-are-positive-below-the-secp256k1-group-order-and-s-is-low",
    "external-signature-evidence-uniquely-recovers-the-exact-f5-authenticated-sender",
    "signed-type-two-transaction-reuses-the-exact-f5-unsigned-fields-and-empty-access-list",
    "signed-transaction-hash-is-legacy-keccak256-of-the-exact-raw-type-two-transaction",
    "signed-private-bundle-matches-the-exact-f5-unsigned-bundle-order-and-identity",
    "relay-endpoint-identifiers-cannot-authorize-conflicting-specifications",
    "relay-endpoint-evidence-contains-no-url-credential-or-production-approval",
    "relay-request-payload-is-canonical-immutable-offline-and-never-dispatched",
    "relay-response-evidence-is-recorded-input-only-and-never-proves-inclusion",
    "relay-acceptance-is-not-inclusion-execution-or-profit-authority",
    "externally-signed-package-recomputes-unsigned-signed-bundle-request-and-response-identities",
    "production-runtime-exposes-no-private-key-signing-or-network-dispatch-function",
    "f6-never-grants-local-signing-submission-execution-or-inclusion-authority",
    "f6-schema-lock-binds-all-external-signature-and-relay-evidence-schemas",
    "relay-response-source-identifiers-and-source-digests-are-independently-unique",
    "evidence-digest-caching-preserves-the-exact-canonical-output-and-identity",
    "recorded-execution-header-hash-and-roots-bind-the-exact-authenticated-block",
    "inclusion-evidence-authenticates-the-executor-runtime-code-hash-and-canonical-empty-storage-at-the-inclusion-block",
    "transaction-and-receipt-inclusion-use-the-exact-same-index-and-authenticated-trie-roots",
    "authenticated-transaction-bytes-equal-the-exact-f6-signed-transaction",
    "nonzero-transaction-index-requires-the-immediately-preceding-authenticated-receipt",
    "transaction-gas-used-is-the-exact-cumulative-receipt-delta",
    "authenticated-gas-used-remains-between-canonical-intrinsic-gas-and-the-f6-gas-limit",
    "effective-gas-price-is-recomputed-from-authenticated-base-fee-and-f6-fee-caps",
    "inclusion-block-lies-inside-the-signed-bundle-range-and-before-the-executor-deadline",
    "successful-outcome-requires-exactly-one-code-hash-bound-executor-settlement-event",
    "settlement-event-plan-beneficiary-token-output-principal-fee-residual-and-direct-payment-reconcile-exactly",
    "actual-gas-rollup-and-direct-payment-costs-cannot-exceed-the-f4-conservative-upper-bounds",
    "ethereum-recorded-rollup-fees-are-exactly-zero",
    "simulation-gas-or-log-drift-is-reported-and-never-rewritten-as-realized-profit",
    "f7-outcome-evidence-never-claims-realized-profit-or-grants-key-submission-or-execution-authority",
    "f7-schema-lock-binds-all-receipt-inclusion-settlement-and-outcome-evidence-schemas",
    "receipt-log-and-topic-count-ceilings-are-enforced-before-canonicalization-or-topic-materialization",
    "canonical-receipt-log-array-digest-enforces-the-global-json-byte-ceiling-before-whole-array-materialization",
    "receipt-logs-bloom-and-canonical-log-digest-are-recomputed-from-the-exact-logs",
    "indexed-trie-proof-values-and-nodes-are-size-bounded-and-source-identified",
    "target-receipt-bloom-is-a-subset-of-the-authenticated-block-header-bloom",
    "consensus-receipt-log-addresses-are-exact-bytes20-and-do-not-inherit-nonzero-deployment-policy",
    "decoded-settlement-event-fields-reconstruct-the-exact-authenticated-log-topics-and-data",
    "executor-post-state-code-continuity-is-model-bound-and-is-not-an-intra-block-execution-trace",
    "f7-schema-references-resolve-by-their-declared-canonical-identifiers",
    "settlement-event-model-cannot-bind-the-canonical-empty-code-hash",
    "settlement-event-model-explicitly-binds-unused-msg-value-refund-to-the-authenticated-sender",
}
F3_SCHEMA_FILES = {
    "authenticated-constant-product-pool-v1.schema.json",
    "atomic-dex-opportunity-v1.schema.json",
    "constant-product-implementation-v1.schema.json",
    "constant-product-model-registry-v1.schema.json",
    "constant-product-pool-spec-v1.schema.json",
    "constant-product-pool-universe-v1.schema.json",
    "constant-product-route-v1.schema.json",
    "opportunity-search-report-v1.schema.json",
    "opportunity-v1.schema.json",
    "route-optimization-v1.schema.json",
}
F4_SCHEMA_FILES = {
    "asset-amount-v1.schema.json",
    "asset-id-v1.schema.json",
    "atomic-execution-plan-v1.schema.json",
    "chain-health-evidence-v1.schema.json",
    "conservative-net-profit-evidence-v1.schema.json",
    "conservative-valuation-rate-v1.schema.json",
    "eip1559-cost-envelope-v1.schema.json",
    "execution-cost-envelope-v1.schema.json",
    "execution-decision-v1.schema.json",
    "funding-plan-v1.schema.json",
    "reserve-cost-component-v1.schema.json",
    "risk-budget-evidence-v1.schema.json",
    "route-simulation-result-v1.schema.json",
    "valuation-book-v1.schema.json",
}
F5_SCHEMA_FILES = {
    "authenticated-executor-deployment-v1.schema.json",
    "execution-constraint-policy-v1.schema.json",
    "executor-deployment-registry-v1.schema.json",
    "executor-deployment-spec-v1.schema.json",
    "executor-interface-v1.schema.json",
    "governed-executor-call-v1.schema.json",
    "private-bundle-intent-v1.schema.json",
    "route-command-v1.schema.json",
    "sender-state-evidence-v1.schema.json",
    "transaction-simulation-result-v1.schema.json",
    "unsigned-eip1559-transaction-v1.schema.json",
    "unsigned-execution-package-v1.schema.json",
}
F6_SCHEMA_FILES = {
    "eip1559-signature-v1.schema.json",
    "externally-signed-execution-package-v1.schema.json",
    "relay-endpoint-registry-v1.schema.json",
    "relay-endpoint-spec-v1.schema.json",
    "relay-response-evidence-v1.schema.json",
    "relay-submission-request-v1.schema.json",
    "signed-eip1559-transaction-v1.schema.json",
    "signed-private-bundle-v1.schema.json",
}
F7_SCHEMA_FILES = {
    "authenticated-execution-block-v1.schema.json",
    "authenticated-transaction-receipt-inclusion-v1.schema.json",
    "evm-block-state-anchor-v1.schema.json",
    "evm-log-entry-v1.schema.json",
    "executor-settlement-event-registry-v1.schema.json",
    "executor-settlement-event-spec-v1.schema.json",
    "executor-settlement-event-v1.schema.json",
    "indexed-trie-proof-v1.schema.json",
    "realized-execution-outcome-v1.schema.json",
    "recorded-execution-block-v1.schema.json",
    "recorded-rollup-fee-v1.schema.json",
    "transaction-receipt-v1.schema.json",
}
REQUIRED_FILES = {
    # Inherited F1/F2 authority.
    "governance/F1_ACCEPTANCE.md",
    "governance/F1_OBSERVATION_LEDGER.md",
    "governance/F1_SOURCE_CONTRACTS.md",
    "governance/F2_ACCEPTANCE.md",
    "governance/F2_AUTHENTICATED_STATE.md",
    "governance/f2-schemas.lock.json",
    "governance/source-contracts.json",
    "scripts/verify_source_contracts.py",
    "scripts/verify_f2_schemas.py",
    "src/aladdin_mev_engine/head_tracker.py",
    "src/aladdin_mev_engine/ledger.py",
    "src/aladdin_mev_engine/ledger_io.py",
    "src/aladdin_mev_engine/observation.py",
    "src/aladdin_mev_engine/source_contracts.py",
    "src/aladdin_mev_engine/state_proof.py",
    # F3 authority.
    "governance/F3_ACCEPTANCE.md",
    "governance/F3_AUTHENTICATED_OPPORTUNITY_GRAPH.md",
    "governance/f3-schemas.lock.json",
    "scripts/verify_f3_schemas.py",
    "src/aladdin_mev_engine/constant_product.py",
    "src/aladdin_mev_engine/opportunity.py",
    "src/aladdin_mev_engine/opportunity_graph.py",
    "src/aladdin_mev_engine/optimizer.py",
    "tests/f3_helpers.py",
    "tests/test_constant_product_f3.py",
    "tests/test_f3_schema_contracts.py",
    "tests/test_opportunity_f3.py",
    "tests/test_opportunity_graph_f3.py",
    "tests/test_optimizer_f3.py",
    "tests/test_repository_policy_f3.py",
    # F4 authority.
    "governance/F4_ACCEPTANCE.md",
    "governance/F4_COST_COMPLETE_PROFIT.md",
    "governance/f4-schemas.lock.json",
    "scripts/verify_f4_schemas.py",
    "src/aladdin_mev_engine/assets.py",
    "src/aladdin_mev_engine/context_evidence.py",
    "src/aladdin_mev_engine/cost_evidence.py",
    "src/aladdin_mev_engine/execution_plan.py",
    "tests/f4_helpers.py",
    "tests/test_assets_f4.py",
    "tests/test_cost_evidence_f4.py",
    "tests/test_execution_plan_f4.py",
    "tests/test_f4_schema_contracts.py",
    "tests/test_governance_f4.py",
    "tests/test_repository_policy_f4.py",
    # F5 authority.
    "governance/F5_SCOPE.md",
    "governance/F5_ACCEPTANCE.md",
    "governance/F5_UNSIGNED_EXECUTION_PACKAGE.md",
    "governance/f5-schemas.lock.json",
    "scripts/verify_f5_schemas.py",
    "src/aladdin_mev_engine/deployments.py",
    "src/aladdin_mev_engine/evm_abi.py",
    "src/aladdin_mev_engine/evm_transaction.py",
    "src/aladdin_mev_engine/execution_package.py",
    "tests/f5_helpers.py",
    "tests/test_deployments_f5.py",
    "tests/test_evm_abi_f5.py",
    "tests/test_evm_transaction_f5.py",
    "tests/test_execution_package_f5.py",
    "tests/test_f5_schema_contracts.py",
    "tests/test_governance_f5.py",
    "tests/test_repository_policy_f5.py",
    # F6 authority.
    "governance/F6_SCOPE.md",
    "governance/F6_ACCEPTANCE.md",
    "governance/F6_SIGNED_RELAY_EVIDENCE.md",
    "governance/f6-schemas.lock.json",
    "scripts/verify_f6_schemas.py",
    "src/aladdin_mev_engine/secp256k1.py",
    "src/aladdin_mev_engine/signed_transaction.py",
    "src/aladdin_mev_engine/relay_evidence.py",
    "tests/f6_helpers.py",
    "tests/test_secp256k1_f6.py",
    "tests/test_signed_transaction_f6.py",
    "tests/test_relay_evidence_f6.py",
    "tests/test_f6_schema_contracts.py",
    "tests/test_governance_f6.py",
    "tests/test_repository_policy_f6.py",
    # F7 authority.
    "governance/F7_SCOPE.md",
    "governance/F7_ACCEPTANCE.md",
    "governance/F7_AUTHENTICATED_EXECUTION_OUTCOME.md",
    "governance/f7-schemas.lock.json",
    "scripts/verify_f7_schemas.py",
    "src/aladdin_mev_engine/evm_receipt.py",
    "src/aladdin_mev_engine/execution_outcome.py",
    "tests/f7_helpers.py",
    "tests/test_evm_receipt_f7.py",
    "tests/test_execution_outcome_f7.py",
    "tests/test_f7_schema_contracts.py",
    "tests/test_governance_f7.py",
    "tests/test_repository_policy_f7.py",
}

ACTION_REF = re.compile(
    r"^\s*-?\s*uses:\s*([^@\s]+)@([0-9a-fA-F]{40})\s*(?:#.*)?$"
)
ANY_USES = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)")
RUN_COMMAND = re.compile(r"^\s*-?\s*run:\s*(.*?)\s*$")
SECRET_PATTERN = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)
WRITE_PERMISSION = re.compile(
    r"^\s+[A-Za-z][A-Za-z0-9_-]*:\s*write\s*$",
    re.MULTILINE,
)
FORBIDDEN_WORKFLOW_COMMAND = re.compile(
    r"\b(?:curl|wget|netcat|socat|ssh|scp|rsync)\b|"
    r"\bgit\s+(?:push|fetch|pull|clone)\b|/dev/tcp|/dev/udp",
    re.IGNORECASE,
)
PRIVATE_MATERIAL = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----|"
    r"\b(?:mnemonic|seed[_ -]?phrase)\s*[:=]",
    re.IGNORECASE,
)
FORBIDDEN_IMPORTS = re.compile(
    r"^\s*(?:from|import)\s+"
    r"(?:requests|httpx|aiohttp|web3|eth_account|websockets|socket|grpc|urllib\.request)\b",
    re.MULTILINE,
)
FORBIDDEN_SOURCE_TERMS = re.compile(
    r"\b(?:eth_sendRawTransaction|send_raw_transaction|sign_transaction|"
    r"broadcast_transaction|deploy_contract|send_bundle|submit_bundle|dispatch_request|http_post|private_key|eth_getTransactionReceipt|get_transaction_receipt|fetch_transaction_receipt|poll_transaction_receipt)\b",
    re.IGNORECASE,
)
FORBIDDEN_DYNAMIC_EXECUTION = re.compile(r"\b(?:eval|exec)\s*\(")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def workflow_policy_errors(text: str) -> list[str]:
    errors: list[str] = []
    if type(text) is not str:
        return ["workflow source must be an exact string"]
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != EXPECTED_WORKFLOW_SHA256:
        errors.append("workflow source does not match the exact governed F7 template")
    if "pull_request_target:" in text:
        errors.append("pull_request_target is forbidden")
    if SECRET_PATTERN.search(text):
        errors.append("workflow secret references are forbidden in F7")
    if len(re.findall(r"^permissions:\s*$", text, flags=re.MULTILINE)) != 1:
        errors.append("workflow must have exactly one top-level permissions block")
    if "permissions:\n  contents: read" not in text:
        errors.append("workflow permissions must be contents: read")
    if "write-all" in text or WRITE_PERMISSION.search(text):
        errors.append("workflow write permissions are forbidden")
    if text.count("persist-credentials: false") != 2:
        errors.append("both governed checkout paths must disable persisted credentials")

    required_contracts = {
        "validate-head:": "missing exact-head validation job",
        "name: F7 exact-head conformance": "missing F7 exact-head job identity",
        "ref: ${{ github.event.pull_request.head.sha || github.sha }}": (
            "exact-head checkout is not bound to the source SHA"
        ),
        "validate-merge:": "missing merge-integration validation job",
        "name: F7 merge integration": "missing F7 merge-integration job identity",
        "if: github.event_name == 'pull_request'": (
            "merge-integration job must be pull-request-only"
        ),
    }
    for contract, message in required_contracts.items():
        if contract not in text:
            errors.append(message)

    action_counts = {action: 0 for action in PINNED_ACTIONS}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = ANY_USES.match(line)
        if match is None:
            continue
        immutable = ACTION_REF.match(line)
        if immutable is None:
            errors.append(
                f"workflow action is not pinned to a full SHA at line {line_number}"
            )
            continue
        action, revision = immutable.groups()
        expected = PINNED_ACTIONS.get(action)
        if expected is None:
            errors.append(
                f"workflow action is not allowlisted at line {line_number}: {action}"
            )
            continue
        if revision.lower() != expected:
            errors.append(f"workflow action pin drift at line {line_number}: {action}")
            continue
        action_counts[action] += 1
    for action, count in action_counts.items():
        if count != 2:
            errors.append(f"workflow must use {action} exactly twice")

    if FORBIDDEN_WORKFLOW_COMMAND.search(text):
        errors.append("workflow contains a forbidden network or publication command")

    run_counts = {command: 0 for command in EXPECTED_RUN_COMMANDS}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = RUN_COMMAND.match(line)
        if match is None:
            continue
        command = match.group(1)
        if command not in run_counts:
            errors.append(
                f"workflow run command is not allowlisted at line {line_number}"
            )
            continue
        run_counts[command] += 1
    for command, expected_count in EXPECTED_RUN_COMMANDS.items():
        actual = run_counts[command]
        if actual != expected_count:
            errors.append(
                "workflow must use governed run command exactly "
                f"{expected_count} time(s): {command}"
            )
    return errors


def _check_workflow(errors: list[str]) -> None:
    path = ROOT / ".github" / "workflows" / "ci.yml"
    if not path.is_file():
        errors.append("missing .github/workflows/ci.yml")
        return
    errors.extend(workflow_policy_errors(path.read_text(encoding="utf-8")))


def _check_project_metadata(errors: list[str]) -> None:
    try:
        with (ROOT / "pyproject.toml").open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        errors.append(f"invalid or missing pyproject.toml: {error}")
        return
    project = document.get("project", {})
    if project.get("dependencies") != []:
        errors.append("F7 runtime dependencies must be exactly empty")
    if project.get("version") != "0.8.0":
        errors.append("F7 project version must be 0.8.0")
    aladdin = document.get("tool", {}).get("aladdin", {})
    expected = {
        "architecture_manifest": "governance/architecture.json",
        "architecture_lock": "governance/architecture.lock.json",
        "source_contracts": "governance/source-contracts.json",
        "f2_schema_lock": "governance/f2-schemas.lock.json",
        "f3_schema_lock": "governance/f3-schemas.lock.json",
        "f4_schema_lock": "governance/f4-schemas.lock.json",
        "f5_schema_lock": "governance/f5-schemas.lock.json",
        "f6_schema_lock": "governance/f6-schemas.lock.json",
        "f7_schema_lock": "governance/f7-schemas.lock.json",
        "observation_authority": "recorded-input-only",
        "state_proof_authority": "offline-recorded-input-only",
        "opportunity_authority": (
            "offline-authenticated-model-bound-gross-shadow-only"
        ),
        "production_model_lock": "none",
        "execution_plan_authority": "offline-structural-plan-only",
        "simulation_authority": (
            "recorded-distinct-implementation-exact-agreement-only"
        ),
        "chain_health_authority": (
            "recorded-source-bound-shadow-context-only"
        ),
        "risk_budget_authority": (
            "recorded-recomputed-snapshot-shadow-only"
        ),
        "cost_evidence_authority": "offline-recorded-upper-bound-shadow-only",
        "deployment_registry_authority": "authenticated-recorded-direct-runtime-shadow-only",
        "calldata_authority": "offline-deterministic-governed-encoding-only",
        "sender_state_authority": "offline-authenticated-eoa-nonce-balance-only",
        "unsigned_transaction_authority": "offline-eip1559-signing-preimage-only",
        "private_bundle_intent_authority": "offline-relay-neutral-intent-only",
        "transaction_simulation_authority": (
            "recorded-distinct-implementation-exact-agreement-only"
        ),
        "execution_package_authority": "offline-unsigned-transaction-bound-shadow-only",
        "submission_authority": "none",
        "execution_authority": "none",
        "network_access": "none",
        "signature_verification_authority": "offline-secp256k1-recovery-only",
        "signed_transaction_authority": "offline-external-signature-evidence-only",
        "signed_bundle_authority": "offline-externally-signed-private-intent-only",
        "relay_endpoint_registry_authority": "explicit-offline-evidence-only-not-production-approval",
        "relay_request_authority": "offline-normalized-request-only",
        "relay_response_authority": "recorded-input-only",
        "externally_signed_package_authority": "offline-external-signature-and-recorded-relay-evidence-only",
        "production_relay_registry_lock": "none",
        "relay_access": "none",
        "credential_authority": "none",
        "key_authority": "none",
        "local_signing_authority": "none",
        "signing_authority": "external-unmodeled",
        "inclusion_authority": "offline-authenticated-transaction-receipt-and-executor-post-state-inclusion-only",
        "settlement_authority": "offline-code-hash-bound-executor-event-reconciliation-only",
        "realized_outcome_authority": "authenticated-inclusion-receipt-code-hash-bound-settlement-and-recorded-rollup-fees-only",
        "realized_profit_authority": "none",
    }
    for key, value in expected.items():
        if aladdin.get(key) != value:
            errors.append(f"tool.aladdin.{key} is not governed")


def source_policy_errors(relative: str, text: str) -> list[str]:
    errors: list[str] = []
    if type(relative) is not str or type(text) is not str:
        return ["source policy inputs must be exact strings"]
    if FORBIDDEN_IMPORTS.search(text):
        errors.append(f"network or signing dependency in {relative}")
    if Path(relative).name != "check_repo_policy.py" and FORBIDDEN_SOURCE_TERMS.search(text):
        errors.append(f"execution capability term in {relative}")
    try:
        tree = ast.parse(text, filename=relative)
    except SyntaxError as error:
        errors.append(f"invalid Python source in {relative}: {error}")
        return errors
    forbidden_functions = {
        "sign", "sign_digest", "sign_hash", "sign_message",
        "sign_transaction", "submit_bundle", "send_bundle",
        "send_raw_transaction", "broadcast_transaction",
        "dispatch_request", "http_post", "get_transaction_receipt",
        "fetch_transaction_receipt", "poll_transaction_receipt",
    }
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in forbidden_functions:
            errors.append(f"forbidden signing or dispatch function in {relative}: {node.name}")
        if isinstance(node, ast.arg) and node.arg == "private_key":
            errors.append(f"private_key parameter is forbidden in production source: {relative}")
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id == "private_key":
            errors.append(f"private_key variable is forbidden in production source: {relative}")
    if FORBIDDEN_DYNAMIC_EXECUTION.search(text):
        errors.append(f"dynamic execution is forbidden in {relative}")
    return errors


def _check_source(errors: list[str]) -> None:
    for base in (ROOT / "src", ROOT / "scripts"):
        if not base.is_dir():
            errors.append(f"missing source directory: {base.relative_to(ROOT)}")
            continue
        for path in sorted(base.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            errors.extend(source_policy_errors(str(path.relative_to(ROOT)), text))


def _check_repository_hygiene(errors: list[str]) -> None:
    ignore_path = ROOT / ".gitignore"
    if not ignore_path.is_file():
        errors.append("missing .gitignore")
        return
    required_ignores = {".env", ".env.*", "*.pem", "*.key"}
    ignores = set(ignore_path.read_text(encoding="utf-8").splitlines())
    missing = required_ignores - ignores
    if missing:
        errors.append("missing credential ignore rules: " + ", ".join(sorted(missing)))

    for path in sorted(ROOT.rglob("*")):
        if any(part in {".git", "__pycache__", ".staging"} for part in path.parts):
            continue
        if path.suffix == ".pyc":
            continue
        if path.is_symlink():
            errors.append(f"repository symlink is forbidden: {path.relative_to(ROOT)}")
            continue
        if not path.is_file():
            continue
        if path.stat().st_size > 1_048_576:
            errors.append(f"repository file exceeds 1 MiB: {path.relative_to(ROOT)}")
        data = path.read_bytes()
        if b"\x00" in data:
            errors.append(f"binary/NUL content is forbidden: {path.relative_to(ROOT)}")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"non-UTF-8 file is forbidden: {path.relative_to(ROOT)}")
            continue
        if PRIVATE_MATERIAL.search(text):
            errors.append(f"possible private material in {path.relative_to(ROOT)}")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line.rstrip(" \t") != line:
                errors.append(
                    f"trailing whitespace in {path.relative_to(ROOT)}:{line_number}"
                )


def _check_required_files(errors: list[str]) -> None:
    for relative in sorted(REQUIRED_FILES):
        if not (ROOT / relative).is_file():
            errors.append(f"missing governed F7 file: {relative}")


def _check_schemas(errors: list[str]) -> None:
    found: set[str] = set()
    for path in sorted((ROOT / "schemas").glob("*.json")):
        found.add(path.name)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            errors.append(f"invalid JSON schema {path.name}: {error}")
            continue
        if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"schema draft is not governed in {path.name}")
        if not document.get("$id"):
            errors.append(f"missing schema id in {path.name}")
        if document.get("additionalProperties") is not False:
            errors.append(
                f"top-level additionalProperties must be false in {path.name}"
            )
    missing = F3_SCHEMA_FILES - found
    if missing:
        errors.append("missing F3 schemas: " + ", ".join(sorted(missing)))
    missing_f4 = F4_SCHEMA_FILES - found
    if missing_f4:
        errors.append("missing F4 schemas: " + ", ".join(sorted(missing_f4)))
    missing_f5 = F5_SCHEMA_FILES - found
    if missing_f5:
        errors.append("missing F5 schemas: " + ", ".join(sorted(missing_f5)))
    missing_f6 = F6_SCHEMA_FILES - found
    if missing_f6:
        errors.append("missing F6 schemas: " + ", ".join(sorted(missing_f6)))
    missing_f7 = F7_SCHEMA_FILES - found
    if missing_f7:
        errors.append("missing F7 schemas: " + ", ".join(sorted(missing_f7)))


def _load_json(relative: str, errors: list[str]) -> dict[str, object] | None:
    try:
        value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"invalid or missing {relative}: {error}")
        return None
    if type(value) is not dict:
        errors.append(f"{relative} must contain an object")
        return None
    return value


def _check_architecture(errors: list[str]) -> None:
    architecture = _load_json("governance/architecture.json", errors)
    lock = _load_json("governance/architecture.lock.json", errors)
    f2_lock = _load_json("governance/f2-schemas.lock.json", errors)
    f3_lock = _load_json("governance/f3-schemas.lock.json", errors)
    f4_lock = _load_json("governance/f4-schemas.lock.json", errors)
    f5_lock = _load_json("governance/f5-schemas.lock.json", errors)
    f6_lock = _load_json("governance/f6-schemas.lock.json", errors)
    f7_lock = _load_json("governance/f7-schemas.lock.json", errors)
    source_contracts = _load_json("governance/source-contracts.json", errors)
    if architecture is None:
        return
    if architecture.get("milestone") != "F7":
        errors.append("architecture milestone must be F7")
    for key, expected in EXPECTED_PARENT.items():
        if architecture.get(key) != expected:
            errors.append(f"architecture {key} does not bind the accepted F6 parent")
    expected_authority = {
        "network_access": "none",
        "relay_access": "none",
        "credential_authority": "none",
        "key_authority": "none",
        "local_signing_authority": "none",
        "signing_authority": "external-unmodeled",
        "execution_authority": "none",
        "inclusion_authority": "offline-authenticated-transaction-receipt-and-executor-post-state-inclusion-only",
        "settlement_authority": "offline-code-hash-bound-executor-event-reconciliation-only",
        "realized_outcome_authority": "authenticated-inclusion-receipt-code-hash-bound-settlement-and-recorded-rollup-fees-only",
        "realized_profit_authority": "none",
        "signature_verification_authority": "offline-secp256k1-recovery-only",
        "signed_transaction_authority": "offline-external-signature-evidence-only",
        "signed_bundle_authority": "offline-externally-signed-private-intent-only",
        "relay_endpoint_registry_authority": "explicit-offline-evidence-only-not-production-approval",
        "relay_request_authority": "offline-normalized-request-only",
        "relay_response_authority": "recorded-input-only",
        "externally_signed_package_authority": "offline-external-signature-and-recorded-relay-evidence-only",
        "production_relay_registry_lock": "none",
        "observation_authority": "recorded-input-only",
        "state_proof_authority": "offline-recorded-input-only",
        "opportunity_authority": (
            "offline-authenticated-model-bound-gross-shadow-only"
        ),
        "production_model_lock": "none",
        "execution_plan_authority": "offline-structural-plan-only",
        "cost_evidence_authority": "offline-recorded-upper-bound-shadow-only",
        "model_registry_authority": (
            "explicit-evidence-model-set-not-production-approval"
        ),
        "execution_plan_authority": "offline-structural-plan-only",
        "simulation_authority": (
            "recorded-distinct-implementation-exact-agreement-only"
        ),
        "chain_health_authority": (
            "recorded-source-bound-shadow-context-only"
        ),
        "risk_budget_authority": (
            "recorded-recomputed-snapshot-shadow-only"
        ),
        "cost_evidence_authority": "offline-recorded-upper-bound-shadow-only",
        "cost_completeness": "complete-recorded-upper-bound-no-inclusion-guarantee",
        "deployment_registry_authority": "authenticated-recorded-direct-runtime-shadow-only",
        "calldata_authority": "offline-deterministic-governed-encoding-only",
        "sender_state_authority": "offline-authenticated-eoa-nonce-balance-only",
        "unsigned_transaction_authority": "offline-eip1559-signing-preimage-only",
        "private_bundle_intent_authority": "offline-relay-neutral-intent-only",
        "transaction_simulation_authority": (
            "recorded-distinct-implementation-exact-agreement-only"
        ),
        "execution_package_authority": "offline-unsigned-transaction-bound-shadow-only",
        "submission_authority": "none",
        "inclusion_guarantee": "none",
    }
    for key, expected in expected_authority.items():
        if architecture.get(key) != expected:
            errors.append(f"architecture {key} is not governed")
    if architecture.get("constant_product_opportunity_scope") != [
        "ethereum",
        "base",
    ]:
        errors.append("architecture constant-product opportunity scope is not governed")
    if architecture.get("historical_outcome_scope") != ["ethereum", "base"]:
        errors.append("architecture historical outcome scope is not governed")
    if architecture.get("runtime_dependencies") != []:
        errors.append("architecture runtime dependencies must be empty")
    if tuple(architecture.get("source_contract_ids", ())) != EXPECTED_SOURCE_IDS:
        errors.append("architecture source-contract identifiers are not governed")
    components = architecture.get("components")
    if type(components) is not list or not REQUIRED_COMPONENTS.issubset(set(components)):
        errors.append("architecture is missing required F7 components")
    invariants = architecture.get("invariants")
    if type(invariants) is not list or not REQUIRED_INVARIANTS.issubset(set(invariants)):
        errors.append("architecture is missing required F7 invariants")
    if f2_lock is not None and architecture.get("f2_schema_lock_sha256") != _canonical_sha256(f2_lock):
        errors.append("architecture F2 schema-lock digest does not match")
    if f3_lock is not None and architecture.get("f3_schema_lock_sha256") != _canonical_sha256(f3_lock):
        errors.append("architecture F3 schema-lock digest does not match")
    if f4_lock is not None and architecture.get("f4_schema_lock_sha256") != _canonical_sha256(f4_lock):
        errors.append("architecture F4 schema-lock digest does not match")
    if f5_lock is not None and architecture.get("f5_schema_lock_sha256") != _canonical_sha256(f5_lock):
        errors.append("architecture F5 schema-lock digest does not match")
    if f6_lock is not None and architecture.get("f6_schema_lock_sha256") != _canonical_sha256(f6_lock):
        errors.append("architecture F6 schema-lock digest does not match")
    if f7_lock is not None and architecture.get("f7_schema_lock_sha256") != _canonical_sha256(f7_lock):
        errors.append("architecture F7 schema-lock digest does not match")
    if source_contracts is not None and architecture.get("source_contract_set_sha256") != source_contracts.get("contracts_sha256"):
        errors.append("architecture source-contract digest does not match")

    digest = _canonical_sha256(architecture)
    if lock is None:
        return
    if set(lock) != {
        "schema",
        "architecture_id",
        "manifest_path",
        "manifest_sha256",
    }:
        errors.append("architecture lock must be a closed object")
    if lock.get("schema") != "aladdin-mev-architecture-lock/v1":
        errors.append("architecture lock schema is not governed")
    if lock.get("manifest_path") != "governance/architecture.json":
        errors.append("architecture lock path is not governed")
    if lock.get("manifest_sha256") != digest:
        errors.append("architecture lock does not bind the canonical manifest")
    if lock.get("architecture_id") != f"AMEV-F7-ARCH-v1-{digest[:12]}":
        errors.append("architecture id does not bind the canonical manifest")


def main() -> int:
    errors: list[str] = []
    _check_workflow(errors)
    _check_project_metadata(errors)
    _check_source(errors)
    _check_repository_hygiene(errors)
    _check_required_files(errors)
    _check_schemas(errors)
    _check_architecture(errors)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("repository policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
