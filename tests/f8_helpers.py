from __future__ import annotations

from functools import lru_cache

from aladdin_mev_engine.assets import ConservativeValuationRate, ValuationBook
from aladdin_mev_engine.execution_outcome import (
    AuthenticatedTransactionReceiptInclusionEvidence,
    ExecutorSettlementEventRegistry,
    ExecutorSettlementEventSpec,
    RealizedExecutionOutcomeEvidence,
    RecordedRollupFeeEvidence,
)
from aladdin_mev_engine.historical_scoreboard import (
    HistoricalAttemptReference,
    HistoricalCorpusSourceManifest,
    HistoricalExecutionRecord,
    HistoricalOutcomeCorpus,
    HistoricalValuationPolicy,
)

from f7_helpers import (
    ROLLUP_FEE_SOURCE,
    f7_inclusion,
    f7_outcome,
    inclusion_fixture,
    settlement_spec,
)

HISTORICAL_VALUATION_SOURCE = "d0" * 32
HISTORICAL_CORPUS_SOURCE = "e2" * 32


def historical_valuation_policy(
    inclusion: AuthenticatedTransactionReceiptInclusionEvidence,
    *,
    source_sha256: str = HISTORICAL_VALUATION_SOURCE,
) -> HistoricalValuationPolicy:
    net = inclusion.package.unsigned_package.net_profit_evidence
    native = net.cost_envelope.fee_envelope.native_asset
    base = net.plan.base_asset
    return HistoricalValuationPolicy(
        policy_id="f8-historical-native-to-base-ceiling",
        native_asset=native,
        base_asset=base,
        rate_source_sha256=None if native == base else source_sha256,
    )


def historical_valuation_book(
    inclusion: AuthenticatedTransactionReceiptInclusionEvidence,
    *,
    denominator: int = 1_000_000,
    source_sha256: str = HISTORICAL_VALUATION_SOURCE,
) -> ValuationBook:
    net = inclusion.package.unsigned_package.net_profit_evidence
    native = net.cost_envelope.fee_envelope.native_asset
    base = net.plan.base_asset
    block_time_ms = inclusion.block.block.block_timestamp_unix_s * 1000
    return ValuationBook(
        (
            ConservativeValuationRate(
                rate_id=f"f8-historical-native-to-base-{denominator}",
                asset_in=native,
                asset_out=base,
                numerator=1,
                denominator=denominator,
                observed_at_unix_ms=block_time_ms,
                valid_until_unix_ms=block_time_ms + 60_000,
                source_sha256=source_sha256,
            ),
        )
    )


def inclusion_from_fixture(*, receipt_status: int, settlement_logs=()):
    fixture = inclusion_fixture(
        receipt_status=receipt_status,
        settlement_logs=settlement_logs,
    )
    return AuthenticatedTransactionReceiptInclusionEvidence(
        package=fixture.package,
        block=fixture.authenticated_block,
        executor_state=fixture.executor_state,
        transaction_proof=fixture.transaction_proof,
        receipt_proof=fixture.receipt_proof,
        previous_receipt_proof=fixture.previous_receipt_proof,
        created_at_unix_ms=fixture.receipt_proof.observed_at_unix_ms + 1,
    )


def settlement_authority_for(
    inclusion: AuthenticatedTransactionReceiptInclusionEvidence,
) -> tuple[ExecutorSettlementEventRegistry, ExecutorSettlementEventSpec]:
    spec = settlement_spec(inclusion.package)
    registry = ExecutorSettlementEventRegistry(
        registry_id="f7-synthetic-settlement-registry",
        specs=(spec,),
    )
    return registry, spec


def rollup_fee_for(
    inclusion: AuthenticatedTransactionReceiptInclusionEvidence,
    *,
    l1_data_fee_paid: int = 0,
    operator_fee_paid: int = 0,
) -> RecordedRollupFeeEvidence:
    return RecordedRollupFeeEvidence(
        chain=inclusion.block.chain,
        transaction_hash=inclusion.package.signed_transaction.transaction_hash,
        l1_data_fee_paid=l1_data_fee_paid,
        operator_fee_paid=operator_fee_paid,
        observed_at_unix_ms=inclusion.created_at_unix_ms + 1,
        source_id="f7-recorded-rollup-fees",
        source_sha256=ROLLUP_FEE_SOURCE,
    )


@lru_cache(maxsize=1)
def settled_record() -> HistoricalExecutionRecord:
    outcome = f7_outcome()
    return HistoricalExecutionRecord(
        package=outcome.package,
        inclusion=outcome.inclusion,
        settlement_registry=outcome.settlement_registry,
        settlement_spec=outcome.settlement_spec,
        rollup_fee=outcome.rollup_fee,
        outcome=outcome,
        historical_valuation_policy=historical_valuation_policy(outcome.inclusion),
        historical_valuation_book=historical_valuation_book(outcome.inclusion),
        recorded_at_unix_ms=outcome.created_at_unix_ms + 1,
    )


def settled_record_with_valuation_overrun() -> HistoricalExecutionRecord:
    outcome = f7_outcome()
    return HistoricalExecutionRecord(
        package=outcome.package,
        inclusion=outcome.inclusion,
        settlement_registry=outcome.settlement_registry,
        settlement_spec=outcome.settlement_spec,
        rollup_fee=outcome.rollup_fee,
        outcome=outcome,
        historical_valuation_policy=historical_valuation_policy(outcome.inclusion),
        historical_valuation_book=historical_valuation_book(
            outcome.inclusion, denominator=1
        ),
        recorded_at_unix_ms=outcome.created_at_unix_ms + 1,
    )


def reverted_record() -> HistoricalExecutionRecord:
    inclusion = inclusion_from_fixture(receipt_status=0, settlement_logs=())
    registry, spec = settlement_authority_for(inclusion)
    rollup = rollup_fee_for(inclusion)
    return HistoricalExecutionRecord(
        package=inclusion.package,
        inclusion=inclusion,
        settlement_registry=registry,
        settlement_spec=spec,
        rollup_fee=rollup,
        outcome=None,
        historical_valuation_policy=historical_valuation_policy(inclusion),
        historical_valuation_book=ValuationBook(()),
        recorded_at_unix_ms=rollup.observed_at_unix_ms + 1,
    )


def settlement_missing_record() -> HistoricalExecutionRecord:
    inclusion = inclusion_from_fixture(receipt_status=1, settlement_logs=())
    registry, spec = settlement_authority_for(inclusion)
    rollup = rollup_fee_for(inclusion)
    return HistoricalExecutionRecord(
        package=inclusion.package,
        inclusion=inclusion,
        settlement_registry=registry,
        settlement_spec=spec,
        rollup_fee=rollup,
        outcome=None,
        historical_valuation_policy=historical_valuation_policy(inclusion),
        historical_valuation_book=ValuationBook(()),
        recorded_at_unix_ms=rollup.observed_at_unix_ms + 1,
    )


def settlement_evidence_incomplete_record() -> HistoricalExecutionRecord:
    inclusion = f7_inclusion()
    registry, spec = settlement_authority_for(inclusion)
    rollup = rollup_fee_for(inclusion)
    return HistoricalExecutionRecord(
        package=inclusion.package,
        inclusion=inclusion,
        settlement_registry=registry,
        settlement_spec=spec,
        rollup_fee=rollup,
        outcome=None,
        historical_valuation_policy=historical_valuation_policy(inclusion),
        historical_valuation_book=ValuationBook(()),
        recorded_at_unix_ms=rollup.observed_at_unix_ms + 1,
    )


def historical_source_manifest(
    records: tuple[HistoricalExecutionRecord, ...],
    *,
    source_sha256: str = HISTORICAL_CORPUS_SOURCE,
    manifest_id: str = "f8-synthetic-source-window",
) -> HistoricalCorpusSourceManifest:
    if type(records) is not tuple or not records:
        raise TypeError("records must be a non-empty exact tuple")
    references = tuple(HistoricalAttemptReference.from_record(item) for item in records)
    return HistoricalCorpusSourceManifest(
        manifest_id=manifest_id,
        source_id="f8-authenticated-inclusion-export",
        source_sha256=source_sha256,
        chain=records[0].cohort.chain,
        start_block_number=min(item.inclusion.block.block_number for item in records),
        end_block_number=max(item.inclusion.block.block_number for item in records),
        references=references,
        created_at_unix_ms=max(item.recorded_at_unix_ms for item in records) + 1,
    )


def historical_corpus(
    records: tuple[HistoricalExecutionRecord, ...],
    *,
    source_sha256: str = HISTORICAL_CORPUS_SOURCE,
    manifest_id: str = "f8-synthetic-source-window",
) -> HistoricalOutcomeCorpus:
    manifest = historical_source_manifest(
        records,
        source_sha256=source_sha256,
        manifest_id=manifest_id,
    )
    return HistoricalOutcomeCorpus(
        source_manifest=manifest,
        records=records,
        created_at_unix_ms=manifest.created_at_unix_ms + 1,
    )
