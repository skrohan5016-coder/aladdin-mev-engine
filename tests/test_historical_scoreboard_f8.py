from __future__ import annotations

from dataclasses import replace
import unittest

from aladdin_mev_engine.assets import ValuationBook
from aladdin_mev_engine.domain import Strategy
from aladdin_mev_engine.source_contracts import Finality
from aladdin_mev_engine.historical_scoreboard import (
    HistoricalAttemptReference,
    HistoricalDisposition,
    HistoricalEconomicScoreboard,
    HistoricalExecutionRecord,
    HistoricalOutcomeCorpus,
)

from f8_helpers import (
    historical_corpus,
    historical_source_manifest,
    historical_valuation_policy,
    historical_valuation_book,
    inclusion_from_fixture,
    reverted_record,
    rollup_fee_for,
    settled_record,
    settled_record_with_valuation_overrun,
    settlement_authority_for,
    settlement_evidence_incomplete_record,
    settlement_missing_record,
)
from f7_helpers import settlement_log


class HistoricalScoreboardF8Tests(unittest.TestCase):
    def test_settled_record_recomputes_inclusion_conditioned_economics(self) -> None:
        record = settled_record()
        self.assertEqual(record.disposition, HistoricalDisposition.SETTLED)
        self.assertTrue(record.execution_success)
        self.assertTrue(record.settlement_observed)
        self.assertTrue(record.economics_scoreable)
        self.assertIsNotNone(record.actual_external_cost_base_upper_bound)
        self.assertEqual(
            record.prediction_error,
            record.historical_conservative_surplus
            - record.predicted_conservative_net_profit,
        )
        value = record.to_json_value()
        self.assertFalse(value["realized_profit_claimed"])
        self.assertFalse(value["production_promotion_authority"])
        self.assertEqual(value["submission_authority"], "none")
        self.assertEqual(value["execution_authority"], "none")

    def test_reverted_missing_and_incomplete_records_remain_retained_but_unscoreable(self) -> None:
        reverted = reverted_record()
        missing = settlement_missing_record()
        incomplete = settlement_evidence_incomplete_record()
        self.assertEqual(reverted.disposition, HistoricalDisposition.REVERTED)
        self.assertFalse(reverted.execution_success)
        self.assertFalse(reverted.economics_scoreable)
        self.assertEqual(missing.disposition, HistoricalDisposition.SETTLEMENT_MISSING)
        self.assertTrue(missing.execution_success)
        self.assertFalse(missing.settlement_observed)
        self.assertFalse(missing.economics_scoreable)
        self.assertEqual(
            incomplete.disposition,
            HistoricalDisposition.SETTLEMENT_EVIDENCE_INCOMPLETE,
        )
        self.assertTrue(incomplete.execution_success)
        self.assertTrue(incomplete.settlement_observed)
        self.assertFalse(incomplete.outcome_evidence_complete)
        self.assertFalse(incomplete.economics_scoreable)
        for record in (reverted, missing, incomplete):
            self.assertIsNone(record.historical_conservative_surplus)
            self.assertIsNone(record.prediction_error)
            self.assertEqual(record.historical_valuation_book, ValuationBook(()))

    def test_cohort_constructor_closes_strategy_and_finality_to_runtime_schema(self) -> None:
        cohort = settled_record().cohort
        with self.assertRaisesRegex(ValueError, "atomic DEX"):
            replace(cohort, strategy=Strategy.LIQUIDATION)
        with self.assertRaisesRegex(ValueError, "confirmed or finalized"):
            replace(cohort, inclusion_finality=Finality.PENDING)

    def test_unscoreable_record_rejects_unused_valuation_authority(self) -> None:
        reverted = reverted_record()
        with self.assertRaisesRegex(ValueError, "unused valuation"):
            HistoricalExecutionRecord(
                package=reverted.package,
                inclusion=reverted.inclusion,
                settlement_registry=reverted.settlement_registry,
                settlement_spec=reverted.settlement_spec,
                rollup_fee=reverted.rollup_fee,
                outcome=None,
                historical_valuation_policy=reverted.historical_valuation_policy,
                historical_valuation_book=historical_valuation_book(reverted.inclusion),
                recorded_at_unix_ms=reverted.recorded_at_unix_ms,
            )

    def test_record_rejects_package_outcome_and_time_drift(self) -> None:
        record = settled_record()
        with self.assertRaisesRegex(ValueError, "predates"):
            replace(record, recorded_at_unix_ms=record.inclusion.created_at_unix_ms - 1)
        with self.assertRaisesRegex(ValueError, "valuation"):
            replace(record, historical_valuation_book=ValuationBook(()))

    def test_corpus_is_deterministic_and_rejects_duplicate_transaction_or_position(self) -> None:
        record = settled_record()
        corpus = historical_corpus((record,))
        self.assertEqual(corpus.records, (record,))
        self.assertEqual(corpus.to_json_value()["record_count"], "1")
        with self.assertRaisesRegex(ValueError, "duplicate record"):
            HistoricalOutcomeCorpus(
                source_manifest=historical_source_manifest((record,)),
                records=(record, record),
                created_at_unix_ms=record.recorded_at_unix_ms + 2,
            )


    def test_source_manifest_bounds_selection_to_an_exact_declared_window(self) -> None:
        record = settled_record()
        manifest = historical_source_manifest((record,))
        reference = HistoricalAttemptReference.from_record(record)
        self.assertEqual(manifest.references, (reference,))
        value = manifest.to_json_value()
        self.assertEqual(
            value["completeness_scope"],
            "exact-declared-source-window-reference-set-only",
        )
        self.assertFalse(value["global_completeness_guarantee"])
        corpus = historical_corpus((record,))
        self.assertEqual(corpus.source_manifest.digest, manifest.digest)
        self.assertFalse(corpus.to_json_value()["global_completeness_guarantee"])

    def test_corpus_rejects_missing_extra_or_drifted_source_references(self) -> None:
        record = settled_record()
        manifest = historical_source_manifest((record,))
        drifted_reference = replace(
            manifest.references[0],
            package_sha256="f1" * 32,
        )
        drifted_manifest = replace(manifest, references=(drifted_reference,))
        with self.assertRaisesRegex(ValueError, "exact source-manifest"):
            HistoricalOutcomeCorpus(
                source_manifest=drifted_manifest,
                records=(record,),
                created_at_unix_ms=drifted_manifest.created_at_unix_ms + 1,
            )
        with self.assertRaisesRegex(ValueError, "duplicate attempt reference"):
            replace(
                manifest,
                references=(manifest.references[0], manifest.references[0]),
            )

    def test_source_manifest_identity_binds_the_record_export_source(self) -> None:
        record = settled_record()
        first = historical_corpus((record,), source_sha256="e2" * 32)
        second = historical_corpus((record,), source_sha256="e3" * 32)
        self.assertNotEqual(first.source_manifest.digest, second.source_manifest.digest)
        self.assertNotEqual(first.digest, second.digest)

    def test_scoreable_and_unscoreable_attempts_share_one_exact_cohort_policy(self) -> None:
        records = (
            settled_record(),
            reverted_record(),
            settlement_missing_record(),
            settlement_evidence_incomplete_record(),
        )
        self.assertEqual(len({item.cohort.digest for item in records}), 1)

    def test_historical_valuation_policy_source_drift_changes_cohort_identity(self) -> None:
        record = settled_record()
        alternate_source = "e1" * 32
        alternate_policy = historical_valuation_policy(
            record.inclusion,
            source_sha256=alternate_source,
        )
        with self.assertRaisesRegex(ValueError, "rate source"):
            HistoricalExecutionRecord(
                package=record.package,
                inclusion=record.inclusion,
                settlement_registry=record.settlement_registry,
                settlement_spec=record.settlement_spec,
                rollup_fee=record.rollup_fee,
                outcome=record.outcome,
                historical_valuation_policy=alternate_policy,
                historical_valuation_book=record.historical_valuation_book,
                recorded_at_unix_ms=record.recorded_at_unix_ms,
            )
        alternate = HistoricalExecutionRecord(
            package=record.package,
            inclusion=record.inclusion,
            settlement_registry=record.settlement_registry,
            settlement_spec=record.settlement_spec,
            rollup_fee=record.rollup_fee,
            outcome=record.outcome,
            historical_valuation_policy=alternate_policy,
            historical_valuation_book=historical_valuation_book(
                record.inclusion,
                source_sha256=alternate_source,
            ),
            recorded_at_unix_ms=record.recorded_at_unix_ms,
        )
        self.assertNotEqual(record.cohort.digest, alternate.cohort.digest)

    def test_scoreboard_includes_all_cohort_records_and_uses_exact_integer_metrics(self) -> None:
        record = settled_record()
        corpus = historical_corpus((record,))
        scoreboard = HistoricalEconomicScoreboard(
            corpus,
            record.cohort,
            corpus.created_at_unix_ms + 1,
        )
        self.assertEqual(scoreboard.attempt_count, 1)
        self.assertEqual(scoreboard.scoreable_count, 1)
        self.assertEqual(scoreboard.settled_count, 1)
        self.assertEqual(scoreboard.outcome_evidence_complete_count, 1)
        self.assertEqual(scoreboard.scoreable_rate_bps, 10_000)
        self.assertEqual(scoreboard.execution_success_rate_bps, 10_000)
        self.assertEqual(scoreboard.unique_inclusion_block_count, 1)
        self.assertEqual(scoreboard.unique_scoreable_inclusion_block_count, 1)
        self.assertEqual(
            scoreboard.historical_conservative_surplus_sum,
            record.historical_conservative_surplus,
        )
        self.assertEqual(
            scoreboard.prediction_error_sum,
            record.prediction_error,
        )
        self.assertEqual(
            scoreboard.guarded_mean_historical_surplus_floor,
            record.historical_conservative_surplus
            - abs(record.prediction_error),
        )
        self.assertFalse(scoreboard.to_json_value()["confidence_guarantee"])

    def test_unscoreable_records_are_not_silently_mixed_into_economic_averages(self) -> None:
        record = settlement_missing_record()
        corpus = historical_corpus((record,))
        scoreboard = HistoricalEconomicScoreboard(
            corpus,
            record.cohort,
            corpus.created_at_unix_ms + 1,
        )
        self.assertEqual(scoreboard.attempt_count, 1)
        self.assertEqual(scoreboard.scoreable_count, 0)
        self.assertEqual(scoreboard.unscoreable_count, 1)
        self.assertEqual(scoreboard.scoreable_rate_bps, 0)
        self.assertEqual(scoreboard.historical_conservative_surplus_sum, 0)

    def test_present_settlement_event_cannot_be_downgraded_to_settlement_missing(self) -> None:
        record = settlement_evidence_incomplete_record()
        self.assertEqual(
            record.disposition,
            HistoricalDisposition.SETTLEMENT_EVIDENCE_INCOMPLETE,
        )
        self.assertTrue(record.settlement_observed)
        value = record.to_json_value()
        self.assertTrue(value["settlement_observed"])
        self.assertFalse(value["outcome_evidence_complete"])

    def test_malformed_executor_settlement_signal_cannot_hide_as_missing(self) -> None:
        package = settled_record().package
        valid_log = settlement_log(package)
        malformed_log = replace(valid_log, topics=valid_log.topics[:3])
        inclusion = inclusion_from_fixture(
            receipt_status=1,
            settlement_logs=(malformed_log,),
        )
        registry, spec = settlement_authority_for(inclusion)
        rollup = rollup_fee_for(inclusion)
        with self.assertRaisesRegex(ValueError, "topic contract"):
            HistoricalExecutionRecord(
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

    def test_historical_valuation_overrun_is_recorded_instead_of_filtering_the_outcome(self) -> None:
        record = settled_record_with_valuation_overrun()
        self.assertTrue(record.economics_scoreable)
        self.assertFalse(record.cost_upper_bounds_respected)
        self.assertFalse(record.conservative_floor_preserved)
        corpus = historical_corpus((record,))
        scoreboard = HistoricalEconomicScoreboard(
            corpus,
            record.cohort,
            corpus.created_at_unix_ms + 1,
        )
        self.assertEqual(scoreboard.cost_upper_bounds_respected_count, 0)
        self.assertEqual(scoreboard.cost_upper_bound_respect_rate_bps, 0)


if __name__ == "__main__":
    unittest.main()
