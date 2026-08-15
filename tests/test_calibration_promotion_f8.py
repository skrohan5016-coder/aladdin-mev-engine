from __future__ import annotations

import unittest

from aladdin_mev_engine.historical_scoreboard import (
    CalibrationBucket,
    CalibrationPolicy,
    MAX_AGGREGATE,
    MAX_UINT256,
    HistoricalCalibrationReport,
    HistoricalEconomicScoreboard,
    HistoricalExpectedValueEvidence,
    HistoricalOutcomeCorpus,
    ResearchPromotionDecision,
    ResearchPromotionPolicy,
    ResearchPromotionReason,
    _unsigned_ratio_bps_ceiling_saturated,
)

from f8_helpers import historical_corpus, settled_record, settlement_missing_record


def scoreboard_for(record):
    corpus = historical_corpus((record,))
    return HistoricalEconomicScoreboard(
        corpus,
        record.cohort,
        corpus.created_at_unix_ms + 1,
    )


class CalibrationAndPromotionF8Tests(unittest.TestCase):
    def test_calibration_buckets_partition_all_attempts_and_only_score_scoreable_records(self) -> None:
        scoreboard = scoreboard_for(settled_record())
        policy = CalibrationPolicy("f8-calibration", (10, 50, 100, 500))
        report = HistoricalCalibrationReport(
            scoreboard,
            policy,
            scoreboard.created_at_unix_ms + 1,
        )
        self.assertEqual(sum(item.attempt_count for item in report.buckets), 1)
        self.assertEqual(sum(item.scoreable_count for item in report.buckets), 1)
        self.assertEqual(report.nonempty_bucket_count, 1)
        self.assertFalse(report.to_json_value()["confidence_guarantee"])

        missing_scoreboard = scoreboard_for(settlement_missing_record())
        missing_report = HistoricalCalibrationReport(
            missing_scoreboard,
            policy,
            missing_scoreboard.created_at_unix_ms + 1,
        )
        self.assertEqual(sum(item.attempt_count for item in missing_report.buckets), 1)
        self.assertEqual(sum(item.scoreable_count for item in missing_report.buckets), 0)

    def test_calibration_policy_rejects_duplicates_unsorted_and_excessive_buckets(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive"):
            CalibrationPolicy("bad", (0, 10))
        with self.assertRaisesRegex(ValueError, "strictly increasing"):
            CalibrationPolicy("bad", (10, 10))
        with self.assertRaisesRegex(ValueError, "strictly increasing"):
            CalibrationPolicy("bad", (50, 10))
        with self.assertRaisesRegex(ValueError, "bucket ceiling"):
            CalibrationPolicy("bad", tuple(range(16)))


    def test_large_exact_error_domain_and_saturated_rate_remain_integer_only(self) -> None:
        bucket = CalibrationBucket(
            lower_bound_bps=0,
            upper_bound_bps=None,
            attempt_count=1,
            scoreable_count=1,
            floor_preserved_count=0,
            predicted_sum=0,
            historical_sum=MAX_AGGREGATE,
            prediction_error_sum=MAX_AGGREGATE,
            absolute_prediction_error_sum=MAX_AGGREGATE,
        )
        self.assertEqual(bucket.mean_absolute_prediction_error_ceiling, MAX_AGGREGATE)
        self.assertEqual(
            _unsigned_ratio_bps_ceiling_saturated(MAX_AGGREGATE, 1),
            MAX_UINT256,
        )
        self.assertNotIn(".", bucket.to_json_value()["mean_absolute_prediction_error_ceiling"])

    def test_expected_value_is_conditional_and_never_claims_confidence_or_realized_profit(self) -> None:
        scoreboard = scoreboard_for(settled_record())
        evidence = HistoricalExpectedValueEvidence(
            scoreboard,
            scoreboard.created_at_unix_ms + 1,
        )
        value = evidence.to_json_value()
        self.assertEqual(value["sample_count"], "1")
        self.assertIn("authenticated-successful-settlement", value["conditioning"])
        self.assertFalse(value["confidence_guarantee"])
        self.assertFalse(value["realized_profit_claimed"])

        missing = scoreboard_for(settlement_missing_record())
        unavailable = HistoricalExpectedValueEvidence(
            missing,
            missing.created_at_unix_ms + 1,
        )
        self.assertFalse(unavailable.available)
        self.assertEqual(unavailable.sample_count, 0)
        self.assertFalse(unavailable.to_json_value()["available"])

    def test_research_promotion_passes_only_with_exact_evidence_and_remains_nonproduction(self) -> None:
        scoreboard = scoreboard_for(settled_record())
        calibration = HistoricalCalibrationReport(
            scoreboard,
            CalibrationPolicy("f8-calibration", (10, 100, 1000)),
            scoreboard.created_at_unix_ms + 1,
        )
        ev = HistoricalExpectedValueEvidence(
            scoreboard,
            calibration.created_at_unix_ms + 1,
        )
        policy = ResearchPromotionPolicy(
            policy_id="f8-research-gate",
            minimum_attempts=1,
            minimum_scoreable_records=1,
            minimum_scoreable_rate_bps=10_000,
            minimum_execution_success_rate_bps=10_000,
            minimum_floor_preservation_rate_bps=0,
            minimum_cost_upper_bound_respect_rate_bps=0,
            minimum_positive_surplus_rate_bps=0,
            minimum_unique_inclusion_blocks=1,
            maximum_native_cost_overrun_rate_bps=10_000,
            maximum_mean_absolute_error_bps_of_capital=10_000,
            minimum_guarded_mean_surplus=-10**18,
            minimum_scoreable_records_per_nonempty_bucket=1,
        )
        decision = ResearchPromotionDecision(
            scoreboard,
            calibration,
            ev,
            policy,
            ev.created_at_unix_ms + 1,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reasons, ())
        value = decision.to_json_value()
        self.assertEqual(value["promotion_scope"], "offline-research-candidate-only")
        self.assertFalse(value["confidence_guarantee"])
        self.assertFalse(value["production_promotion_authority"])
        self.assertEqual(value["submission_authority"], "none")
        self.assertEqual(value["execution_authority"], "none")

    def test_promotion_gate_reports_all_confirmed_failures_without_short_circuiting(self) -> None:
        scoreboard = scoreboard_for(settled_record())
        calibration = HistoricalCalibrationReport(
            scoreboard,
            CalibrationPolicy("f8-calibration", (10, 100, 1000)),
            scoreboard.created_at_unix_ms + 1,
        )
        ev = HistoricalExpectedValueEvidence(
            scoreboard,
            calibration.created_at_unix_ms + 1,
        )
        strict = ResearchPromotionPolicy(
            policy_id="f8-strict-research-gate",
            minimum_attempts=2,
            minimum_scoreable_records=2,
            minimum_scoreable_rate_bps=10_000,
            minimum_execution_success_rate_bps=10_000,
            minimum_floor_preservation_rate_bps=10_000,
            minimum_cost_upper_bound_respect_rate_bps=10_000,
            minimum_positive_surplus_rate_bps=10_000,
            minimum_unique_inclusion_blocks=2,
            maximum_native_cost_overrun_rate_bps=0,
            maximum_mean_absolute_error_bps_of_capital=0,
            minimum_guarded_mean_surplus=10**18,
            minimum_scoreable_records_per_nonempty_bucket=2,
        )
        decision = ResearchPromotionDecision(
            scoreboard,
            calibration,
            ev,
            strict,
            ev.created_at_unix_ms + 1,
        )
        self.assertFalse(decision.allowed)
        self.assertIn(ResearchPromotionReason.INSUFFICIENT_ATTEMPTS, decision.reasons)
        self.assertIn(ResearchPromotionReason.INSUFFICIENT_SCOREABLE_RECORDS, decision.reasons)
        self.assertIn(ResearchPromotionReason.INSUFFICIENT_UNIQUE_BLOCKS, decision.reasons)
        self.assertIn(ResearchPromotionReason.CALIBRATION_BUCKET_UNDERSAMPLED, decision.reasons)

    def test_scoreable_coverage_gate_prevents_missing_settlement_selection_bias(self) -> None:
        scoreboard = scoreboard_for(settlement_missing_record())
        self.assertEqual(scoreboard.scoreable_rate_bps, 0)
        self.assertEqual(scoreboard.execution_success_rate_bps, 10_000)
        calibration = HistoricalCalibrationReport(
            scoreboard,
            CalibrationPolicy("f8-calibration", (10, 100, 1000)),
            scoreboard.created_at_unix_ms + 1,
        )
        expected_value = HistoricalExpectedValueEvidence(
            scoreboard,
            calibration.created_at_unix_ms + 1,
        )
        policy = ResearchPromotionPolicy(
            policy_id="f8-missing-settlement-gate",
            minimum_attempts=1,
            minimum_scoreable_records=1,
            minimum_scoreable_rate_bps=1,
            minimum_execution_success_rate_bps=0,
            minimum_floor_preservation_rate_bps=0,
            minimum_cost_upper_bound_respect_rate_bps=0,
            minimum_positive_surplus_rate_bps=0,
            minimum_unique_inclusion_blocks=1,
            maximum_native_cost_overrun_rate_bps=10_000,
            maximum_mean_absolute_error_bps_of_capital=10_000,
            minimum_guarded_mean_surplus=-10**18,
            minimum_scoreable_records_per_nonempty_bucket=1,
        )
        decision = ResearchPromotionDecision(
            scoreboard,
            calibration,
            expected_value,
            policy,
            expected_value.created_at_unix_ms + 1,
        )
        self.assertFalse(decision.allowed)
        self.assertIn(
            ResearchPromotionReason.EXPECTED_VALUE_UNAVAILABLE,
            decision.reasons,
        )
        self.assertIn(
            ResearchPromotionReason.INSUFFICIENT_SCOREABLE_RECORDS,
            decision.reasons,
        )
        self.assertIn(
            ResearchPromotionReason.INSUFFICIENT_SCOREABLE_RATE,
            decision.reasons,
        )

    def test_promotion_policy_requires_positive_evidence_minima(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive"):
            ResearchPromotionPolicy(
                policy_id="bad",
                minimum_attempts=0,
                minimum_scoreable_records=1,
                minimum_scoreable_rate_bps=0,
                minimum_execution_success_rate_bps=0,
                minimum_floor_preservation_rate_bps=0,
                minimum_cost_upper_bound_respect_rate_bps=0,
                minimum_positive_surplus_rate_bps=0,
                minimum_unique_inclusion_blocks=1,
                maximum_native_cost_overrun_rate_bps=10_000,
                maximum_mean_absolute_error_bps_of_capital=10_000,
                minimum_guarded_mean_surplus=0,
                minimum_scoreable_records_per_nonempty_bucket=1,
            )


if __name__ == "__main__":
    unittest.main()
