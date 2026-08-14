from __future__ import annotations

from dataclasses import replace
import unittest

from aladdin_mev_engine.assets import AssetId
from aladdin_mev_engine.execution_plan import AtomicExecutionPlan, FundingKind, FundingPlan

from f4_helpers import SOURCE_A, execution_plan, profitable_opportunity


class ExecutionPlanF4Tests(unittest.TestCase):
    def test_plan_recomputes_exact_route_flow_and_never_authorizes_execution(self) -> None:
        plan = execution_plan()
        self.assertEqual(plan.steps[0].amount_in, plan.funding.principal)
        self.assertEqual(
            plan.steps[-1].amount_out,
            plan.opportunity.route_quote.amount_out,
        )
        for left, right in zip(plan.steps, plan.steps[1:]):
            self.assertEqual(left.token_out, right.token_in)
            self.assertEqual(left.amount_out, right.amount_in)
        value = plan.to_json_value()
        self.assertFalse(value["execution_eligible"])
        self.assertEqual(value["calldata_authority"], "none")
        self.assertEqual(value["signing_authority"], "none")

    def test_funding_asset_principal_and_validity_are_exact(self) -> None:
        opportunity = profitable_opportunity()
        base = AssetId.erc20(opportunity.universe.chain, opportunity.route.base_token)
        funding = FundingPlan(
            FundingKind.FLASH_LOAN,
            base,
            opportunity.capital_at_risk + 1,
            1,
            "lender",
            opportunity.created_at_unix_ms,
            opportunity.created_at_unix_ms + 100,
            SOURCE_A,
        )
        with self.assertRaisesRegex(ValueError, "principal"):
            AtomicExecutionPlan(
                opportunity,
                funding,
                opportunity.created_at_unix_ms + 1,
            )
        wrong_asset = AssetId.erc20(opportunity.universe.chain, bytes.fromhex("99" * 20))
        with self.assertRaisesRegex(ValueError, "funding asset"):
            AtomicExecutionPlan(
                opportunity,
                replace(funding, asset=wrong_asset, principal=opportunity.capital_at_risk),
                opportunity.created_at_unix_ms + 1,
            )
        with self.assertRaisesRegex(ValueError, "not valid"):
            AtomicExecutionPlan(
                opportunity,
                replace(
                    funding,
                    principal=opportunity.capital_at_risk,
                    valid_until_unix_ms=opportunity.created_at_unix_ms,
                ),
                opportunity.created_at_unix_ms + 1,
            )

    def test_own_inventory_has_zero_fee_and_external_flash_fee_is_explicit(self) -> None:
        own = execution_plan(kind=FundingKind.OWN_INVENTORY)
        flash = execution_plan(flash_fee=77)
        self.assertEqual(own.funding.fee, 0)
        self.assertEqual(flash.funding.fee, 77)
        self.assertEqual(
            flash.residual_before_external_costs,
            flash.gross_profit - 77,
        )
        with self.assertRaisesRegex(ValueError, "cannot claim"):
            replace(own.funding, fee=1)
        with self.assertRaisesRegex(ValueError, "external provider"):
            replace(flash.funding, provider_id="self")


if __name__ == "__main__":
    unittest.main()
