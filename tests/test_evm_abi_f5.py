from __future__ import annotations

from dataclasses import replace
import hashlib
import random
import unittest

from aladdin_mev_engine.deployments import AuthenticatedExecutorDeployment, ExecutorDeploymentRegistry
from aladdin_mev_engine.evm_abi import (
    MAX_UINT64,
    ROUTE_PAYLOAD_HEADER,
    ROUTE_PAYLOAD_VERSION,
    ExecutionConstraintPolicy,
    GovernedExecutorCall,
    RouteCommand,
    encode_governed_execute_call,
)

from f5_helpers import f5_call, f5_deployment, f5_net_evidence


class EvmAbiF5Tests(unittest.TestCase):
    def test_call_is_deterministic_and_abi_layout_is_canonical(self) -> None:
        call = f5_call()
        self.assertTrue(call.route_payload.startswith(ROUTE_PAYLOAD_HEADER + b"\x01\x02"))
        self.assertEqual(call.calldata[:4].hex(), "2a4b1c55")
        words = [call.calldata[4 + index * 32 : 4 + (index + 1) * 32] for index in range(6)]
        self.assertEqual(words[0], bytes.fromhex(call.net_profit_evidence.plan.digest))
        self.assertEqual(words[1], bytes(12) + call.net_profit_evidence.plan.base_asset.address)
        self.assertEqual(int.from_bytes(words[2], "big"), call.net_profit_evidence.plan.opportunity.capital_at_risk)
        self.assertEqual(int.from_bytes(words[3], "big"), call.minimum_final_output)
        self.assertEqual(int.from_bytes(words[4], "big"), call.deadline_unix_s)
        self.assertEqual(int.from_bytes(words[5], "big"), 192)
        dynamic_start = 4 + 192
        dynamic_length = int.from_bytes(call.calldata[dynamic_start : dynamic_start + 32], "big")
        self.assertEqual(dynamic_length, len(call.route_payload))
        self.assertEqual(
            call.calldata[dynamic_start + 32 : dynamic_start + 32 + dynamic_length],
            call.route_payload,
        )
        self.assertEqual(
            set(call.calldata[dynamic_start + 32 + dynamic_length :]),
            {0},
        )
        rebuilt = encode_governed_execute_call(
            selector=call.deployment.spec.interface.function_selector,
            plan_sha256=bytes.fromhex(call.net_profit_evidence.plan.digest),
            base_token=call.net_profit_evidence.plan.base_asset.address,
            principal=call.net_profit_evidence.plan.opportunity.capital_at_risk,
            minimum_final_output=call.minimum_final_output,
            deadline_unix_s=call.deadline_unix_s,
            route_payload=call.route_payload,
        )
        self.assertEqual(rebuilt, call.calldata)

    def test_route_commands_are_derived_from_exact_f4_steps(self) -> None:
        call = f5_call()
        steps = call.net_profit_evidence.plan.steps
        self.assertEqual(len(call.commands), len(steps))
        for command, step in zip(call.commands, steps):
            self.assertEqual(len(command.binary), 189)
            self.assertEqual(command.binary[0], command.index)
            self.assertEqual(command.binary[1:21], command.pool_address)
            self.assertEqual(command.binary[21:41], command.token_in)
            self.assertEqual(command.binary[41:61], command.token_out)
            self.assertEqual(int.from_bytes(command.binary[61:93], "big"), command.amount_in)
            self.assertEqual(int.from_bytes(command.binary[93:125], "big"), command.expected_amount_out)
            self.assertEqual(int.from_bytes(command.binary[125:157], "big"), command.minimum_amount_out)
            self.assertEqual(command.binary[157:189], bytes.fromhex(command.quote_sha256))
            self.assertEqual(command.pool_address, step.pool_address)
            self.assertEqual(command.amount_in, step.amount_in)
            self.assertEqual(command.expected_amount_out, step.amount_out)
            expected_slippage_floor = (
                step.amount_out * (10_000 - call.constraints.maximum_slippage_bps)
                + 9_999
            ) // 10_000
            self.assertGreaterEqual(command.minimum_amount_out, expected_slippage_floor)
            self.assertLessEqual(command.minimum_amount_out, command.expected_amount_out)
        self.assertEqual(call.commands[-1].minimum_amount_out, call.minimum_final_output)

    def test_economic_floor_is_not_weakened_by_slippage_policy(self) -> None:
        evidence = f5_net_evidence()
        weak = GovernedExecutorCall(
            net_profit_evidence=evidence,
            deployment=f5_deployment(),
            constraints=ExecutionConstraintPolicy("weak-slippage", 10_000, 30_000),
            created_at_unix_ms=max(
                evidence.created_at_unix_ms + 1,
                f5_deployment().evidence.proof_observed_at_unix_ms,
            ),
        )
        economic = (
            evidence.plan.opportunity.capital_at_risk
            + evidence.cost_envelope.costs.total_cost
            + evidence.profit_policy.minimum_absolute_profit
        )
        self.assertGreaterEqual(weak.minimum_final_output, economic)

    def test_exact_millisecond_validity_does_not_expand_to_the_deadline_second(self) -> None:
        evidence = f5_net_evidence()
        deployment = f5_deployment()
        created = max(
            evidence.created_at_unix_ms + 1,
            deployment.evidence.proof_observed_at_unix_ms,
        )
        call = GovernedExecutorCall(
            net_profit_evidence=evidence,
            deployment=deployment,
            constraints=ExecutionConstraintPolicy(
                "exact-ms-deadline",
                50,
                1_501,
            ),
            created_at_unix_ms=created,
        )
        self.assertEqual(
            call.inputs_valid_until_unix_ms,
            min(evidence.inputs_valid_until_unix_ms, created + 1_501),
        )
        self.assertLessEqual(
            call.deadline_unix_s * 1000,
            call.inputs_valid_until_unix_ms,
        )
        self.assertLess(
            call.inputs_valid_until_unix_ms,
            (call.deadline_unix_s + 1) * 1000,
        )

    def test_unapproved_expired_or_wrong_anchor_evidence_fails_closed(self) -> None:
        evidence = f5_net_evidence()
        rejected = replace(evidence, profit_policy=replace(evidence.profit_policy, minimum_absolute_profit=10**30))
        with self.assertRaisesRegex(ValueError, "approved"):
            GovernedExecutorCall(
                rejected,
                f5_deployment(),
                ExecutionConstraintPolicy("rejected", 50, 30_000),
                rejected.created_at_unix_ms + 1,
            )
        with self.assertRaisesRegex(ValueError, "expired"):
            GovernedExecutorCall(
                evidence,
                f5_deployment(),
                ExecutionConstraintPolicy("expired", 50, 30_000),
                evidence.inputs_valid_until_unix_ms + 1,
            )
        wrong = replace(
            f5_deployment(),
            evidence=replace(
                f5_deployment().evidence,
                anchor=replace(
                    f5_deployment().evidence.anchor,
                    state_observation=replace(
                        f5_deployment().evidence.anchor.state_observation,
                        source_sequence=f5_deployment().evidence.anchor.state_source_sequence + 1,
                    ),
                ),
            ),
        )
        with self.assertRaises(Exception):
            GovernedExecutorCall(
                evidence,
                wrong,
                ExecutionConstraintPolicy("wrong-anchor", 50, 30_000),
                evidence.created_at_unix_ms + 1,
            )


    def test_executor_interface_must_bind_the_exact_f4_flash_funding_authority(self) -> None:
        evidence = f5_net_evidence()
        deployment = f5_deployment()
        wrong_interface = replace(
            deployment.spec.interface,
            flash_loan_provider_id="different-recorded-lender",
        )
        wrong_spec = replace(
            deployment.spec,
            deployment_id="wrong-funding-interface",
            interface=wrong_interface,
        )
        wrong_registry = ExecutorDeploymentRegistry(
            "wrong-funding-registry",
            (wrong_spec,),
        )
        wrong_deployment = AuthenticatedExecutorDeployment(
            wrong_spec,
            deployment.evidence,
            wrong_registry,
        )
        with self.assertRaisesRegex(ValueError, "funding authority"):
            GovernedExecutorCall(
                evidence,
                wrong_deployment,
                ExecutionConstraintPolicy("wrong-funding", 50, 30_000),
                max(evidence.created_at_unix_ms + 1, deployment.evidence.proof_observed_at_unix_ms),
            )


    def test_public_abi_encoder_rejects_ungoverned_inputs_and_route_frames(self) -> None:
        call = f5_call()
        common = {
            "selector": call.deployment.spec.interface.function_selector,
            "plan_sha256": bytes.fromhex(call.net_profit_evidence.plan.digest),
            "base_token": call.net_profit_evidence.plan.base_asset.address,
            "principal": call.net_profit_evidence.plan.opportunity.capital_at_risk,
            "minimum_final_output": call.minimum_final_output,
            "deadline_unix_s": call.deadline_unix_s,
            "route_payload": call.route_payload,
        }
        cases = (
            ({"selector": bytes(4)}, "selector"),
            ({"plan_sha256": bytes(32)}, "plan_sha256"),
            ({"principal": 0}, "principal"),
            ({"minimum_final_output": common["principal"] - 1}, "smaller than principal"),
            ({"deadline_unix_s": MAX_UINT64 + 1}, "64-bit"),
            ({"deadline_unix_s": 0}, "positive"),
            ({"route_payload": b""}, "shorter"),
            ({"route_payload": b"BADHDR!!" + call.route_payload[8:]}, "header"),
            (
                {
                    "route_payload": (
                        ROUTE_PAYLOAD_HEADER
                        + bytes((ROUTE_PAYLOAD_VERSION + 1, call.route_payload[9]))
                        + call.route_payload[10:]
                    )
                },
                "version",
            ),
            (
                {
                    "route_payload": (
                        ROUTE_PAYLOAD_HEADER
                        + bytes((ROUTE_PAYLOAD_VERSION, 1))
                        + call.route_payload[10:]
                    )
                },
                "command count",
            ),
            ({"route_payload": call.route_payload[:-1]}, "length"),
            (
                {
                    "route_payload": call.route_payload[:10]
                    + b"\x01"
                    + call.route_payload[11:]
                },
                "indexes",
            ),
            (
                {
                    "route_payload": call.route_payload[:11]
                    + bytes(20)
                    + call.route_payload[31:]
                },
                "pool_address",
            ),
            (
                {
                    "route_payload": call.route_payload[:31]
                    + call.route_payload[31:51]
                    + call.route_payload[31:51]
                    + call.route_payload[71:]
                },
                "tokens",
            ),
            (
                {
                    "route_payload": call.route_payload[:71]
                    + bytes(32)
                    + call.route_payload[103:]
                },
                "amount_in",
            ),
            (
                {
                    "route_payload": call.route_payload[:103]
                    + (1).to_bytes(32, "big")
                    + (2).to_bytes(32, "big")
                    + call.route_payload[167:]
                },
                "minimum output",
            ),
            (
                {
                    "route_payload": call.route_payload[:167]
                    + bytes(32)
                    + call.route_payload[199:]
                },
                "quote digest",
            ),
        )
        for replacement, message in cases:
            with self.subTest(message=message):
                values = dict(common)
                values.update(replacement)
                with self.assertRaisesRegex((ValueError, TypeError), message):
                    encode_governed_execute_call(**values)

    def test_randomized_public_abi_encoding_independently_decodes(self) -> None:
        rng = random.Random(0xF5AB1)
        for case in range(250):
            command_count = rng.randint(2, 4)
            commands = []
            for index in range(command_count):
                token_in = bytes(((case + index) % 250 + 1,)) * 20
                token_out = bytes(((case + index + 97) % 250 + 1,)) * 20
                if token_out == token_in:
                    token_out = bytes(((token_out[0] % 250) + 1,)) * 20
                amount_in = rng.randint(1, 10**18)
                expected = rng.randint(1, 10**18)
                minimum = rng.randint(1, expected)
                commands.append(
                    RouteCommand(
                        index=index,
                        pool_address=bytes(((case + index + 193) % 250 + 1,)) * 20,
                        token_in=token_in,
                        token_out=token_out,
                        amount_in=amount_in,
                        expected_amount_out=expected,
                        minimum_amount_out=minimum,
                        quote_sha256=hashlib.sha256(
                            f"f5-route-{case}-{index}".encode("ascii")
                        ).hexdigest(),
                    )
                )
            payload = (
                ROUTE_PAYLOAD_HEADER
                + bytes((ROUTE_PAYLOAD_VERSION, command_count))
                + b"".join(item.binary for item in commands)
            )
            principal = rng.randint(1, 10**18)
            minimum_final = principal + rng.randint(0, 10**12)
            plan_sha256 = hashlib.sha256(f"f5-plan-{case}".encode("ascii")).digest()
            selector = hashlib.sha256(f"f5-selector-{case}".encode("ascii")).digest()[:4]
            if selector == bytes(4):
                selector = b"\x01\x00\x00\x00"
            base_token = bytes(((case + 41) % 250 + 1,)) * 20
            deadline = rng.randint(1, MAX_UINT64)
            calldata = encode_governed_execute_call(
                selector=selector,
                plan_sha256=plan_sha256,
                base_token=base_token,
                principal=principal,
                minimum_final_output=minimum_final,
                deadline_unix_s=deadline,
                route_payload=payload,
            )
            self.assertEqual(calldata[:4], selector)
            words = [calldata[4 + i * 32 : 4 + (i + 1) * 32] for i in range(6)]
            self.assertEqual(words[0], plan_sha256)
            self.assertEqual(words[1], bytes(12) + base_token)
            self.assertEqual(int.from_bytes(words[2], "big"), principal)
            self.assertEqual(int.from_bytes(words[3], "big"), minimum_final)
            self.assertEqual(int.from_bytes(words[4], "big"), deadline)
            self.assertEqual(int.from_bytes(words[5], "big"), 192)
            dynamic = 4 + int.from_bytes(words[5], "big")
            length = int.from_bytes(calldata[dynamic : dynamic + 32], "big")
            self.assertEqual(length, len(payload))
            decoded = calldata[dynamic + 32 : dynamic + 32 + length]
            self.assertEqual(decoded[:8], ROUTE_PAYLOAD_HEADER)
            self.assertEqual(decoded[8], ROUTE_PAYLOAD_VERSION)
            self.assertEqual(decoded[9], command_count)
            for index, expected_command in enumerate(commands):
                start = 10 + index * 189
                raw = decoded[start : start + 189]
                self.assertEqual(raw[0], index)
                self.assertEqual(raw[1:21], expected_command.pool_address)
                self.assertEqual(raw[21:41], expected_command.token_in)
                self.assertEqual(raw[41:61], expected_command.token_out)
                self.assertEqual(int.from_bytes(raw[61:93], "big"), expected_command.amount_in)
                self.assertEqual(
                    int.from_bytes(raw[93:125], "big"),
                    expected_command.expected_amount_out,
                )
                self.assertEqual(
                    int.from_bytes(raw[125:157], "big"),
                    expected_command.minimum_amount_out,
                )
                self.assertEqual(raw[157:189], bytes.fromhex(expected_command.quote_sha256))
            self.assertEqual(
                set(calldata[dynamic + 32 + length :]) or {0},
                {0},
            )

    def test_constraint_policy_and_raw_abi_inputs_are_bounded(self) -> None:
        with self.assertRaisesRegex(ValueError, "10000"):
            ExecutionConstraintPolicy("too-much-slippage", 10_001, 1)
        with self.assertRaisesRegex(ValueError, "positive"):
            ExecutionConstraintPolicy("zero-deadline", 0, 0)
        with self.assertRaisesRegex(ValueError, "selector"):
            encode_governed_execute_call(
                selector=b"bad",
                plan_sha256=bytes(32),
                base_token=bytes.fromhex("11" * 20),
                principal=1,
                minimum_final_output=1,
                deadline_unix_s=1,
                route_payload=b"",
            )


if __name__ == "__main__":
    unittest.main()
