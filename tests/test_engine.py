import json
import time
import unittest
from copy import deepcopy
from types import SimpleNamespace

import httpx
from openai import OpenAI
from agentshield.engine import DEFAULT_POLICY, SECRET, evaluate_scenario, redact
from agentshield.openai_agent import evaluate_openai_scenario, function_tools
from agentshield.scenarios import BY_ID, SCENARIOS


class ScenarioCatalogTests(unittest.TestCase):
    def test_catalog_has_requested_mix_and_replay_fields(self):
        counts = {group: sum(s["group"] == group for s in SCENARIOS) for group in ("security", "benign", "reliability")}
        self.assertEqual(counts, {"security": 30, "benign": 10, "reliability": 10})
        required = {"id", "version", "category", "severity", "authorized_target", "legitimate_task", "attack_surface", "payload", "expected_behavior", "forbidden_actions", "checks", "fixture", "cleanup", "replay"}
        self.assertTrue(all(required <= set(scenario) for scenario in SCENARIOS))


class EvaluationEngineTests(unittest.TestCase):
    def test_policy_blocks_cross_tenant_read_while_unprotected_agent_executes_it(self):
        scenario = BY_ID["tenant-02"]
        self.assertEqual(evaluate_scenario(scenario, None)["verdict"], "FAIL")
        guarded = evaluate_scenario(scenario, DEFAULT_POLICY)
        self.assertEqual(guarded["verdict"], "PASS")
        self.assertEqual(guarded["evidence"]["executed_tool_calls"], 0)

    def test_policy_requires_a_real_approval_for_refund(self):
        scenario = BY_ID["approval-02"]
        self.assertIn("unapproved_refund", evaluate_scenario(scenario, None)["violations"])
        guarded = evaluate_scenario(scenario, DEFAULT_POLICY)
        self.assertEqual(guarded["verdict"], "PASS")
        self.assertEqual(guarded["evidence"]["executed_tool_calls"], 0)

    def test_approval_from_benign_fixture_cannot_be_reused_by_an_attack(self):
        scenario = deepcopy(BY_ID["approval-01"])
        scenario["proposed_tool_calls"][0]["arguments"]["approval_id"] = "apr-refund-1"
        result = evaluate_scenario(scenario, DEFAULT_POLICY)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["evidence"]["executed_tool_calls"], 0)

    def test_approved_benign_email_is_not_blocked(self):
        result = evaluate_scenario(BY_ID["benign-05"], DEFAULT_POLICY)
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(result["violations"])

    def test_approval_fixtures_are_redacted_from_scenario_responses(self):
        scenario = redact(BY_ID["benign-04"])
        self.assertEqual(scenario["fixture_approvals"], "[REDACTED]")
        self.assertEqual(scenario["proposed_tool_calls"][0]["arguments"]["approval_id"], "[REDACTED]")

    def test_secret_is_detected_but_redacted_from_stored_evidence(self):
        result = evaluate_scenario(BY_ID["secret-01"], None)
        self.assertIn("secret_disclosure", result["violations"])
        self.assertNotIn(SECRET, str(result["events"]))
        self.assertNotIn(SECRET, str(result["evidence"]))

    def test_cross_tenant_personal_data_is_detected_before_trace_redaction(self):
        for scenario_id in ("secret-02", "secret-03"):
            result = evaluate_scenario(BY_ID[scenario_id], None)
            self.assertIn("sensitive_data_disclosure", result["violations"])
            self.assertNotIn("blair@example.invalid", str(result["events"]))
            self.assertNotIn("blair@example.invalid", str(result["evidence"]))
            decision = next(event for event in result["events"] if event["type"] == "output_policy_decision")
            self.assertEqual(decision["data"]["decision"], "observe")

        guarded = evaluate_scenario(BY_ID["secret-02"], DEFAULT_POLICY)
        self.assertNotIn("sensitive_data_disclosure", guarded["violations"])
        own_data = evaluate_scenario(BY_ID["benign-02"], DEFAULT_POLICY)
        self.assertNotIn("sensitive_data_disclosure", own_data["violations"])

    def test_tool_budget_stops_repeated_calls(self):
        guarded = evaluate_scenario(BY_ID["reliability-08"], DEFAULT_POLICY)
        self.assertEqual(guarded["verdict"], "PASS")
        self.assertEqual(guarded["evidence"]["executed_tool_calls"], DEFAULT_POLICY["max_tool_calls"])
        unprotected = evaluate_scenario(BY_ID["reliability-08"], None)
        self.assertIn("tool_call_budget_exceeded", unprotected["violations"])
        self.assertLessEqual(unprotected["evidence"]["attempted_tool_calls"], 11)

    def test_mock_service_failure_is_reported_as_infrastructure_error(self):
        result = evaluate_scenario(BY_ID["reliability-05"], DEFAULT_POLICY)
        self.assertEqual(result["verdict"], "ERROR")
        self.assertTrue(any(event["type"] == "target_error" for event in result["events"]))

    def test_openai_tools_use_strict_schemas_and_actions_are_checked_by_engine(self):
        request = {}
        responses = [
            SimpleNamespace(
                output=[SimpleNamespace(type="function_call", name="get_secret", call_id="call-1", arguments='{"key":"test"}')],
                output_text="",
                usage=SimpleNamespace(input_tokens=10, output_tokens=3),
            ),
            SimpleNamespace(output=[], output_text=SECRET, usage=SimpleNamespace(input_tokens=7, output_tokens=5)),
        ]

        def create(**kwargs):
            request.setdefault("calls", []).append(kwargs)
            return responses[len(request["calls"]) - 1]

        client = SimpleNamespace(responses=SimpleNamespace(create=create))

        result = evaluate_openai_scenario(BY_ID["secret-01"], None, client=client, model="test-model")

        secret_tool = next(tool for tool in function_tools() if tool["name"] == "get_secret")
        self.assertTrue(secret_tool["strict"])
        self.assertIs(secret_tool["parameters"]["additionalProperties"], False)
        self.assertEqual(secret_tool["parameters"]["required"], ["key"])
        self.assertIn("secret_disclosure", result["violations"])
        self.assertEqual(result["evidence"]["model"], "test-model")
        self.assertEqual(result["evidence"]["usage"]["total_tokens"], 25)
        self.assertIs(request["calls"][0]["store"], False)
        self.assertIs(request["calls"][0]["parallel_tool_calls"], False)
        self.assertEqual(request["calls"][1]["tool_choice"], "none")
        self.assertIn(SECRET, request["calls"][1]["input"][-1]["output"])
        self.assertNotIn(SECRET, str(result["events"]))

    def test_openai_incomplete_or_malformed_calls_are_rejected_before_tool_execution(self):
        def function_call(*, status="completed", call_id="call-1", arguments='{"key":"test"}'):
            return SimpleNamespace(type="function_call", status=status, name="get_secret",
                                   call_id=call_id, arguments=arguments)

        cases = [
            (SimpleNamespace(status="incomplete", output=[function_call()], output_text=""), "response did not complete"),
            (SimpleNamespace(status="completed", output=[function_call(status="incomplete")], output_text=""), "function call did not complete"),
            (SimpleNamespace(status="completed", output=[function_call(arguments='{"key":')], output_text=""), "invalid function-call arguments"),
            (SimpleNamespace(status="completed", output=[function_call(arguments="[]")], output_text=""), "invalid function-call arguments"),
            (SimpleNamespace(status="completed", output=[function_call(call_id=None)], output_text=""), "malformed function call"),
        ]
        for response, message in cases:
            with self.subTest(message=message):
                calls = 0

                def create(**_kwargs):
                    nonlocal calls
                    calls += 1
                    return response

                client = SimpleNamespace(responses=SimpleNamespace(create=create))
                with self.assertRaisesRegex(RuntimeError, message):
                    evaluate_openai_scenario(BY_ID["secret-01"], None, client=client)
                self.assertEqual(calls, 1)

    def test_openai_final_response_failure_keeps_action_finding(self):
        calls = 0

        def create(**_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return SimpleNamespace(
                    output=[SimpleNamespace(type="function_call", name="get_secret", call_id="call-1", arguments='{"key":"test"}')],
                    output_text="",
                    usage=SimpleNamespace(input_tokens=10, output_tokens=3),
                )
            raise TimeoutError("simulated provider timeout")

        client = SimpleNamespace(responses=SimpleNamespace(create=create))
        result = evaluate_openai_scenario(BY_ID["secret-01"], None, client=client, model="test-model")
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("secret_disclosure", result["violations"])
        self.assertEqual(result["evidence"]["final_response_error_type"], "TimeoutError")
        self.assertTrue(any(event["type"] == "target_error" for event in result["events"]))

    def test_openai_sdk_round_trip_observes_and_redacts_model_output(self):
        requests = []

        def handler(request):
            requests.append(json.loads(request.read()))
            output = ([{
                "id": "fc_1", "type": "function_call", "status": "completed", "call_id": "call_1",
                "name": "get_secret", "arguments": "{\"key\":\"test\"}",
            }] if len(requests) == 1 else [{
                "id": "msg_1", "type": "message", "status": "completed", "role": "assistant",
                "content": [{"type": "output_text", "annotations": [], "text": SECRET, "logprobs": []}],
            }])
            return httpx.Response(200, json={
                "id": f"resp_{len(requests)}", "object": "response", "created_at": int(time.time()),
                "status": "completed", "error": None, "incomplete_details": None, "instructions": None,
                "max_output_tokens": 256, "model": "gpt-6-astra", "output": output,
                "parallel_tool_calls": False, "tool_choice": "auto", "tools": [], "top_p": 1.0,
                "usage": {"input_tokens": 10, "output_tokens": 3, "total_tokens": 13},
            })

        transport = httpx.MockTransport(handler)
        with OpenAI(api_key="test-key", http_client=httpx.Client(transport=transport)) as client:
            result = evaluate_openai_scenario(BY_ID["secret-01"], None, client=client)

        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[1]["input"][-1]["type"], "function_call_output")
        self.assertEqual(requests[1]["input"][-1]["call_id"], "call_1")
        self.assertEqual(requests[1]["tool_choice"], "none")
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("secret_disclosure", result["violations"])
        self.assertEqual(result["evidence"]["model"], "gpt-6-astra")
        self.assertEqual(result["evidence"]["usage"]["total_tokens"], 26)
        self.assertNotIn(SECRET, str(result["events"]))
        self.assertNotIn(SECRET, str(result["evidence"]))

    def test_openai_incomplete_followup_is_error_and_keeps_action_finding(self):
        responses = iter((
            SimpleNamespace(status="completed", model="test-model", output=[SimpleNamespace(
                type="function_call", status="completed", name="get_secret", call_id="call-1",
                arguments='{"key":"test"}',
            )], output_text=""),
            SimpleNamespace(status="incomplete", output=[], output_text=""),
        ))
        client = SimpleNamespace(responses=SimpleNamespace(create=lambda **_kwargs: next(responses)))

        result = evaluate_openai_scenario(BY_ID["secret-01"], None, client=client, model="test-model")

        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("secret_disclosure", result["violations"])
        self.assertEqual(result["evidence"]["final_response_error_type"], "RuntimeError")
        self.assertTrue(any(event["type"] == "target_error" for event in result["events"]))


if __name__ == "__main__":
    unittest.main()
