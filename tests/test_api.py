import tempfile
import unittest
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from celery.exceptions import SoftTimeLimitExceeded
from fastapi.testclient import TestClient

from agentshield import app as api
from agentshield import db
from agentshield.auth import issue_key
from agentshield.scenarios import SCENARIOS
from agentshield.worker import BROKER_VISIBILITY_TIMEOUT, RUN_LOCK_TIMEOUT, TASK_HARD_LIMIT, TASK_SOFT_LIMIT, celery_app


class WorkerConfigurationTests(unittest.TestCase):
    def test_worker_deadlines_outlive_a_bounded_openai_run(self):
        self.assertLess(TASK_SOFT_LIMIT, TASK_HARD_LIMIT)
        self.assertLess(TASK_HARD_LIMIT, RUN_LOCK_TIMEOUT)
        self.assertLess(RUN_LOCK_TIMEOUT, BROKER_VISIBILITY_TIMEOUT)
        self.assertEqual(celery_app.conf.task_time_limit, TASK_HARD_LIMIT)
        self.assertEqual(celery_app.conf.broker_transport_options["visibility_timeout"], BROKER_VISIBILITY_TIMEOUT)


class SQLiteRunnerMigrationTests(unittest.TestCase):
    def test_existing_sqlite_targets_default_to_deterministic(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = db.DB_PATH
            db.DB_PATH = Path(temp_dir) / "legacy.sqlite3"
            try:
                with sqlite3.connect(db.DB_PATH) as conn:
                    conn.execute("CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL)")
                    conn.execute("CREATE TABLE policies (id TEXT PRIMARY KEY, name TEXT NOT NULL, version INTEGER NOT NULL, definition TEXT NOT NULL, created_at TEXT NOT NULL)")
                    conn.execute("""CREATE TABLE targets (
                        id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL, owner TEXT NOT NULL,
                        environment TEXT NOT NULL, authorized INTEGER NOT NULL, policy_id TEXT, created_at TEXT NOT NULL
                    )""")
                api._init_db()
                with db.connect() as conn:
                    old_target = conn.execute("SELECT runner FROM targets WHERE id='simulated-unprotected'").fetchone()
                    reference_target = conn.execute("SELECT runner FROM targets WHERE id='openai-reference-unprotected'").fetchone()
                self.assertEqual(old_target["runner"], "deterministic")
                self.assertEqual(reference_target["runner"], "openai_reference")
            finally:
                db.DB_PATH = old_path


class OrganizationApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_path = db.DB_PATH
        self.old_auth = api.AUTH_REQUIRED
        self.old_bootstrap = os.environ.get("AGENTSHIELD_BOOTSTRAP_API_KEY")
        self.old_openai_key = os.environ.get("OPENAI_API_KEY")
        db.DB_PATH = Path(self.temp.name) / "test.sqlite3"
        os.environ["AGENTSHIELD_BOOTSTRAP_API_KEY"] = "ash_test_bootstrap_key_for_api_tests_only_123456789"
        api.AUTH_REQUIRED = True
        self.client = TestClient(api.app)
        self.client.__enter__()
        with db.connect() as conn:
            self.admin_key = os.environ["AGENTSHIELD_BOOTSTRAP_API_KEY"]
            _, self.platform_key = issue_key(conn, None, "platform_admin")

    def tearDown(self):
        self.client.__exit__(None, None, None)
        api.AUTH_REQUIRED = self.old_auth
        if self.old_bootstrap is None:
            os.environ.pop("AGENTSHIELD_BOOTSTRAP_API_KEY", None)
        else:
            os.environ["AGENTSHIELD_BOOTSTRAP_API_KEY"] = self.old_bootstrap
        if self.old_openai_key is None:
            os.environ.pop("OPENAI_API_KEY", None)
        else:
            os.environ["OPENAI_API_KEY"] = self.old_openai_key
        db.DB_PATH = self.old_path
        self.temp.cleanup()

    @staticmethod
    def headers(key):
        return {"Authorization": f"Bearer {key}"}

    def test_api_requires_key_and_organizations_cannot_read_each_others_targets(self):
        self.assertEqual(self.client.get("/api/v1/targets").status_code, 401)
        create = self.client.post("/api/v1/organizations", headers=self.headers(self.platform_key), json={"name": "Second tenant"})
        self.assertEqual(create.status_code, 201, create.text)
        second = create.json()
        second_headers = self.headers(second["admin_key"])

        first_targets = self.client.get("/api/v1/targets", headers=self.headers(self.admin_key)).json()["items"]
        second_targets = self.client.get("/api/v1/targets", headers=second_headers).json()["items"]
        self.assertEqual(len(first_targets), 4)
        self.assertEqual(len(second_targets), 4)
        self.assertEqual(first_targets[0]["runner"], "deterministic")
        self.assertNotEqual(first_targets[0]["id"], second_targets[0]["id"])
        cross_tenant = self.client.post(f"/api/v1/targets/{first_targets[0]['id']}/validate", headers=second_headers)
        self.assertEqual(cross_tenant.status_code, 404)

    def test_viewer_cannot_start_run_and_revoked_key_stops_authenticating(self):
        created = self.client.post("/api/v1/api-keys", headers=self.headers(self.admin_key), json={"role": "viewer"})
        self.assertEqual(created.status_code, 201, created.text)
        key = created.json()
        targets = self.client.get("/api/v1/targets", headers=self.headers(self.admin_key)).json()["items"]
        denied = self.client.post("/api/v1/evaluations", headers=self.headers(key["key"]), json={"target_id": targets[0]["id"], "scenario_ids": ["benign-01"]})
        self.assertEqual(denied.status_code, 403)
        revoked = self.client.delete(f"/api/v1/api-keys/{key['id']}", headers=self.headers(self.admin_key))
        self.assertEqual(revoked.status_code, 204)
        self.assertEqual(self.client.get("/api/v1/targets", headers=self.headers(key["key"])).status_code, 401)

    def test_full_benchmark_and_report_survive_api_round_trip(self):
        headers = self.headers(self.admin_key)
        targets = self.client.get("/api/v1/targets", headers=headers).json()["items"]
        runs = []
        ordered_targets = [next(t for t in targets if "Unprotected" in t["name"]), next(t for t in targets if "Guarded" in t["name"])]
        for target in ordered_targets:
            response = self.client.post("/api/v1/evaluations", headers=headers, json={
                "target_id": target["id"], "scenario_ids": [scenario["id"] for scenario in SCENARIOS],
            })
            self.assertEqual(response.status_code, 202, response.text)
            result = self.client.get(f"/api/v1/evaluations/{response.json()['id']}", headers=headers).json()
            self.assertEqual(result["status"], "completed")
            runs.append(result)
        self.assertEqual(runs[0]["summary"]["confirmed_violations"], 30)
        self.assertEqual(runs[1]["summary"]["confirmed_violations"], 0)
        findings = self.client.get(f"/api/v1/evaluations/{runs[0]['id']}/findings", headers=headers).json()["items"]
        self.assertTrue(any("sensitive_data_disclosure" in item["violations"] for item in findings))
        self.assertNotIn("blair@example.invalid", str(findings))
        report = self.client.get(f"/api/v1/evaluations/{runs[1]['id']}/report", headers=headers).json()
        self.assertEqual(len(report["executions"]), 50)
        compare = self.client.post("/api/v1/evaluations/compare", headers=headers, json={
            "baseline_run_id": runs[0]["id"], "protected_run_id": runs[1]["id"],
        })
        self.assertEqual(compare.status_code, 200, compare.text)
        self.assertEqual(len(compare.json()["improved"]), 31)
        self.assertEqual(set(compare.json()["unscored"]), {"reliability-03", "reliability-04", "reliability-05", "reliability-06", "reliability-07", "reliability-09"})
        self.assertTrue(set(compare.json()["unscored"]).isdisjoint(compare.json()["unchanged"]))

    def test_compare_requires_matching_scenarios_and_guard_states(self):
        headers = self.headers(self.admin_key)
        targets = self.client.get("/api/v1/targets", headers=headers).json()["items"]
        unguarded = next(target for target in targets if "Unprotected" in target["name"])
        guarded = next(target for target in targets if "Guarded" in target["name"])

        def completed_run(target, scenario_ids):
            response = self.client.post("/api/v1/evaluations", headers=headers, json={
                "target_id": target["id"], "scenario_ids": scenario_ids,
            })
            self.assertEqual(response.status_code, 202, response.text)
            run = self.client.get(f"/api/v1/evaluations/{response.json()['id']}", headers=headers).json()
            self.assertEqual(run["status"], "completed")
            return run

        baseline = completed_run(unguarded, ["benign-01"])
        mismatched = completed_run(guarded, ["benign-01", "benign-02"])
        response = self.client.post("/api/v1/evaluations/compare", headers=headers, json={
            "baseline_run_id": baseline["id"], "protected_run_id": mismatched["id"],
        })
        self.assertEqual(response.status_code, 422, response.text)
        wrong_guard = completed_run(unguarded, ["benign-01"])
        response = self.client.post("/api/v1/evaluations/compare", headers=headers, json={
            "baseline_run_id": baseline["id"], "protected_run_id": wrong_guard["id"],
        })
        self.assertEqual(response.status_code, 422, response.text)

    def test_openai_reference_requires_key_and_limits_scenario_count(self):
        headers = self.headers(self.admin_key)
        target_id = "openai-reference-unprotected"
        os.environ.pop("OPENAI_API_KEY", None)
        validation = self.client.post(f"/api/v1/targets/{target_id}/validate", headers=headers)
        self.assertEqual(validation.json()["status"], "configuration_required")
        missing_key = self.client.post("/api/v1/evaluations", headers=headers, json={
            "target_id": target_id, "scenario_ids": ["benign-01"],
        })
        self.assertEqual(missing_key.status_code, 503, missing_key.text)

        os.environ["OPENAI_API_KEY"] = "test-key"
        over_limit = self.client.post("/api/v1/evaluations", headers=headers, json={
            "target_id": target_id, "scenario_ids": [scenario["id"] for scenario in SCENARIOS[:11]],
        })
        self.assertEqual(over_limit.status_code, 422, over_limit.text)

    def test_openai_reference_run_reports_mocked_provider_usage_without_fake_cost(self):
        os.environ["OPENAI_API_KEY"] = "test-key"
        from agentshield.openai_agent import evaluate_openai_scenario

        response_obj = SimpleNamespace(output=[], output_text="Task completed.", usage=SimpleNamespace(input_tokens=12, output_tokens=4))
        client = SimpleNamespace(responses=SimpleNamespace(create=lambda **_kwargs: response_obj))
        models = iter(("test-model", "different-model"))

        def fake_provider(scenario, policy):
            return evaluate_openai_scenario(scenario, policy, client=client, model=next(models))

        with patch("agentshield.openai_agent.evaluate_openai_scenario", side_effect=fake_provider):
            queued = self.client.post("/api/v1/evaluations", headers=self.headers(self.admin_key), json={
                "target_id": "openai-reference-unprotected", "scenario_ids": ["benign-01"],
            })
            protected = self.client.post("/api/v1/evaluations", headers=self.headers(self.admin_key), json={
                "target_id": "openai-reference-protected", "scenario_ids": ["benign-01"],
            })
        self.assertEqual(queued.status_code, 202, queued.text)
        run = self.client.get(f"/api/v1/evaluations/{queued.json()['id']}", headers=self.headers(self.admin_key)).json()
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["summary"]["model"], "test-model")
        self.assertEqual(run["summary"]["tokens_used"], 16)
        self.assertEqual(run["summary"]["inconclusive"], 1)
        self.assertIsNone(run["summary"]["estimated_provider_cost_usd"])
        report = self.client.get(f"/api/v1/evaluations/{run['id']}/report?format=markdown", headers=self.headers(self.admin_key))
        self.assertEqual(report.status_code, 200, report.text)
        self.assertIn("Estimated provider cost: not estimated", report.text)
        self.assertEqual(protected.status_code, 202, protected.text)
        guarded_run = self.client.get(f"/api/v1/evaluations/{protected.json()['id']}", headers=self.headers(self.admin_key)).json()
        comparison = self.client.post("/api/v1/evaluations/compare", headers=self.headers(self.admin_key), json={
            "baseline_run_id": run["id"], "protected_run_id": guarded_run["id"],
        })
        self.assertEqual(comparison.status_code, 422, comparison.text)

    def test_queued_evaluation_can_be_cancelled(self):
        original_enqueue = api._enqueue
        api._enqueue = lambda *args: None
        try:
            headers = self.headers(self.admin_key)
            target_id = self.client.get("/api/v1/targets", headers=headers).json()["items"][0]["id"]
            queued = self.client.post("/api/v1/evaluations", headers=headers, json={"target_id": target_id, "scenario_ids": ["benign-01"]})
            self.assertEqual(queued.status_code, 202, queued.text)
            cancelled = self.client.post(f"/api/v1/evaluations/{queued.json()['id']}/cancel", headers=headers)
            self.assertEqual(cancelled.status_code, 200, cancelled.text)
            self.assertEqual(cancelled.json()["status"], "cancelled")
        finally:
            api._enqueue = original_enqueue

    def test_running_evaluation_stops_at_a_case_boundary(self):
        original_enqueue = api._enqueue
        original_evaluator = api.evaluate_scenario
        api._enqueue = lambda *args: None
        try:
            headers = self.headers(self.admin_key)
            target_id = self.client.get("/api/v1/targets", headers=headers).json()["items"][0]["id"]
            queued = self.client.post("/api/v1/evaluations", headers=headers, json={"target_id": target_id, "scenario_ids": ["benign-01", "benign-04"]})
            run_id = queued.json()["id"]
            calls = 0

            def cancel_after_first(scenario, policy):
                nonlocal calls
                result = original_evaluator(scenario, policy)
                calls += 1
                if calls == 1:
                    with db.connect() as conn:
                        conn.execute("UPDATE runs SET status='cancel_requested' WHERE id=?", (run_id,))
                return result

            api.evaluate_scenario = cancel_after_first
            api._execute_run_from_id(run_id)
            result = self.client.get(f"/api/v1/evaluations/{run_id}", headers=headers).json()
            self.assertEqual(result["status"], "cancelled")
            self.assertEqual(result["summary"]["completed"], 1)
        finally:
            api.evaluate_scenario = original_evaluator
            api._enqueue = original_enqueue

    def test_worker_time_limit_is_retried_instead_of_recorded_as_a_case_error(self):
        original_enqueue = api._enqueue
        original_evaluator = api.evaluate_scenario
        api._enqueue = lambda *args: None

        def time_out(*_args):
            raise SoftTimeLimitExceeded()

        api.evaluate_scenario = time_out
        try:
            headers = self.headers(self.admin_key)
            target_id = self.client.get("/api/v1/targets", headers=headers).json()["items"][0]["id"]
            queued = self.client.post("/api/v1/evaluations", headers=headers, json={"target_id": target_id, "scenario_ids": ["benign-01"]})
            with self.assertRaises(SoftTimeLimitExceeded):
                api._execute_run_from_id(queued.json()["id"])
        finally:
            api.evaluate_scenario = original_evaluator
            api._enqueue = original_enqueue


if __name__ == "__main__":
    unittest.main()
