"""Exercise the production API and Celery path against disposable CI services."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

if os.environ.get("AGENTSHIELD_ENV") != "production":
    raise SystemExit("Set AGENTSHIELD_ENV=production for this disposable-service smoke test.")

from fastapi.testclient import TestClient

from agentshield.app import app


def wait_for_run(client: TestClient, headers: dict[str, str], run_id: str, worker: subprocess.Popen) -> dict:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if worker.poll() is not None:
            raise RuntimeError(f"Celery worker exited with status {worker.returncode}.")
        response = client.get(f"/api/v1/evaluations/{run_id}", headers=headers)
        assert response.status_code == 200, response.text
        run = response.json()
        if run["status"] in {"completed", "failed", "cancelled"}:
            assert run["status"] == "completed", run
            return run
        time.sleep(0.2)
    raise TimeoutError(f"Celery did not complete run {run_id} within 30 seconds.")


def main() -> None:
    headers = {"Authorization": f"Bearer {os.environ['AGENTSHIELD_BOOTSTRAP_API_KEY']}"}
    worker = None

    with TestClient(app) as client:
        ready = client.get("/health/ready")
        assert ready.status_code == 200, ready.text
        worker = subprocess.Popen(
            [sys.executable, "-m", "celery", "-A", "agentshield.worker:celery_app", "worker",
             "--loglevel=WARNING", "--pool=solo", "--concurrency=1"],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            targets = client.get("/api/v1/targets", headers=headers)
            assert targets.status_code == 200, targets.text
            items = targets.json()["items"]
            unguarded = next(target for target in items if "Unprotected" in target["name"])
            guarded = next(target for target in items if "Guarded" in target["name"])
            scenarios = ["secret-02", "benign-02"]

            first = client.post("/api/v1/evaluations", headers={**headers, "Idempotency-Key": "production-smoke-run"},
                                json={"target_id": unguarded["id"], "scenario_ids": scenarios})
            assert first.status_code == 202, first.text
            duplicate = client.post("/api/v1/evaluations", headers={**headers, "Idempotency-Key": "production-smoke-run"},
                                    json={"target_id": unguarded["id"], "scenario_ids": scenarios})
            assert duplicate.status_code == 202, duplicate.text
            assert duplicate.json()["id"] == first.json()["id"]

            protected = client.post("/api/v1/evaluations", headers=headers,
                                    json={"target_id": guarded["id"], "scenario_ids": scenarios})
            assert protected.status_code == 202, protected.text
            baseline_run = wait_for_run(client, headers, first.json()["id"], worker)
            guarded_run = wait_for_run(client, headers, protected.json()["id"], worker)
            assert baseline_run["summary"]["confirmed_violations"] == 1, baseline_run
            assert guarded_run["summary"]["confirmed_violations"] == 0, guarded_run

            findings = client.get(f"/api/v1/evaluations/{baseline_run['id']}/findings", headers=headers)
            assert findings.status_code == 200, findings.text
            assert any("sensitive_data_disclosure" in item["violations"] for item in findings.json()["items"])
            assert "blair@example.invalid" not in findings.text
            report = client.get(f"/api/v1/evaluations/{guarded_run['id']}/report", headers=headers)
            assert report.status_code == 200, report.text
            assert len(report.json()["executions"]) == 2

            comparison = client.post("/api/v1/evaluations/compare", headers=headers,
                                     json={"baseline_run_id": baseline_run["id"], "protected_run_id": guarded_run["id"]})
            assert comparison.status_code == 200, comparison.text
            assert comparison.json()["improved"] == ["secret-02"], comparison.text
            print("Production API, PostgreSQL, Redis/Celery worker, idempotency, findings, and report passed.")
        finally:
            worker.terminate()
            try:
                worker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait()


if __name__ == "__main__":
    main()
