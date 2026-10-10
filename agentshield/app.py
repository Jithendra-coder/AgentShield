from __future__ import annotations

import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.staticfiles import StaticFiles
from celery.exceptions import SoftTimeLimitExceeded

from .engine import DEFAULT_POLICY, TOOL_SCHEMAS, evaluate_scenario, redact
from .scenarios import BY_ID, SCENARIOS, get_scenarios
from . import db as database
from .auth import Principal, authenticate, issue_key, require_role

DATA_DIR = database.DATA_DIR
DB_PATH = database.DB_PATH
ENVIRONMENT = os.environ.get("AGENTSHIELD_ENV", "development").lower()
PRODUCTION = ENVIRONMENT == "production"
AUTH_REQUIRED = ENVIRONMENT != "development" or os.environ.get("AGENTSHIELD_AUTH_REQUIRED", "false").lower() == "true"
REDIS_URL = os.environ.get("AGENTSHIELD_REDIS_URL", "")
MAX_REQUEST_BYTES = 1_048_576
OPENAI_MAX_SCENARIOS_PER_RUN = 10
STATIC_DIR = Path(__file__).resolve().parent / "static"
ACCESS_LOG = logging.getLogger("agentshield.access")
RUN_LOG = logging.getLogger("agentshield.runner")
REMEDIATIONS = {
    "cross_tenant_action": "Derive tenant scope from the authenticated identity and reject cross-tenant writes before calling tools.",
    "cross_tenant_read": "Derive tenant scope server-side and check record ownership before returning data.",
    "unapproved_refund": "Require a server-issued approval token for refunds above the configured threshold; ignore model-supplied approval flags.",
    "unapproved_email": "Require a server-issued approval token before sending outbound messages.",
    "record_deletion": "Remove destructive tools from the agent allowlist or put them behind an explicit approval step.",
    "bulk_export": "Replace bulk export access with scoped queries and enforce per-user data minimization.",
    "secret_disclosure": "Keep secrets out of model-visible tool results and add output checks before returning responses.",
    "sensitive_data_disclosure": "Enforce tenant scope before lookup and return only the personal data needed for the task.",
    "tool_call_budget_exceeded": "Set a per-run tool-call budget and stop execution when the budget is reached.",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(redact(value), separators=(",", ":"), ensure_ascii=False)


def _load(value: str | None, default: Any = None) -> Any:
    return json.loads(value) if value else default


def _org_id(request: Request) -> str:
    organization_id = request.state.principal.organization_id
    if organization_id is None:
        raise HTTPException(403, "A platform key cannot access organization data.")
    return organization_id


def _require(request: Request, *roles: str) -> str:
    principal = request.state.principal
    require_role(principal, *roles)
    return _org_id(request)


def _seed_org(db, organization_id: str, name: str) -> None:
    policy_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "agentshield:policy:default:v1")) if organization_id == "default" else str(uuid.uuid5(uuid.NAMESPACE_URL, f"agentshield:policy:{organization_id}:default:v1"))
    unprotected_id = "simulated-unprotected" if organization_id == "default" else str(uuid.uuid5(uuid.NAMESPACE_URL, f"agentshield:{organization_id}:unprotected"))
    protected_id = "simulated-protected" if organization_id == "default" else str(uuid.uuid5(uuid.NAMESPACE_URL, f"agentshield:{organization_id}:protected"))
    openai_unprotected_id = "openai-reference-unprotected" if organization_id == "default" else str(uuid.uuid5(uuid.NAMESPACE_URL, f"agentshield:{organization_id}:openai-unprotected"))
    openai_protected_id = "openai-reference-protected" if organization_id == "default" else str(uuid.uuid5(uuid.NAMESPACE_URL, f"agentshield:{organization_id}:openai-protected"))
    db.execute("INSERT INTO policies (id,organization_id,name,version,definition,created_at) VALUES (?, ?, ?, 1, ?, ?) ON CONFLICT(id) DO NOTHING",
               (policy_id, organization_id, "AgentShield Baseline", _json(DEFAULT_POLICY), _now()))
    authorized = "TRUE" if database.IS_POSTGRES else "1"
    query = f"INSERT INTO targets (id,organization_id,name,version,owner,environment,authorized,policy_id,created_at) VALUES (?, ?, ?, '1.0.0', ?, 'simulator', {authorized}, ?, ?) ON CONFLICT(id) DO NOTHING"
    db.execute(query, (unprotected_id, organization_id, "Simulated Support Agent · Unprotected", name, None, _now()))
    db.execute(query, (protected_id, organization_id, "Simulated Support Agent · Guarded", name, policy_id, _now()))
    query = f"INSERT INTO targets (id,organization_id,name,version,owner,environment,authorized,policy_id,created_at,runner) VALUES (?, ?, ?, '1.0.0', ?, 'simulator', {authorized}, ?, ?, 'openai_reference') ON CONFLICT(id) DO NOTHING"
    db.execute(query, (openai_unprotected_id, organization_id, "OpenAI Reference Agent · Unprotected", name, None, _now()))
    db.execute(query, (openai_protected_id, organization_id, "OpenAI Reference Agent · Guarded", name, policy_id, _now()))


_connect = database.connect


def _init_db() -> None:
    bootstrap_key = os.environ.get("AGENTSHIELD_BOOTSTRAP_API_KEY")
    platform_key = os.environ.get("AGENTSHIELD_PLATFORM_API_KEY")
    if AUTH_REQUIRED and (not bootstrap_key or not bootstrap_key.startswith("ash_") or len(bootstrap_key) < 32):
        raise RuntimeError("Authenticated deployments require AGENTSHIELD_BOOTSTRAP_API_KEY with the ash_ prefix and at least 32 characters.")
    if PRODUCTION and (not database.IS_POSTGRES or not platform_key or not platform_key.startswith("ash_") or len(platform_key) < 32 or not REDIS_URL):
        raise RuntimeError("Production requires PostgreSQL, 32+ character ash_ bootstrap and platform API keys, and AGENTSHIELD_REDIS_URL.")
    if database.IS_POSTGRES:
        database.migrate()
        statements = []
    else:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        statements = [
            "CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, organization_id TEXT REFERENCES organizations(id), prefix TEXT NOT NULL, secret_hash TEXT NOT NULL UNIQUE, role TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT)",
            "CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL DEFAULT 'default', name TEXT NOT NULL, version INTEGER NOT NULL, definition TEXT NOT NULL, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS targets (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL DEFAULT 'default', name TEXT NOT NULL, version TEXT NOT NULL, owner TEXT NOT NULL, environment TEXT NOT NULL CHECK(environment = 'simulator'), authorized INTEGER NOT NULL CHECK(authorized = 1), policy_id TEXT REFERENCES policies(id), created_at TEXT NOT NULL, runner TEXT NOT NULL DEFAULT 'deterministic' CHECK(runner IN ('deterministic','openai_reference')))",
            "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL DEFAULT 'default', target_id TEXT NOT NULL REFERENCES targets(id), policy_id TEXT REFERENCES policies(id), status TEXT NOT NULL, scenario_ids TEXT NOT NULL, scenario_snapshots TEXT NOT NULL DEFAULT '[]', idempotency_key TEXT, created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT, summary TEXT, error TEXT)",
            "CREATE TABLE IF NOT EXISTS executions (id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, scenario_id TEXT NOT NULL, scenario_version TEXT NOT NULL, verdict TEXT NOT NULL, evidence TEXT NOT NULL, violations TEXT NOT NULL, scenario_snapshot TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS executions_run_idx ON executions(run_id, scenario_id)",
            "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, execution_id TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE, scenario_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_type TEXT NOT NULL, data TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS events_run_idx ON events(run_id, id)",
            "CREATE TABLE IF NOT EXISTS job_outbox (run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE, created_at TEXT NOT NULL, sent_at TEXT)",
        ]
    with _connect() as db:
        for statement in statements:
            db.execute(statement)
        if not database.IS_POSTGRES:
            db.execute("INSERT OR IGNORE INTO organizations (id,name,created_at) VALUES ('default','AgentShield',?)", (_now(),))
            for table, column, definition in (("policies", "organization_id", "TEXT NOT NULL DEFAULT 'default'"),
                                             ("targets", "organization_id", "TEXT NOT NULL DEFAULT 'default'"),
                                             ("runs", "organization_id", "TEXT NOT NULL DEFAULT 'default'"),
                                             ("runs", "scenario_snapshots", "TEXT NOT NULL DEFAULT '[]'"),
                                             ("executions", "scenario_snapshot", "TEXT NOT NULL DEFAULT '{}'"),
                                             ("runs", "policy_id", "TEXT REFERENCES policies(id)"),
                                             ("targets", "runner", "TEXT NOT NULL DEFAULT 'deterministic' CHECK(runner IN ('deterministic','openai_reference'))")):
                columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
                if column not in columns:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            # Normalize rows created by the initial local prototype.
            db.execute("UPDATE policies SET organization_id='default' WHERE organization_id IS NULL")
            db.execute("UPDATE targets SET organization_id='default' WHERE organization_id IS NULL")
            db.execute("UPDATE runs SET organization_id='default' WHERE organization_id IS NULL")
            for index in ("CREATE INDEX IF NOT EXISTS policies_org_idx ON policies(organization_id, created_at)",
                          "CREATE INDEX IF NOT EXISTS targets_org_idx ON targets(organization_id, created_at)",
                          "CREATE UNIQUE INDEX IF NOT EXISTS runs_org_idempotency_idx ON runs(organization_id, idempotency_key) WHERE idempotency_key IS NOT NULL",
                          "CREATE INDEX IF NOT EXISTS runs_org_idx ON runs(organization_id, created_at)"):
                db.execute(index)
        db.execute("INSERT INTO organizations (id,name,created_at) VALUES (?, ?, ?) ON CONFLICT(id) DO NOTHING", ("default", os.environ.get("AGENTSHIELD_BOOTSTRAP_ORG", "AgentShield"), _now()))
        _seed_org(db, "default", os.environ.get("AGENTSHIELD_BOOTSTRAP_ORG", "AgentShield"))
        for token, org_id, role in ((bootstrap_key, "default", "admin"), (platform_key, None, "platform_admin")):
            if token:
                import hashlib
                if not db.execute("SELECT 1 FROM api_keys WHERE secret_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone():
                    db.execute("INSERT INTO api_keys (id,organization_id,prefix,secret_hash,role,created_at) VALUES (?,?,?,?,?,?) ON CONFLICT(secret_hash) DO NOTHING",
                               (str(uuid.uuid4()), org_id, token[:12], hashlib.sha256(token.encode()).hexdigest(), role, _now()))
        if ENVIRONMENT == "development":
            db.execute("UPDATE runs SET status='failed', completed_at=?, error='Development server stopped before completion' WHERE status IN ('queued','running','cancel_requested')", (_now(),))
            db.execute("DELETE FROM job_outbox WHERE run_id IN (SELECT id FROM runs WHERE status='failed')")


@asynccontextmanager
async def lifespan(_: FastAPI):
    _init_db()
    if PRODUCTION:
        from redis.asyncio import Redis
        app.state.redis = Redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=3, socket_timeout=3)
        await app.state.redis.ping()
    yield
    if PRODUCTION:
        await app.state.redis.aclose()
        database.close_pool()


app = FastAPI(title="AgentShield", version="1.0.0", description="Agent security evaluation and runtime defense platform", lifespan=lifespan,
              docs_url=None if AUTH_REQUIRED else "/docs", redoc_url=None if AUTH_REQUIRED else "/redoc",
              openapi_url=None if AUTH_REQUIRED else "/openapi.json")
allowed_hosts = [host.strip() for host in os.environ.get("AGENTSHIELD_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver" if AUTH_REQUIRED else "*").split(",") if host.strip()]
if AUTH_REQUIRED and (not allowed_hosts or "*" in allowed_hosts):
    raise RuntimeError("Authenticated deployments require AGENTSHIELD_ALLOWED_HOSTS without a wildcard.")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def request_context(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    started = time.perf_counter()

    def finish(response):
        response.headers["X-Request-ID"] = request.state.request_id
        principal = getattr(request.state, "principal", None)
        ACCESS_LOG.info(json.dumps({
            "event": "http_request", "request_id": request.state.request_id,
            "method": request.method, "path": request.url.path, "status": response.status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "organization_id": principal.organization_id if principal else None,
            "role": principal.role if principal else None,
        }, separators=(",", ":")))
        return _security_headers(response, secure=request.url.scheme == "https")

    try:
        too_large = int(request.headers.get("content-length", "0") or 0) > MAX_REQUEST_BYTES
    except ValueError:
        too_large = True
    if too_large:
        response = _error(413, "request_too_large", "Request body exceeds the 1 MiB limit.", request.state.request_id)
    elif "chunked" in request.headers.get("transfer-encoding", "").lower():
        response = _error(411, "content_length_required", "Requests with bodies must declare Content-Length.", request.state.request_id)
    elif request.url.path.startswith("/api/v1/"):
        if AUTH_REQUIRED:
            authorization = request.headers.get("authorization", "")
            scheme, _, token = authorization.partition(" ")
            try:
                remote_ip = request.client.host if request.client else "unknown"
                ip_count = await request.app.state.redis.eval(
                    "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n",
                    1, f"ratelimit:ip:{remote_ip}", 60,
                ) if PRODUCTION else 0
                if ip_count > 600:
                    response = _error(429, "rate_limited", "Request limit exceeded. Try again shortly.", request.state.request_id)
                    response.headers["Retry-After"] = "60"
                    return finish(response)
                if scheme.lower() != "bearer":
                    raise HTTPException(401, "A valid AgentShield API key is required.", headers={"WWW-Authenticate": "Bearer"})
                request.state.principal = await run_in_threadpool(authenticate, token)
            except HTTPException as exc:
                response = _error(exc.status_code, "authentication_required" if exc.status_code == 401 else "request_error", exc.detail, request.state.request_id, exc.headers)
                return finish(response)
            except Exception:
                response = _error(503, "authentication_unavailable", "Authentication is temporarily unavailable.", request.state.request_id)
                return finish(response)
        else:
            request.state.principal = Principal("default", "admin")
        if PRODUCTION:
            key = request.state.principal.key_id or "unknown"
            try:
                count = await request.app.state.redis.eval(
                    "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n",
                    1, f"ratelimit:key:{key}", 60,
                )
            except Exception:
                response = _error(503, "rate_limiter_unavailable", "Request protection is temporarily unavailable.", request.state.request_id)
                return finish(response)
            if count > 120:
                response = _error(429, "rate_limited", "Request limit exceeded. Try again shortly.", request.state.request_id)
                response.headers["Retry-After"] = "60"
                return finish(response)
        response = await call_next(request)
    else:
        response = await call_next(request)
    return finish(response)


def _security_headers(response, *, secure: bool = False):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
    if PRODUCTION and secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if PRODUCTION:
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return _error(422, "validation_error", "Request did not match the API schema.", request.state.request_id)


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
    code = {404: "not_found", 409: "conflict", 422: "validation_error"}.get(exc.status_code, "request_error")
    return _error(exc.status_code, code, detail, request.state.request_id, exc.headers)


def _error(status: int, code: str, message: str, request_id: str, headers: dict | None = None):
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}, "request_id": request_id}, headers=headers)


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetCreate(ClosedModel):
    name: str = Field(min_length=1, max_length=120)
    version: str = Field(default="1.0.0", min_length=1, max_length=40)
    owner: str = Field(default="local developer", min_length=1, max_length=120)
    environment: Literal["simulator"] = "simulator"
    runner: Literal["deterministic", "openai_reference"] = "deterministic"
    authorized: Literal[True]


class PolicyCreate(ClosedModel):
    name: str = Field(min_length=1, max_length=120)
    tool_allowlist: list[str] = Field(min_length=1, max_length=20)
    refund_approval_threshold: float = Field(default=100, ge=0, le=1_000_000, allow_inf_nan=False)
    approval_required_tools: list[str] = Field(default_factory=list, max_length=20)
    max_tool_calls: int = Field(default=5, ge=1, le=10)


class TargetPolicy(ClosedModel):
    policy_id: str | None


class EvaluationCreate(ClosedModel):
    target_id: str
    scenario_ids: list[str] | None = Field(default=None, max_length=50)


class ReplayRequest(ClosedModel):
    target_id: str | None = None


class CompareRequest(ClosedModel):
    baseline_run_id: str
    protected_run_id: str


class OrganizationCreate(ClosedModel):
    name: str = Field(min_length=1, max_length=120)


class ApiKeyCreate(ClosedModel):
    role: Literal["viewer", "operator", "admin"] = "viewer"


def _target(row) -> dict:
    return {"id": row["id"], "name": row["name"], "version": row["version"], "owner": row["owner"],
            "environment": row["environment"], "runner": row["runner"], "authorized": bool(row["authorized"]), "policy_id": row["policy_id"],
            "protected": bool(row["policy_id"]), "max_scenarios_per_run": OPENAI_MAX_SCENARIOS_PER_RUN if row["runner"] == "openai_reference" else 50,
            "created_at": row["created_at"]}


def _run(row) -> dict:
    return {"id": row["id"], "target_id": row["target_id"], "status": row["status"],
            "policy_id": row["policy_id"],
            "scenario_ids": _load(row["scenario_ids"], []), "created_at": row["created_at"],
            "started_at": row["started_at"], "completed_at": row["completed_at"],
            "summary": _load(row["summary"]), "error": row["error"]}


def _get_run(db, run_id: str, organization_id: str | None = None):
    row = db.execute("SELECT * FROM runs WHERE id=?" + (" AND organization_id=?" if organization_id else ""),
                     (run_id, organization_id) if organization_id else (run_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Evaluation run was not found.")
    return row


def _get_target(db, target_id: str, organization_id: str | None = None):
    row = db.execute("SELECT * FROM targets WHERE id=?" + (" AND organization_id=?" if organization_id else ""),
                     (target_id, organization_id) if organization_id else (target_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Target was not found.")
    return row


def _summary(executions: list[dict], requested: int, duration_ms: int) -> dict:
    counts = {verdict.lower(): sum(item["verdict"] == verdict for item in executions) for verdict in ("PASS", "FAIL", "ERROR", "INCONCLUSIVE")}
    security = [item for item in executions if item["group"] == "security" and item["verdict"] in {"PASS", "FAIL"}]
    benign = [item for item in executions if item["group"] == "benign"]
    tokens_used = sum(item["evidence"].get("usage", {}).get("total_tokens", 0) for item in executions)
    provider_model = next((item["evidence"]["model"] for item in executions if item["evidence"].get("provider") == "openai"), None)
    return {
        "total": requested, **counts,
        "adversarial_valid": len(security),
        "confirmed_violations": sum(item["verdict"] == "FAIL" for item in security),
        "attack_success_rate": round(sum(item["verdict"] == "FAIL" for item in security) / len(security), 4) if security else None,
        "benign_false_positives": sum(item["verdict"] == "FAIL" for item in benign),
        "benign_false_positive_rate": round(sum(item["verdict"] == "FAIL" for item in benign) / len(benign), 4) if benign else None,
        "duration_ms": duration_ms,
        "tokens_used": tokens_used,
        "estimated_provider_cost_usd": None if provider_model else 0.0,
        "model": provider_model,
    }


def _execute_run(run_id: str, scenario_ids: list[str], scenario_snapshots: list[dict] | None = None) -> None:
    with _connect() as db:
        run = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if run is None or run["status"] in {"completed", "cancelled"}:
            return
        if run["status"] == "cancel_requested":
            db.execute("UPDATE runs SET status='cancelled', completed_at=? WHERE id=?", (_now(), run_id))
            db.execute("DELETE FROM job_outbox WHERE run_id=?", (run_id,))
            return
        policy_row = db.execute("SELECT definition FROM policies WHERE id=?", (run["policy_id"],)).fetchone() if run["policy_id"] else None
        policy = _load(policy_row["definition"]) if policy_row else None
        target = db.execute("SELECT runner FROM targets WHERE id=?", (run["target_id"],)).fetchone()
        runner = target["runner"] if target else "deterministic"
        db.execute("UPDATE runs SET status='running', started_at=? WHERE id=?", (_now(), run_id))
        db.execute("DELETE FROM events WHERE run_id=?", (run_id,))
        db.execute("DELETE FROM executions WHERE run_id=?", (run_id,))
    if scenario_snapshots is None:
        scenario_snapshots = _load(run["scenario_snapshots"], None)
    executions: list[dict] = []
    started = time.perf_counter()
    provider_error = None
    for index, scenario_id in enumerate(scenario_ids):
        with _connect() as db:
            status = db.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()["status"]
            if status == "cancel_requested":
                summary = _summary(executions, len(scenario_ids), round((time.perf_counter() - started) * 1000))
                summary["completed"] = len(executions)
                db.execute("UPDATE runs SET status='cancelled', completed_at=?, summary=? WHERE id=?", (_now(), _json(summary), run_id))
                db.execute("DELETE FROM job_outbox WHERE run_id=?", (run_id,))
                return
        scenario = scenario_snapshots[index] if scenario_snapshots else BY_ID[scenario_id]
        execution_id = str(uuid.uuid4())
        try:
            if runner == "openai_reference" and scenario["group"] != "reliability" and scenario.get("fault") is None:
                if provider_error:
                    raise RuntimeError(provider_error)
                from .openai_agent import evaluate_openai_scenario
                result = evaluate_openai_scenario(scenario, policy)
            else:
                result = evaluate_scenario(scenario, policy)
        except SoftTimeLimitExceeded:
            raise
        except Exception as exc:
            error_type = provider_error or type(exc).__name__
            RUN_LOG.error(json.dumps({"event": "scenario_runner_error", "run_id": run_id, "scenario_id": scenario_id, "error_type": error_type}, separators=(",", ":")))
            event = {"sequence": 1, "type": "runner_error", "data": {"message": "Scenario runner failed; see worker logs.", "run_id": run_id}}
            result = {"verdict": "ERROR", "events": [event], "evidence": {"error_type": error_type, **({"provider": "openai", "model": os.environ.get("AGENTSHIELD_OPENAI_MODEL", "gpt-6-astra")} if runner == "openai_reference" else {})}, "violations": [], "executed_calls": 0}
            if runner == "openai_reference" and scenario["group"] != "reliability":
                provider_error = type(exc).__name__
        if result["evidence"].get("final_response_error_type"):
            provider_error = result["evidence"]["final_response_error_type"]
        executions.append({"id": execution_id, "scenario_id": scenario_id, "group": scenario["group"],
                           "verdict": result["verdict"], "violations": result["violations"], "evidence": result["evidence"]})
        with _connect() as db:
            db.execute("""INSERT INTO executions
                (id,run_id,scenario_id,scenario_version,verdict,evidence,violations,scenario_snapshot)
                VALUES (?,?,?,?,?,?,?,?)""",
                (execution_id, run_id, scenario_id, scenario["version"], result["verdict"], _json(result["evidence"]),
                 _json(result["violations"]), json.dumps(scenario, ensure_ascii=False, separators=(",", ":"))))
            db.executemany("INSERT INTO events (run_id, execution_id, scenario_id, sequence, event_type, data) VALUES (?, ?, ?, ?, ?, ?)",
                           [(run_id, execution_id, scenario_id, event["sequence"], event["type"], _json(event["data"])) for event in result["events"]])
    summary = _summary(executions, len(scenario_ids), round((time.perf_counter() - started) * 1000))
    with _connect() as db:
        result = db.execute("UPDATE runs SET status='completed', completed_at=?, summary=? WHERE id=? AND status='running'", (_now(), _json(summary), run_id))
        if getattr(result, "rowcount", 0) == 0:
            db.execute("UPDATE runs SET status='cancelled', completed_at=?, summary=? WHERE id=? AND status='cancel_requested'", (_now(), _json(summary), run_id))
        db.execute("DELETE FROM job_outbox WHERE run_id=?", (run_id,))


def _execute_run_from_id(run_id: str) -> None:
    with _connect() as db:
        run = db.execute("SELECT scenario_ids,scenario_snapshots FROM runs WHERE id=?", (run_id,)).fetchone()
    if run:
        _execute_run(run_id, _load(run["scenario_ids"], []), _load(run["scenario_snapshots"], None))


def _enqueue(run_id: str, scenario_ids: list[str], snapshots: list[dict], background: BackgroundTasks) -> None:
    if PRODUCTION:
        from .worker import run_evaluation
        try:
            run_evaluation.delay(run_id)
            with _connect() as db:
                db.execute("UPDATE job_outbox SET sent_at=? WHERE run_id=?", (_now(), run_id))
        except Exception:
            pass
    else:
        background.add_task(_execute_run, run_id, scenario_ids, snapshots)


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/workbench", include_in_schema=False)
def workbench():
    return FileResponse(STATIC_DIR / "workbench.html")


@app.get("/health")
def health():
    return {"status": "ok", "mode": "production" if PRODUCTION else "development"}


@app.get("/health/ready", include_in_schema=False)
async def readiness():
    try:
        with _connect() as db:
            db.execute("SELECT 1").fetchone()
        if PRODUCTION:
            await app.state.redis.ping()
    except Exception:
        raise HTTPException(503, "A required service is unavailable.")
    return {"status": "ready"}


@app.get("/api/v1/auth/me")
def whoami(request: Request):
    principal = request.state.principal
    return {"organization_id": principal.organization_id, "role": principal.role}


@app.post("/api/v1/organizations", status_code=201)
def create_organization(body: OrganizationCreate, request: Request):
    require_role(request.state.principal, "platform_admin")
    organization_id = str(uuid.uuid4())
    with _connect() as db:
        db.execute("INSERT INTO organizations (id,name,created_at) VALUES (?, ?, ?)", (organization_id, body.name, _now()))
        _seed_org(db, organization_id, body.name)
        key_id, token = issue_key(db, organization_id, "admin")
    return {"id": organization_id, "name": body.name, "admin_key": token, "key_id": key_id,
            "message": "Save this key now; it is shown only once."}


@app.get("/api/v1/platform/api-keys")
def list_platform_keys(request: Request):
    require_role(request.state.principal, "platform_admin")
    with _connect() as db:
        rows = db.execute("SELECT id,prefix,created_at,revoked_at FROM api_keys WHERE organization_id IS NULL ORDER BY created_at DESC").fetchall()
    return {"items": [dict(row) for row in rows]}


@app.post("/api/v1/platform/api-keys", status_code=201)
def create_platform_key(request: Request):
    require_role(request.state.principal, "platform_admin")
    with _connect() as db:
        key_id, token = issue_key(db, None, "platform_admin")
    return {"id": key_id, "key": token, "message": "Save this key now; it is shown only once."}


@app.delete("/api/v1/platform/api-keys/{key_id}", status_code=204)
def revoke_platform_key(key_id: str, request: Request):
    require_role(request.state.principal, "platform_admin")
    if request.state.principal.key_id == key_id:
        raise HTTPException(409, "Use a different platform key to revoke this key.")
    with _connect() as db:
        result = db.execute("UPDATE api_keys SET revoked_at=? WHERE id=? AND organization_id IS NULL AND revoked_at IS NULL", (_now(), key_id))
        if getattr(result, "rowcount", 0) == 0:
            raise HTTPException(404, "Platform key was not found.")
    return None


@app.get("/api/v1/api-keys")
def list_api_keys(request: Request):
    organization_id = _require(request, "admin")
    with _connect() as db:
        rows = db.execute("SELECT id,prefix,role,created_at,revoked_at FROM api_keys WHERE organization_id=? ORDER BY created_at DESC", (organization_id,)).fetchall()
    return {"items": [dict(row) for row in rows]}


@app.post("/api/v1/api-keys", status_code=201)
def create_api_key(body: ApiKeyCreate, request: Request):
    organization_id = _require(request, "admin")
    with _connect() as db:
        key_id, token = issue_key(db, organization_id, body.role)
    return {"id": key_id, "role": body.role, "key": token, "message": "Save this key now; it is shown only once."}


@app.delete("/api/v1/api-keys/{key_id}", status_code=204)
def revoke_api_key(key_id: str, request: Request):
    organization_id = _require(request, "admin")
    if request.state.principal.key_id == key_id:
        raise HTTPException(409, "Use a different admin key to revoke this key.")
    with _connect() as db:
        result = db.execute("UPDATE api_keys SET revoked_at=? WHERE id=? AND organization_id=? AND revoked_at IS NULL", (_now(), key_id, organization_id))
        if getattr(result, "rowcount", 0) == 0:
            raise HTTPException(404, "API key was not found.")
    return None


@app.get("/api/v1/targets")
def list_targets(request: Request):
    organization_id = _org_id(request)
    with _connect() as db:
        rows = db.execute("SELECT * FROM targets WHERE organization_id=? ORDER BY CASE runner WHEN 'deterministic' THEN 0 ELSE 1 END, created_at, name", (organization_id,)).fetchall()
    return {"items": [_target(row) for row in rows]}


@app.post("/api/v1/targets", status_code=201)
def create_target(body: TargetCreate, request: Request):
    organization_id = _require(request, "admin")
    target_id = str(uuid.uuid4())
    with _connect() as db:
        db.execute("INSERT INTO targets (id,organization_id,name,version,owner,environment,authorized,policy_id,created_at,runner) VALUES (?,?,?,?,?,?,?,NULL,?,?)",
                   (target_id, organization_id, body.name, body.version, body.owner, body.environment, True, _now(), body.runner))
        row = _get_target(db, target_id, organization_id)
    return _target(row)


@app.post("/api/v1/targets/{target_id}/validate")
def validate_target(target_id: str, request: Request):
    organization_id = _org_id(request)
    with _connect() as db:
        target = _get_target(db, target_id, organization_id)
    ready = target["runner"] != "openai_reference" or bool(os.environ.get("OPENAI_API_KEY", "").strip())
    return {"target_id": target_id, "status": "healthy" if ready else "configuration_required", "authorized": bool(target["authorized"]),
            "runner_ready": ready,
            "environment": "simulator", "runner": target["runner"], "tool_manifest": sorted(TOOL_SCHEMAS)}


@app.get("/api/v1/scenarios")
def list_scenarios(category: str | None = None, group: Literal["security", "benign", "reliability"] | None = None,
                   q: str | None = Query(default=None, max_length=120)):
    items = SCENARIOS
    if category:
        items = [item for item in items if item["category"] == category]
    if group:
        items = [item for item in items if item["group"] == group]
    if q:
        query = q.casefold()
        items = [item for item in items if query in (item["id"] + " " + item["title"] + " " + item["category"]).casefold()]
    return {"items": [redact(item) for item in get_scenarios([item["id"] for item in items])], "total": len(items)}


@app.get("/api/v1/policies")
def list_policies(request: Request):
    organization_id = _org_id(request)
    with _connect() as db:
        rows = db.execute("SELECT * FROM policies WHERE organization_id=? ORDER BY created_at", (organization_id,)).fetchall()
    return {"items": [{"id": row["id"], "name": row["name"], "version": row["version"],
                       "definition": _load(row["definition"]), "created_at": row["created_at"]} for row in rows]}


@app.post("/api/v1/policies", status_code=201)
def create_policy(body: PolicyCreate, request: Request):
    organization_id = _require(request, "admin")
    from .engine import TOOL_SCHEMAS
    if len(set(body.tool_allowlist)) != len(body.tool_allowlist) or len(set(body.approval_required_tools)) != len(body.approval_required_tools):
        raise HTTPException(422, "Policy tool lists cannot contain duplicates.")
    if not set(body.tool_allowlist + body.approval_required_tools).issubset(TOOL_SCHEMAS):
        raise HTTPException(422, "Policy references a tool outside the local simulator manifest.")
    definition = body.model_dump(exclude={"name"})
    policy_id = str(uuid.uuid4())
    with _connect() as db:
        version = db.execute("SELECT COALESCE(MAX(version),0)+1 FROM policies WHERE organization_id=?", (organization_id,)).fetchone()[0]
        db.execute("INSERT INTO policies (id,organization_id,name,version,definition,created_at) VALUES (?, ?, ?, ?, ?, ?)",
                   (policy_id, organization_id, body.name, version, _json(definition), _now()))
    return {"id": policy_id, "name": body.name, "version": version, "definition": definition}


@app.post("/api/v1/targets/{target_id}/policy")
def assign_policy(target_id: str, body: TargetPolicy, request: Request):
    organization_id = _require(request, "admin")
    with _connect() as db:
        _get_target(db, target_id, organization_id)
        if body.policy_id is not None and not db.execute("SELECT 1 FROM policies WHERE id=? AND organization_id=?", (body.policy_id, organization_id)).fetchone():
            raise HTTPException(404, "Policy was not found.")
        db.execute("UPDATE targets SET policy_id=? WHERE id=? AND organization_id=?", (body.policy_id, target_id, organization_id))
        return _target(_get_target(db, target_id, organization_id))


@app.post("/api/v1/evaluations", status_code=202)
def create_evaluation(body: EvaluationCreate, request: Request, background: BackgroundTasks, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
    organization_id = _require(request, "admin", "operator")
    if idempotency_key and (len(idempotency_key) > 128 or not idempotency_key.strip()):
        raise HTTPException(422, "Idempotency-Key must contain 1 to 128 characters.")
    run_id = str(uuid.uuid4())
    with _connect() as db:
        target = _get_target(db, body.target_id, organization_id)
        if not target["authorized"] or target["environment"] != "simulator":
            raise HTTPException(403, "Only explicitly authorized local simulator targets can run evaluations.")
        if target["runner"] == "openai_reference" and not os.environ.get("OPENAI_API_KEY", "").strip():
            raise HTTPException(503, "OpenAI reference targets require OPENAI_API_KEY.")
        if body.scenario_ids is None and target["runner"] == "openai_reference":
            by_group = {group: [item["id"] for item in SCENARIOS if item["group"] == group] for group in ("security", "benign", "reliability")}
            scenario_ids = by_group["security"][:6] + by_group["benign"][:2] + by_group["reliability"][:2]
        else:
            scenario_ids = body.scenario_ids if body.scenario_ids is not None else [item["id"] for item in SCENARIOS]
        if not scenario_ids:
            raise HTTPException(422, "Select at least one scenario.")
        if target["runner"] == "openai_reference" and len(scenario_ids) > OPENAI_MAX_SCENARIOS_PER_RUN:
            raise HTTPException(422, f"OpenAI reference runs are limited to {OPENAI_MAX_SCENARIOS_PER_RUN} scenarios.")
        if len(set(scenario_ids)) != len(scenario_ids):
            raise HTTPException(422, "Scenario IDs cannot be repeated.")
        unknown = set(scenario_ids) - set(BY_ID)
        if unknown:
            raise HTTPException(422, "One or more scenario IDs are not in the versioned local catalog.")
        scenario_snapshots = [BY_ID[scenario_id] for scenario_id in scenario_ids]
        if idempotency_key:
            existing = db.execute("SELECT * FROM runs WHERE organization_id=? AND idempotency_key=?", (organization_id, idempotency_key)).fetchone()
            if existing:
                if existing["target_id"] != body.target_id or _load(existing["scenario_ids"], []) != scenario_ids:
                    raise HTTPException(409, "Idempotency-Key was already used with a different evaluation request.")
                return _run(existing)
        db.execute("""INSERT INTO runs (id,organization_id,target_id,policy_id,status,scenario_ids,scenario_snapshots,idempotency_key,created_at)
                      VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
                   (run_id, organization_id, body.target_id, target["policy_id"], _json(scenario_ids), json.dumps(scenario_snapshots, ensure_ascii=False, separators=(",", ":")), idempotency_key, _now()))
        created = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if created is None:
            existing = db.execute("SELECT * FROM runs WHERE organization_id=? AND idempotency_key=?", (organization_id, idempotency_key)).fetchone()
            if existing and existing["target_id"] == body.target_id and _load(existing["scenario_ids"], []) == scenario_ids:
                return _run(existing)
            raise HTTPException(409, "Idempotency-Key was already used with a different evaluation request.")
        db.execute("INSERT INTO job_outbox (run_id,created_at) VALUES (?,?)", (run_id, _now()))
    _enqueue(run_id, scenario_ids, scenario_snapshots, background)
    return {"id": run_id, "target_id": body.target_id, "status": "queued", "scenario_ids": scenario_ids}


@app.get("/api/v1/evaluations")
def list_evaluations(request: Request, limit: int = Query(20, ge=1, le=100)):
    organization_id = _org_id(request)
    with _connect() as db:
        rows = db.execute("SELECT * FROM runs WHERE organization_id=? ORDER BY created_at DESC LIMIT ?", (organization_id, limit)).fetchall()
    return {"items": [_run(row) for row in rows]}


@app.get("/api/v1/evaluations/{run_id}")
def get_evaluation(run_id: str, request: Request):
    organization_id = _org_id(request)
    with _connect() as db:
        return _run(_get_run(db, run_id, organization_id))


@app.post("/api/v1/evaluations/{run_id}/cancel")
def cancel_evaluation(run_id: str, request: Request):
    organization_id = _require(request, "admin", "operator")
    with _connect() as db:
        run = _get_run(db, run_id, organization_id)
        if run["status"] == "queued":
            result = db.execute("UPDATE runs SET status='cancelled', completed_at=? WHERE id=? AND status='queued'", (_now(), run_id))
            if getattr(result, "rowcount", 0):
                db.execute("DELETE FROM job_outbox WHERE run_id=?", (run_id,))
            else:
                db.execute("UPDATE runs SET status='cancel_requested' WHERE id=? AND status='running'", (run_id,))
        elif run["status"] == "running":
            db.execute("UPDATE runs SET status='cancel_requested' WHERE id=? AND status='running'", (run_id,))
        elif run["status"] != "cancel_requested":
            raise HTTPException(409, "Only queued or running evaluations can be cancelled.")
        return _run(_get_run(db, run_id, organization_id))


@app.get("/api/v1/evaluations/{run_id}/events")
def list_events(run_id: str, request: Request, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500)):
    organization_id = _org_id(request)
    with _connect() as db:
        _get_run(db, run_id, organization_id)
        rows = db.execute("SELECT * FROM events WHERE run_id=? ORDER BY id LIMIT ? OFFSET ?", (run_id, limit, offset)).fetchall()
        total = db.execute("SELECT COUNT(*) FROM events WHERE run_id=?", (run_id,)).fetchone()[0]
    return {"items": [{"scenario_id": row["scenario_id"], "sequence": row["sequence"], "type": row["event_type"], "data": _load(row["data"])} for row in rows], "total": total, "offset": offset, "limit": limit}


@app.get("/api/v1/evaluations/{run_id}/findings")
def list_findings(run_id: str, request: Request):
    organization_id = _org_id(request)
    with _connect() as db:
        _get_run(db, run_id, organization_id)
        rows = db.execute("SELECT * FROM executions WHERE run_id=? AND verdict='FAIL' ORDER BY scenario_id", (run_id,)).fetchall()
    items = []
    for row in rows:
        scenario = _load(row["scenario_snapshot"]) or BY_ID[row["scenario_id"]]
        violations = _load(row["violations"], [])
        items.append({"scenario_id": row["scenario_id"], "scenario": scenario["title"], "severity": scenario["severity"],
                      "category": scenario["category"], "violations": violations,
                      "remediation": list(dict.fromkeys(REMEDIATIONS[key] for key in violations if key in REMEDIATIONS)),
                      "evidence": _load(row["evidence"], {})})
    return {"items": items}


@app.post("/api/v1/evaluations/{run_id}/replay", status_code=202)
def replay_evaluation(run_id: str, request: Request, background: BackgroundTasks, body: ReplayRequest = ReplayRequest()):
    organization_id = _require(request, "admin", "operator")
    with _connect() as db:
        original = _get_run(db, run_id, organization_id)
        if original["status"] != "completed":
            raise HTTPException(409, "Only completed evaluations can be replayed.")
        target_id = body.target_id or original["target_id"]
        target = _get_target(db, target_id, organization_id)
        if not target["authorized"] or target["environment"] != "simulator":
            raise HTTPException(403, "Only authorized local simulator targets can run evaluations.")
        if target["runner"] == "openai_reference" and not os.environ.get("OPENAI_API_KEY", "").strip():
            raise HTTPException(503, "OpenAI reference targets require OPENAI_API_KEY.")
        scenario_ids = _load(original["scenario_ids"], [])
        if target["runner"] == "openai_reference" and len(scenario_ids) > OPENAI_MAX_SCENARIOS_PER_RUN:
            raise HTTPException(422, f"OpenAI reference runs are limited to {OPENAI_MAX_SCENARIOS_PER_RUN} scenarios.")
        scenario_snapshots = _load(original["scenario_snapshots"], None)
        if not scenario_snapshots:
            stored = {row["scenario_id"]: _load(row["scenario_snapshot"]) for row in db.execute("SELECT scenario_id,scenario_snapshot FROM executions WHERE run_id=?", (run_id,))}
            scenario_snapshots = [stored.get(scenario_id) or BY_ID[scenario_id] for scenario_id in scenario_ids]
        policy_id = original["policy_id"] if target_id == original["target_id"] else target["policy_id"]
        new_id = str(uuid.uuid4())
        db.execute("INSERT INTO runs (id,organization_id,target_id,policy_id,status,scenario_ids,scenario_snapshots,created_at) VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)",
                   (new_id, organization_id, target_id, policy_id, _json(scenario_ids), json.dumps(scenario_snapshots, ensure_ascii=False, separators=(",", ":")), _now()))
        db.execute("INSERT INTO job_outbox (run_id,created_at) VALUES (?,?)", (new_id, _now()))
    _enqueue(new_id, scenario_ids, scenario_snapshots, background)
    return {"id": new_id, "target_id": target_id, "status": "queued", "scenario_ids": scenario_ids, "replayed_from": run_id}


@app.post("/api/v1/evaluations/compare")
def compare_evaluations(body: CompareRequest, request: Request):
    organization_id = _org_id(request)
    with _connect() as db:
        baseline = _get_run(db, body.baseline_run_id, organization_id)
        protected = _get_run(db, body.protected_run_id, organization_id)
        if baseline["status"] != "completed" or protected["status"] != "completed":
            raise HTTPException(409, "Both evaluations must complete before comparison.")
        baseline_target = _get_target(db, baseline["target_id"], organization_id)
        protected_target = _get_target(db, protected["target_id"], organization_id)
        if baseline_target["runner"] != protected_target["runner"]:
            raise HTTPException(422, "Both evaluations must use the same agent runner.")
        if baseline_target["runner"] == "openai_reference" and _load(baseline["summary"], {}).get("model") != _load(protected["summary"], {}).get("model"):
            raise HTTPException(422, "OpenAI evaluations must use the same model.")
        if baseline["policy_id"] is not None or protected["policy_id"] is None:
            raise HTTPException(422, "Comparison requires a guard-off baseline and a guard-on evaluation.")
        baseline_scenarios = set(_load(baseline["scenario_ids"], []))
        protected_scenarios = set(_load(protected["scenario_ids"], []))
        if baseline_scenarios != protected_scenarios:
            raise HTTPException(422, "Both evaluations must use the same scenarios.")
        left = {row["scenario_id"]: row["verdict"] for row in db.execute("SELECT scenario_id, verdict FROM executions WHERE run_id=?", (body.baseline_run_id,))}
        right = {row["scenario_id"]: row["verdict"] for row in db.execute("SELECT scenario_id, verdict FROM executions WHERE run_id=?", (body.protected_run_id,))}
    if set(left) != baseline_scenarios or set(right) != protected_scenarios:
        raise HTTPException(409, "Completed evaluations must contain a result for every selected scenario.")
    scenarios = sorted(baseline_scenarios)
    scored = {"PASS", "FAIL"}
    return {"baseline_run_id": body.baseline_run_id, "protected_run_id": body.protected_run_id,
            "improved": [scenario_id for scenario_id in scenarios if left.get(scenario_id) == "FAIL" and right.get(scenario_id) == "PASS"],
            "regressed": [scenario_id for scenario_id in scenarios if left.get(scenario_id) == "PASS" and right.get(scenario_id) == "FAIL"],
            "unchanged": [scenario_id for scenario_id in scenarios if left.get(scenario_id) == right.get(scenario_id) and left.get(scenario_id) in scored],
            "unscored": [scenario_id for scenario_id in scenarios if left.get(scenario_id) not in scored or right.get(scenario_id) not in scored],
            "verdicts": {scenario_id: {"baseline": left.get(scenario_id), "protected": right.get(scenario_id)} for scenario_id in scenarios}}


@app.get("/api/v1/evaluations/{run_id}/report")
def evaluation_report(run_id: str, request: Request, format: Literal["json", "markdown"] = "json"):
    organization_id = _org_id(request)
    with _connect() as db:
        run = _get_run(db, run_id, organization_id)
        target = _get_target(db, run["target_id"], organization_id)
        policy_row = db.execute("SELECT id,name,version,definition FROM policies WHERE id=? AND organization_id=?", (run["policy_id"], organization_id)).fetchone() if run["policy_id"] else None
        rows = db.execute("SELECT * FROM executions WHERE run_id=? ORDER BY scenario_id", (run_id,)).fetchall()
    target_snapshot = _target(target)
    target_snapshot["policy_id"] = run["policy_id"]
    target_snapshot["protected"] = bool(run["policy_id"])
    executions = []
    for row in rows:
        scenario = _load(row["scenario_snapshot"]) or BY_ID[row["scenario_id"]]
        violations = _load(row["violations"], [])
        executions.append({"scenario_id": row["scenario_id"], "title": scenario["title"], "group": scenario["group"],
                           "category": scenario["category"], "verdict": row["verdict"], "violations": violations,
                           "remediation": list(dict.fromkeys(REMEDIATIONS[key] for key in violations if key in REMEDIATIONS)),
                           "evidence": _load(row["evidence"], {})})
    report = {"run_id": run_id, "target": target_snapshot, "status": run["status"], "created_at": run["created_at"],
              "policy": ({"id": policy_row["id"], "name": policy_row["name"], "version": policy_row["version"],
                          "definition": _load(policy_row["definition"])} if policy_row else None),
              "summary": _load(run["summary"], {}), "findings": [item for item in executions if item["verdict"] == "FAIL"],
              "executions": executions}
    if format == "json":
        return report
    summary = report["summary"]
    policy_label = f"{policy_row['name']} v{policy_row['version']}" if policy_row else "Guard disabled"
    provider_cost = summary.get("estimated_provider_cost_usd")
    provider_cost_label = f"${provider_cost:.2f}" if provider_cost is not None else "not estimated"
    target_name = target["name"].replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    lines = [f"# AgentShield evaluation report", "", f"- Run: `{run_id}`", f"- Target: {target_name}", f"- Policy: {policy_label}", f"- Status: {run['status']}",
             f"- Pass: {summary.get('pass', 0)} · Fail: {summary.get('fail', 0)} · Error: {summary.get('error', 0)} · Inconclusive: {summary.get('inconclusive', 0)}",
             f"- Duration: {summary.get('duration_ms', 0)} ms · Model: {summary.get('model') or 'deterministic'} · Tokens: {summary.get('tokens_used', 0)} · Estimated provider cost: {provider_cost_label}", "", "## Findings", ""]
    if report["findings"]:
        for item in report["findings"]:
            lines.append(f"- **{item['scenario_id']} — {item['title']}**: {', '.join(item['violations']) or 'deterministic violation'}")
            lines.extend(f"  - Remediation: {recommendation}" for recommendation in item["remediation"])
    else:
        lines.append("No confirmed violations.")
    lines += ["", "## Scenario outcomes", "", "| Scenario | Group | Verdict |", "|---|---|---|"]
    lines.extend(f"| {item['scenario_id']} — {item['title']} | {item['group']} | {item['verdict']} |" for item in executions)
    return PlainTextResponse("\n".join(lines), media_type="text/markdown")
