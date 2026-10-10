# AgentShield portfolio diagrams

Two diagrams explain the current implementation from different angles: system boundaries and dependencies, then one evaluation request from submission through stored evidence. The SVGs are vector exports; the PNGs are high-resolution portfolio previews.

## Files

| Asset | Purpose |
| --- | --- |
| `system-architecture.svg` / `.png` | Runtime components, boundaries, storage, and communication paths |
| `execution-flow.svg` / `.png` | Request validation, dispatch, policy decisions, failure handling, and results |
| `system-architecture.mmd` | Editable Mermaid architecture source |
| `execution-flow.mmd` | Editable Mermaid runtime-flow source |
| `render_diagrams.py` | Recreates the polished SVG and PNG layout with Matplotlib |

The Mermaid files capture the same components and paths as the exports. The Python renderer controls the portfolio layout; edit both sources when changing structure. SVG files remain editable as vector artwork in tools such as Figma or Inkscape.

To regenerate the exports in an environment with Matplotlib and Pillow installed:

```powershell
python docs/portfolio-diagrams/render_diagrams.py
```

The renderer checks that each SVG is well-formed, each PNG decodes, and the PNG width is at least 2,200 pixels. It changes no application files or dependencies.

## 01 — System architecture

The architecture diagram separates the external client and deployment-specific TLS proxy from the Docker Compose runtime. Inside the runtime, FastAPI handles REST and static pages; the evaluation API validates target and scenario selections, applies idempotency, stores a run and outbox row, then returns a run ID. Celery dispatch and workers move the longer evaluation work out of the request path.

### Main components and communication

- **Workbench and REST clients:** The browser workbench is static HTML, CSS, and JavaScript served by the API. It submits evaluations and reads run status, findings, events, and reports. Its API key is held in browser `sessionStorage`.
- **TLS reverse proxy:** TLS and public routing sit in the deployment environment, outside the provided Compose services. The API binds to loopback.
- **FastAPI / Uvicorn:** Handles REST endpoints and static pages. API keys are hashed at rest; role checks distinguish viewers, operators, admins, and platform admins. Strict Pydantic models reject extra fields. Middleware applies trusted-host checks, a 1 MiB body limit, request IDs, security headers, and rate limits.
- **Evaluation API:** Accepts at most 50 known scenario IDs for an authorized simulator target. It saves the run, scenario snapshots, policy reference, and job-outbox record in one PostgreSQL transaction. An idempotency key with the same request returns the existing run; a conflicting request returns 409.
- **PostgreSQL 16:** Production source of truth for organizations, keys, policies, targets, runs, scenario snapshots, executions, events, and the job outbox. Local development uses SQLite through the same database adapter.
- **Redis 7 and Celery:** Redis is the Celery broker and holds API rate-limit counters and per-run locks. In production, the API tries to enqueue immediately. Celery Beat scans unsent outbox rows every 10 seconds and republishes pending jobs. The worker uses late acknowledgements, a Redis run lock, bounded retries, and task time limits.
- **Deterministic evaluator:** Uses versioned local scenarios and a fresh in-memory fixture state for each case. Before a proposed tool action can affect that state, checks cover the local tool manifest, argument schema, tenant scope, approval tokens, and call budgets. Postcondition checks detect forbidden state changes and secret disclosure.
- **Operations:** JSON access logs include request IDs. `/health` is a liveness check; `/health/ready` checks PostgreSQL and Redis.

### Technology fit and trade-offs

The code establishes the current roles of FastAPI, PostgreSQL, Redis, and Celery, but it does not record the historical reasons they were selected. Their present fit is clear: FastAPI provides the HTTP layer, PostgreSQL stores durable tenant-scoped records and the transactional outbox, Redis supports broker/lock/rate-limit state, and Celery runs evaluations outside the request handler. SQLite and FastAPI background tasks keep local development lightweight.

The outbox makes run creation and job intent atomic in PostgreSQL. Immediate enqueue reduces dispatch delay; Beat provides a recovery path for unsent rows. The trade-off is more operational components to monitor. Tenant isolation is enforced by organization-scoped application queries; PostgreSQL row-level security is not configured.

### Security and reliability present in the code

- Production API-key authentication, role checks, hashed key storage, and organization scoping.
- Strict request validation, simulator-only target registration, trusted-host checks, body-size limit, and production Redis-backed rate limits of 120 requests/minute per key and 600/minute per source IP.
- Tool schema, allowlist, tenant, approval, and call-budget checks before a protected fixture action.
- Redaction of emails and synthetic secrets from stored events and evidence. The evaluator checks raw output before redaction so a leak can still be recorded as a finding.
- Atomic run/outbox writes, periodic pending-outbox dispatch, late worker acknowledgement, duplicate-run locking, bounded exponential retries, task time limits, and cancellation checks between cases.

### Current scope and limitations

AgentShield provides a deterministic runner and an optional OpenAI Responses API reference runner. The reference runner sends built-in synthetic scenario text to one configured model, observes at most one strict function call per case, checks it against policy, applies permitted calls to isolated in-memory fixture state, and asks the model for one final response. It does not connect to a user's live agent, external target, or real payment/email/database tools. The catalog contains 50 versioned cases; OpenAI runs are limited to 10. Results describe the selected runner and synthetic cases, not the security of a customer's deployed agent.

The service emits logs and health checks but does not ship an OpenTelemetry exporter, metrics backend, alert routing, or automated backup schedule. Rate limits are fixed in the current code. Tenant boundaries are enforced in application queries rather than database RLS. PostgreSQL migrations 1 and 2 create a new schema and add the runner field to existing AgentShield databases; they do not migrate the earlier local SQLite schema.

## 02 — End-to-end execution flow

The flow diagram follows `POST /api/v1/evaluations` through authorization, durable scheduling, scenario evaluation, and report retrieval.

1. **Receive and authorize.** The request passes trusted-host, body-size, API-key, role, and rate-limit checks. Missing/invalid credentials return 401; insufficient permissions return 403.
2. **Validate and deduplicate.** Strict request models, target authorization, and known scenario IDs are checked. Invalid payloads return 422. A repeated idempotency key with the same body returns its existing run; a changed body conflicts with 409.
3. **Commit and acknowledge.** PostgreSQL stores the run, policy reference, scenario snapshots, and outbox row in one transaction. The API returns 202 with a run ID. The workbench polls for completion.
4. **Dispatch work.** Production uses Celery through Redis. The API attempts immediate enqueue; Beat republishes any unsent outbox rows every 10 seconds. Local development uses FastAPI `BackgroundTasks` instead.
5. **Load and evaluate.** The worker acquires a per-run Redis lock, loads stored snapshots and policy, then evaluates each case against fresh fixture state. The policy gate checks schema, allowlist, tenant, approval, and tool-call budget before an action can run. A denied action is skipped and its reason is recorded.
6. **Check, redact, and persist.** Outcome checks inspect fixture state and raw output before evidence is redacted and written. Each case receives `PASS`, `FAIL`, `ERROR`, or `INCONCLUSIVE`; a runner exception becomes error evidence and does not prevent later cases from running. Infrastructure failures use bounded Celery retries; exhaustion marks the run `FAILED`.
7. **Return results.** The workbench retrieves run status, findings, events, and reports through REST endpoints.

### 30-second explanation

AgentShield is a multi-tenant evaluation service for checking security and reliability scenarios against tool proposals. FastAPI validates and authorizes a run, then commits its scenario snapshots and outbox record to PostgreSQL. Celery workers evaluate deterministic proposals or one OpenAI reference model action per case using explicit policy checks and isolated fixture state, with Redis providing the broker and run locks. The service stores redacted evidence and findings for the workbench. OpenAI results can vary between runs and do not describe a customer's agent or live tools.

### Two-minute explanation

An operator submits a run from the browser workbench or REST API. The API enforces key authentication and role permissions, strict request validation, an authorized simulator target, and a bounded list of known scenario IDs. An idempotency key makes safe retries predictable. The API then commits the run, versioned scenario snapshots, policy reference, and job-outbox record together in PostgreSQL before returning 202.

In production, the API tries to publish a Celery task through Redis. If that publish does not complete, Celery Beat scans the outbox every 10 seconds and republishes unsent jobs. Workers use late acknowledgements, a per-run Redis lock, bounded exponential retries, and execution time limits. A worker loads the stored snapshots and evaluates each case against fresh fixture state. Proposed actions pass through checks for tool schema, allowlist, tenant, scenario-scoped approval, and call budget; a denied action is skipped and recorded. The evaluator checks resulting state and raw output for violations, then redacts events and evidence before storage. A runner exception becomes an error result for that case while the remaining cases continue. Infrastructure failures retry and eventually set the run to failed if exhausted. The workbench polls and reads the persisted status, findings, events, and reports.

The important boundary is scope: deterministic runs use seeded proposals, while the optional OpenAI reference runner uses model-generated proposals and final responses. Both use synthetic fixtures; neither connects to a customer's live agent or external tools. The architecture still exercises tenant-scoped APIs, an outbox, async workers, policy checks, idempotency, retries, and auditable evidence, but benchmark outcomes should not be generalized beyond the configured runner and implemented fixtures.

### Interview questions

**1. How do you avoid losing an evaluation between database commit and queue publication?**  
The run and outbox row commit in one PostgreSQL transaction. The API attempts immediate Celery enqueue, while Beat periodically republishes rows still marked unsent. Late acknowledgement and bounded worker retry cover worker interruptions; a per-run Redis lock protects against duplicate delivery.

**2. What prevents a scenario from exercising an unsafe tool call?**  
The evaluator checks the local tool manifest, argument schema, tenant, scenario-scoped approval token, and call budget before changing fixture state. A denied call is skipped and traced. Postcondition checks independently inspect the resulting fixture state for forbidden changes.

**3. Does this evaluate a live LLM or agent?**  
The optional OpenAI reference target evaluates one configured model against synthetic scenarios and tools. It does not connect to a customer's agent or live tools, and model output can vary between runs.

**4. Why save scenario snapshots and policy references with a run?**  
The worker evaluates stored snapshots rather than reconstructing a run from whatever is currently in the catalog. Replay uses the stored scenario versions and policy reference, which gives the run a stable audit context.

**5. What happens when a worker fails?**  
Celery tasks use late acknowledgement, up to five retries with exponential backoff capped at 30 seconds, and soft/hard time limits. A Redis per-run lock handles duplicate delivery. If infrastructure retries are exhausted, the run is marked failed; a runner exception is recorded as an error result for that case and the worker continues with later cases.

## Validation summary

Sources inspected: `agentshield/app.py`, `auth.py`, `db.py`, `engine.py`, `scenarios.py`, and `worker.py`; `static/app.js`; `README.md`; `docs/architecture.md`; `docs/operations.md`; `Dockerfile`; `docker-compose.yml`; and `requirements.txt`.

The architecture boundaries, API controls, data stores, job outbox, worker retry/lock behavior, policy gate, result handling, and observability labels were checked against those sources. The SVG and PNG exports were rendered and visually inspected. The renderer verifies valid SVG markup, decodable PNGs, and high-resolution PNG width. The Mermaid sources were reviewed against the exports but were not run through a Mermaid renderer in this environment.
