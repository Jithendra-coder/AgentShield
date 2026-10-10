# AgentShield — Project Data for Architecture and Flow Diagrams

**Project name:** AgentShield  
**Project descriptor:** AI Agent Security, Red-Team Evaluation & Runtime Defense Platform  
**Document purpose:** Source data for portfolio explanations and future diagram revisions. This is a text brief; it contains no diagram exports.

## 1. Project summary

AgentShield is a multi-tenant service for running security and reliability evaluations against agent-style tool proposals. An authorized user selects a deterministic or OpenAI reference target, policy, and versioned scenarios. The service runs the cases, checks proposed actions and resulting state, and stores findings and redacted evidence.

The deterministic target uses seeded proposals. The optional OpenAI reference target calls the configured Responses API model for a tool proposal, checks and applies at most one action through the same policy and isolated in-memory fixture, then makes one final response call if a tool call was proposed. Scenario text and synthetic tool results are sent to OpenAI. This does not connect to a user's live agent or real external tools; results describe the selected runner and synthetic fixtures.

### Problem addressed

Agent workflows can be influenced to request actions outside their intended permissions, such as cross-tenant reads, unapproved refunds or messages, data exports, deletion, or secret disclosure. AgentShield provides repeatable cases and policy checks to inspect whether those requests are denied and whether the simulated state remains within the expected boundaries.

### Intended users

- **Viewer:** Reads organization-scoped runs and evidence.
- **Operator:** Runs evaluations and reads results.
- **Admin:** Manages organization policies, targets, and API keys.
- **Platform admin:** Manages platform-level organizations and keys.

## 2. Main capabilities

- Submit an evaluation against an authorized synthetic target.
- Select up to 50 deterministic or 10 OpenAI reference scenarios from the local catalog.
- Compare guard-off and guard-on results only when scenarios, runner, and (for OpenAI) model match.
- Apply a policy tied to the target and validate proposed tool actions against its controls.
- Queue work asynchronously in production and retain a local-development execution path.
- Store per-case verdicts, findings, violations, event traces, snapshots, and reports.
- Poll run status and retrieve results in the workbench; download JSON or Markdown reports, compare runs, replay completed runs, and request cancellation.

The catalog contains **50 scenarios**: 30 security/adversarial, 10 benign, and 10 reliability cases.

## 3. System architecture data

### Client and edge

| Component | Current implementation and responsibility |
| --- | --- |
| Browser workbench | Static HTML, CSS, and JavaScript served by the API. Submits runs and reads status, findings, events, and reports. The browser keeps its API key in `sessionStorage`. |
| REST consumer | Calls the JSON API over HTTPS through the configured edge. |
| TLS reverse proxy | Deployment-specific component outside the supplied Docker Compose services. Terminates TLS and forwards traffic to the API, which binds to loopback. |

### Application and evaluation

| Component | Technology | Responsibility |
| --- | --- | --- |
| Web/API service | Python, FastAPI, Uvicorn, Pydantic | Serves REST routes and static pages; authenticates API keys; checks roles; validates request models; applies host, body-size, rate-limit, request-ID, and security-header controls. |
| Evaluation API | Python application service | Validates target and scenario selection, resolves the applicable policy, handles idempotency, snapshots selected scenarios, commits the run and outbox record, and returns HTTP 202 with a run ID. |
| Scenario catalog | Versioned local Python data | Supplies known security, benign, and reliability cases; callers cannot supply arbitrary executable code or endpoints. |
| Deterministic evaluator | Python runner and policy checks | Runs each case against fresh in-memory fixture state. Checks the tool manifest, argument schema, tenant scope, scenario-scoped approval tokens, and call budgets before a protected action changes fixture state. Checks resulting state and raw output for violations. |
| OpenAI reference runner | OpenAI Responses API | Sends built-in synthetic scenario text, accepts at most one strict tool-call proposal, applies policy checks locally, sends the synthetic result back for one final answer, and records model, token usage, latency, and redacted evidence. |

### Queue, persistence, and operations

| Component | Technology | Responsibility |
| --- | --- | --- |
| Production database | PostgreSQL 16 | Durable tenant, key, policy, target, run, scenario snapshot, execution, event, and job-outbox records. The run, scenario snapshots, policy reference, and outbox row are committed in one transaction. |
| Local database | SQLite | Local development storage through the database adapter. It is not the production database. |
| Broker and short-lived state | Redis 7 | Celery broker, API rate-limit counters, and per-run worker locks. Redis persistence uses AOF in the supplied production Compose setup. |
| Background scheduling | Celery Beat | Scans for unsent outbox rows every 10 seconds and dispatches pending work. |
| Background execution | Celery worker | Runs stored evaluations outside the API request. Uses late acknowledgement, a Redis per-run lock, bounded retries, and task time limits. |
| Deployment | Docker Compose | Runs the API, worker, scheduler, PostgreSQL, and Redis services. The public reverse proxy and TLS termination are deployment responsibilities. |
| Service signals | JSON logs and health routes | Access logs include request IDs. `/health` is liveness; `/health/ready` checks PostgreSQL and Redis. |

### Communication paths

- Browser or REST consumer → TLS reverse proxy → FastAPI REST API.
- FastAPI → Redis for production rate-limit state; FastAPI → PostgreSQL for tenant-scoped API operations.
- Evaluation API → PostgreSQL to atomically save a run, snapshots, policy reference, and outbox record.
- Production API → Redis/Celery for immediate job enqueue. Celery Beat reads pending outbox work and republishes unsent jobs. Redis delivers queued tasks to workers.
- Worker → PostgreSQL to load the stored run context and persist executions, findings, events, and final status.
- Worker → deterministic evaluator for seeded proposals, or OpenAI reference runner for model-generated proposals. Both use the same local policy checks and isolated fixture tools.
- OpenAI reference runner → OpenAI Responses API for the prompt, then one final answer request with the policy-approved synthetic result.
- Workbench polls the API and retrieves stored run results.

## 4. End-to-end execution data

### Primary successful path

1. A user submits `POST /api/v1/evaluations` from the workbench or a REST client.
2. The API checks the trusted host, request-size cap, production API-key authentication, rate limits, and role permissions.
3. Strict request validation checks the payload, synthetic target authorization, known scenario IDs, and the target-specific 50-case deterministic or 10-case OpenAI maximum.
4. The idempotency key is checked. The same key and body return the existing run; a conflicting body returns HTTP 409.
5. PostgreSQL commits the run, selected scenario snapshots, policy reference, and job-outbox row in one transaction. The API returns HTTP 202 and the run ID.
6. In production, the API attempts immediate Celery enqueue. Celery Beat checks unsent outbox rows every 10 seconds and dispatches pending work. In local development, FastAPI `BackgroundTasks` runs the evaluation.
7. A Celery worker acquires a per-run Redis lock, loads the stored scenario snapshots and policy, and checks for cancellation between cases.
8. Each case starts with fresh fixture state. The evaluator checks proposed calls against the policy controls before executing an allowed fixture action. A denied action is skipped and its reason is recorded.
9. Postcondition checks inspect fixture state and raw output, including the synthetic canary and cross-tenant customer email addresses. Events and evidence are redacted before persistence; findings retain the violation category without storing the raw value.
10. Per-case results are stored and aggregated. The workbench polls status and retrieves findings, events, and reports through REST.

### Decision and failure outcomes

| Condition | Implemented outcome |
| --- | --- |
| Missing or invalid production API key | HTTP 401 |
| Authenticated principal lacks required role | HTTP 403 |
| Invalid schema, unknown scenario, or invalid target selection | HTTP 422 validation response |
| Reused idempotency key with a different request body | HTTP 409 |
| Rate limit exceeded | HTTP 429 |
| Production rate limiter unavailable | HTTP 503; request protection fails closed |
| Target timeout, malformed output, or oversized output | Per-case `ERROR` |
| Empty target response | Per-case `INCONCLUSIVE` |
| Runner exception for a case | Record `ERROR` evidence and continue to later cases |
| Policy denies a proposed action | Skip the action and record the denial reason |
| Infrastructure exception in the worker | Celery exponential retry, up to five retries; after exhaustion, mark the run `FAILED` |
| Duplicate task delivery | Redis per-run lock and completed-run idempotency checks protect the run |
| Cancellation of a queued run | Cancel while still queued |
| Cancellation after a run starts | Set cancellation request; worker checks between cases |
| Replay | Allowed for completed runs; uses stored scenario snapshots and the original policy reference |

Per-case verdicts are `PASS`, `FAIL`, `ERROR`, or `INCONCLUSIVE`. A worker-level terminal failure sets the run status to `FAILED`.

## 5. Security and reliability controls

- API keys use a random `ash_` prefix and are stored as SHA-256 hashes; a key is shown only once and can be revoked.
- Production API-key authentication is required. Role checks separate viewer, operator, admin, and platform-admin actions.
- Organization-scoped application queries constrain tenant records. PostgreSQL row-level security is not configured.
- Strict request models reject unknown fields. The API caps declared request bodies at 1 MiB, checks trusted hosts, applies security headers, and attaches request IDs.
- Production Redis rate limits are fixed at 120 requests per minute per API key and 600 per minute per source IP.
- Targets are synthetic-only. The worker has no external agent or HTTP target adapter; the OpenAI reference runner is opt-in and uses built-in scenarios only.
- Tool schema, allowlist, tenant, approval, and call-budget checks run before a protected action changes fixture state.
- Postcondition checks independently inspect fixture state for forbidden changes and raw output for synthetic secret and cross-tenant personal-data disclosure.
- Events and reports redact email addresses and synthetic secrets; detection runs before redaction.
- PostgreSQL and Redis are private Compose services with persistent volumes. The API binds to loopback; public routing and TLS belong to the reverse proxy.
- Job intent is persisted with the run. Celery late acknowledgement, a run lock, bounded retries, time limits, and the periodic outbox dispatcher handle duplicate delivery and common worker interruptions.

## 6. Technology fit and operating model

The code documents what each technology does, but does not record the original selection rationale. A defensible explanation of current fit is:

- **FastAPI and Pydantic:** HTTP API plus request schema validation.
- **PostgreSQL:** Durable relational records and atomic run/outbox writes.
- **Redis:** Celery broker and short-lived lock/rate-limit state.
- **Celery and Beat:** Background evaluation with periodic outbox recovery.
- **SQLite and FastAPI BackgroundTasks:** Simpler local-development substitutes.
- **Docker Compose:** Localized multi-service runtime definition.

This pattern moves lengthy evaluation work off the request path and preserves job intent with database state. It also introduces separate database, broker, scheduler, and worker services that need operational monitoring. The implementation does not claim measured throughput, tested capacity, or automatic horizontal scaling behavior.

## 7. Current scope and known limitations

- The OpenAI reference runner is not a live-agent connector. No HTTP target adapter, MCP integration, real email/payment/database tool, vector database, or RAG path is implemented.
- Deterministic scenario proposals and all tool effects use fresh in-memory fixture state. OpenAI responses can vary across runs; results do not establish the security of a customer's deployed agent.
- No OpenTelemetry exporter, metrics backend, alert-routing provider, or automated backup schedule is included.
- Rate limits are fixed in the current implementation.
- Tenant isolation is enforced in application queries, not with PostgreSQL row-level security.
- Production migrations 1 and 2 create a PostgreSQL schema and add the runner field to existing AgentShield databases; the earlier SQLite schema is not migrated into it.
- External agent testing would need a target adapter plus destination allowlists, DNS/IP rebinding defenses, isolated credentials, egress controls, and isolated execution. These are not present.

## 8. Requirements for future portfolio diagrams

These are presentation requirements, separate from implemented product behavior.

### Architecture view

- Show the client/workbench, external deployment edge, FastAPI API, evaluation service, PostgreSQL, Redis, Celery Beat, Celery workers, deterministic evaluator, optional OpenAI reference provider path, scenario catalog, and implemented operations signals.
- Mark the Docker Compose boundary and show the reverse proxy outside it.
- Distinguish synchronous API/database paths from asynchronous Celery dispatch.
- Show the transactional outbox, worker, policy checks, and persisted evidence.

### Execution-flow view

- Show request input, API security and validation, idempotency, atomic persistence, HTTP 202, production dispatch and local development path, worker lock/retry behavior, per-case policy decisions, result checks, redaction, persistence, and report retrieval.
- Include the important denial, validation, retry-exhaustion, cancellation, `ERROR`, and `INCONCLUSIVE` outcomes without crowding the primary successful path.
- Keep the system architecture and execution flow visually distinct: one describes organization, the other describes runtime behavior.

### Visual and accuracy requirements

- Use a white background, minimal technical layout, restrained slate/blue/teal/green/amber/red colors, clear type, consistent spacing, and readable labels.
- Use editable source and vector/raster exports when diagrams are requested.
- Do not invent models, agents, integrations, services, stores, metrics, or scaling claims.
- Keep scope limitations in explanatory project data; do not add small caveat or footnote lines to the diagram artwork.

## 9. Source files used for this project data

- `agentshield/app.py`
- `agentshield/auth.py`
- `agentshield/db.py`
- `agentshield/engine.py`
- `agentshield/scenarios.py`
- `agentshield/worker.py`
- `static/app.js`
- `README.md`
- `docs/architecture.md`
- `docs/operations.md`
- `Dockerfile`
- `docker-compose.yml`
- `requirements.txt`
