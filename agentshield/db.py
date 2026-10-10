"""Small DB-API compatibility layer for SQLite development and PostgreSQL deployments."""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

DATA_DIR = Path(os.environ.get("AGENTSHIELD_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DB_PATH = DATA_DIR / "agentshield.sqlite3"
DATABASE_URL = os.environ.get("AGENTSHIELD_DATABASE_URL", f"sqlite:///{DB_PATH.as_posix()}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL.removeprefix("postgres://")
if DATABASE_URL.startswith("postgresql+psycopg://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL.removeprefix("postgresql+psycopg://")
IS_POSTGRES = DATABASE_URL.startswith("postgresql://")
if not IS_POSTGRES and not DATABASE_URL.startswith("sqlite:///"):
    raise RuntimeError("AGENTSHIELD_DATABASE_URL must use SQLite or PostgreSQL with psycopg.")

POSTGRES_MIGRATIONS = (
    (1, (
        "CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL)",
        "CREATE TABLE api_keys (id TEXT PRIMARY KEY, organization_id TEXT REFERENCES organizations(id), prefix TEXT NOT NULL, secret_hash TEXT NOT NULL UNIQUE, role TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT)",
        "CREATE TABLE policies (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), name TEXT NOT NULL, version INTEGER NOT NULL, definition TEXT NOT NULL, created_at TEXT NOT NULL)",
        "CREATE INDEX policies_org_idx ON policies(organization_id, created_at)",
        "CREATE TABLE targets (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), name TEXT NOT NULL, version TEXT NOT NULL, owner TEXT NOT NULL, environment TEXT NOT NULL CHECK(environment = 'simulator'), authorized BOOLEAN NOT NULL CHECK(authorized = TRUE), policy_id TEXT REFERENCES policies(id), created_at TEXT NOT NULL)",
        "CREATE INDEX targets_org_idx ON targets(organization_id, created_at)",
        "CREATE TABLE runs (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), target_id TEXT NOT NULL REFERENCES targets(id), policy_id TEXT REFERENCES policies(id), status TEXT NOT NULL, scenario_ids TEXT NOT NULL, scenario_snapshots TEXT NOT NULL, idempotency_key TEXT, created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT, summary TEXT, error TEXT)",
        "CREATE UNIQUE INDEX runs_idempotency_idx ON runs(organization_id, idempotency_key) WHERE idempotency_key IS NOT NULL",
        "CREATE INDEX runs_org_idx ON runs(organization_id, created_at DESC)",
        "CREATE TABLE executions (id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, scenario_id TEXT NOT NULL, scenario_version TEXT NOT NULL, verdict TEXT NOT NULL, evidence TEXT NOT NULL, violations TEXT NOT NULL, scenario_snapshot TEXT NOT NULL)",
        "CREATE INDEX executions_run_idx ON executions(run_id, scenario_id)",
        "CREATE TABLE events (id BIGSERIAL PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, execution_id TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE, scenario_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_type TEXT NOT NULL, data TEXT NOT NULL)",
        "CREATE INDEX events_run_idx ON events(run_id, id)",
        "CREATE TABLE job_outbox (run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE, created_at TEXT NOT NULL, sent_at TEXT)",
    )),
    (2, (
        "ALTER TABLE targets ADD COLUMN runner TEXT NOT NULL DEFAULT 'deterministic' CHECK(runner IN ('deterministic','openai_reference'))",
    )),
)
_POSTGRES_POOL = None


def _postgres_pool():
    global _POSTGRES_POOL
    if _POSTGRES_POOL is None:
        from psycopg_pool import ConnectionPool

        _POSTGRES_POOL = ConnectionPool(conninfo=DATABASE_URL, min_size=1, max_size=8, timeout=5, open=True)
        _POSTGRES_POOL.wait()
    return _POSTGRES_POOL


def close_pool() -> None:
    global _POSTGRES_POOL
    if _POSTGRES_POOL is not None:
        _POSTGRES_POOL.close()
        _POSTGRES_POOL = None


def migrate() -> None:
    if not IS_POSTGRES:
        return
    with connect() as db:
        db.execute("SELECT pg_advisory_xact_lock(617402918)")
        db.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        current = db.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0]
        for version, statements in POSTGRES_MIGRATIONS:
            if version <= current:
                continue
            for statement in statements:
                db.execute(statement)
            db.execute("INSERT INTO schema_migrations (version,applied_at) VALUES (?,?)", (version, datetime.now(timezone.utc).isoformat()))


class _Row(list):
    def __init__(self, names: list[str], values: tuple[Any, ...]):
        super().__init__(values)
        self._values = dict(zip(names, values))

    def __getitem__(self, key):
        return self._values[key] if isinstance(key, str) else super().__getitem__(key)

    def keys(self):
        return self._values.keys()


class _Result:
    def __init__(self, cursor):
        self.cursor = cursor
        self.names = [column.name for column in cursor.description] if cursor.description else []

    def fetchone(self):
        row = self.cursor.fetchone()
        return _Row(self.names, row) if row is not None else None

    def fetchall(self):
        return [_Row(self.names, row) for row in self.cursor.fetchall()]

    def __iter__(self) -> Iterator[_Row]:
        for row in self.cursor:
            yield _Row(self.names, row)

    @property
    def rowcount(self):
        return self.cursor.rowcount


class Connection:
    def __init__(self, raw, postgres: bool):
        self.raw = raw
        self.postgres = postgres

    def execute(self, sql: str, params=()):
        if not self.postgres:
            return self.raw.execute(sql, params)
        cursor = self.raw.cursor()
        cursor.execute(sql.replace("?", "%s"), params)
        return _Result(cursor)

    def executemany(self, sql: str, params):
        if not self.postgres:
            return self.raw.executemany(sql, params)
        cursor = self.raw.cursor()
        cursor.executemany(sql.replace("?", "%s"), params)
        return cursor


@contextmanager
def connect():
    if IS_POSTGRES:
        with _postgres_pool().connection() as raw:
            yield Connection(raw, True)
    else:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        raw = sqlite3.connect(DB_PATH, timeout=10)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA foreign_keys = ON")
        raw.execute("PRAGMA journal_mode = WAL")
        raw.execute("PRAGMA busy_timeout = 10000")
        try:
            yield Connection(raw, False)
            raw.commit()
        except BaseException:
            raw.rollback()
            raise
        finally:
            raw.close()
