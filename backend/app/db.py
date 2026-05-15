"""
SQLite persistence layer — WAL mode for crash-safe checkpointing.

Every CPN transition commits the serialized master state here so that
the Orchestrator can resume at the exact node after a crash.
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.config import SQLITE_DB_PATH

_local = threading.local()

# ── Schema bootstrap ─────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS checkpoints (
    trace_id    TEXT    NOT NULL,
    node_id     TEXT    NOT NULL,
    state_json  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (trace_id, node_id)
);

CREATE TABLE IF NOT EXISTS execution_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id    TEXT    NOT NULL,
    task_id     TEXT    NOT NULL,
    agent_name  TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pending',
    input_json  TEXT,
    output_json TEXT,
    error       TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""


def _get_connection() -> sqlite3.Connection:
    """Return a thread-local connection configured for WAL mode."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(SQLITE_DB_PATH, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        conn.executescript(_DDL)
        _local.conn = conn
    return conn


@contextmanager
def atomic():
    """Context manager that wraps a block in a SQLite transaction."""
    conn = _get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# ── Checkpoint CRUD ──────────────────────────────────────────────────────────

def save_checkpoint(trace_id: str, node_id: str, state: Dict[str, Any]) -> None:
    """Atomically upsert the master state for a (trace, node) pair."""
    with atomic() as conn:
        conn.execute(
            """
            INSERT INTO checkpoints (trace_id, node_id, state_json, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(trace_id, node_id)
            DO UPDATE SET state_json = excluded.state_json,
                          created_at = excluded.created_at
            """,
            (trace_id, node_id, json.dumps(state), _now()),
        )


def load_latest_checkpoint(trace_id: str) -> Optional[Dict[str, Any]]:
    """Return the most recent checkpoint for *trace_id*, or None."""
    conn = _get_connection()
    row = conn.execute(
        "SELECT state_json FROM checkpoints WHERE trace_id = ? ORDER BY created_at DESC LIMIT 1",
        (trace_id,),
    ).fetchone()
    return json.loads(row["state_json"]) if row else None


# ── Execution log CRUD ───────────────────────────────────────────────────────

def log_execution(
    trace_id: str,
    task_id: str,
    agent_name: str,
    *,
    status: str = "pending",
    input_json: Optional[str] = None,
    output_json: Optional[str] = None,
    error: Optional[str] = None,
) -> int:
    """Insert an execution-log row and return the new row id."""
    with atomic() as conn:
        cur = conn.execute(
            """
            INSERT INTO execution_log
                (trace_id, task_id, agent_name, status, input_json, output_json, error, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (trace_id, task_id, agent_name, status, input_json, output_json, error, _now(), _now()),
        )
        return cur.lastrowid  # type: ignore[return-value]


def update_execution(
    row_id: int,
    *,
    status: Optional[str] = None,
    output_json: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    """Patch selected fields on an existing execution-log row."""
    fields, values = [], []
    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if output_json is not None:
        fields.append("output_json = ?")
        values.append(output_json)
    if error is not None:
        fields.append("error = ?")
        values.append(error)
    if not fields:
        return
    fields.append("updated_at = ?")
    values.append(_now())
    values.append(row_id)
    with atomic() as conn:
        conn.execute(
            f"UPDATE execution_log SET {', '.join(fields)} WHERE id = ?",
            values,
        )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
