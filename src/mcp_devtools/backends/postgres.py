"""Read-only Postgres query backend built on psycopg 3.

Defence in depth for the query tool:

1. :mod:`mcp_devtools.security.sql_guard` rejects anything that is not a single
   read-only statement before we connect;
2. every query runs in a transaction opened with ``READ ONLY`` and a
   transaction-local ``statement_timeout`` / ``lock_timeout``;
3. the transaction is always rolled back, never committed;
4. rows are streamed through a server-side cursor where Postgres allows it and
   at most ``max_rows`` are ever transferred.

Operators should still point the server at a role with only ``SELECT``
privileges; the layers above are a seat belt, not a substitute for grants.
"""

from __future__ import annotations

import base64
import datetime as dt
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Protocol

from mcp_devtools.errors import BackendError
from mcp_devtools.security.redact import redact_text

APPLICATION_NAME = "mcp-devtools"
_SERVER_SIDE_OK = {"SELECT", "WITH", "VALUES", "TABLE"}


@dataclass(frozen=True, slots=True)
class QueryResult:
    columns: list[str]
    rows: list[list[Any]]
    truncated: bool
    duration_ms: float
    notices: list[str] = field(default_factory=list)

    @property
    def row_count(self) -> int:
        return len(self.rows)


class QueryBackend(Protocol):
    def execute(
        self,
        dsn: str,
        sql: str,
        *,
        statement: str,
        max_rows: int,
        timeout_ms: int,
        params: dict[str, Any] | None = None,
    ) -> QueryResult: ...


def to_jsonable(value: Any) -> Any:
    """Convert values psycopg returns into JSON-friendly equivalents."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dt.datetime | dt.date | dt.time):
        return value.isoformat()
    if isinstance(value, dt.timedelta):
        return value.total_seconds()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        encoded = base64.b64encode(raw[:256]).decode("ascii")
        return {"base64": encoded, "bytes": len(raw), "truncated": len(raw) > 256}
    if isinstance(value, list | tuple):
        return [to_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    return str(value)


class PsycopgBackend:
    def __init__(self, *, connect_timeout: int = 5) -> None:
        self.connect_timeout = connect_timeout

    def execute(
        self,
        dsn: str,
        sql: str,
        *,
        statement: str,
        max_rows: int,
        timeout_ms: int,
        params: dict[str, Any] | None = None,
    ) -> QueryResult:
        import psycopg  # imported lazily so the server starts without libpq when unused

        started = time.perf_counter()
        notices: list[str] = []
        try:
            with psycopg.connect(
                dsn,
                connect_timeout=self.connect_timeout,
                application_name=APPLICATION_NAME,
                autocommit=False,
            ) as conn:
                conn.read_only = True
                conn.add_notice_handler(lambda diag: notices.append(str(diag.message_primary)))
                try:
                    _configure_transaction(conn, timeout_ms)
                    cursor_name = "mcp_devtools_q" if statement in _SERVER_SIDE_OK else None
                    with conn.cursor(name=cursor_name) if cursor_name else conn.cursor() as cur:
                        cur.execute(sql.encode("utf-8"), params or None)
                        if cur.description is None:
                            return QueryResult([], [], False, _ms(started), notices)
                        columns = [col.name for col in cur.description]
                        fetched = cur.fetchmany(max_rows + 1)
                finally:
                    conn.rollback()
        except psycopg.Error as exc:
            message = redact_text(str(exc).strip()) or type(exc).__name__
            sqlstate = getattr(exc, "sqlstate", None)
            prefix = f"[{sqlstate}] " if sqlstate else ""
            raise BackendError(f"postgres error: {prefix}{message}") from exc

        truncated = len(fetched) > max_rows
        rows = [[to_jsonable(v) for v in row] for row in fetched[:max_rows]]
        return QueryResult(columns, rows, truncated, _ms(started), notices)


def _configure_transaction(conn: Any, timeout_ms: int) -> None:
    lock_ms = min(timeout_ms, 2000)
    with conn.cursor() as cur:
        cur.execute("SET TRANSACTION READ ONLY")
        cur.execute(
            "SELECT set_config('statement_timeout', %s, true),"
            " set_config('lock_timeout', %s, true),"
            " set_config('idle_in_transaction_session_timeout', %s, true)",
            (f"{timeout_ms}ms", f"{lock_ms}ms", f"{timeout_ms * 2}ms"),
        )


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)
