from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal
from typing import Any

import psycopg
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_devtools.backends.postgres import PsycopgBackend, QueryResult, to_jsonable
from mcp_devtools.errors import BackendError
from mcp_devtools.tools.context import ToolContext
from mcp_devtools.tools.db_tools import DatabaseTools, summarise_plan
from tests.fakes import FakePostgres


@pytest.fixture
def db(ctx: ToolContext) -> DatabaseTools:
    return DatabaseTools(ctx)


def test_query_passes_validated_sql_and_limits(
    db: DatabaseTools, fake_postgres: FakePostgres
) -> None:
    fake_postgres.result = QueryResult(["id"], [[1], [2], [3], [4], [5]], False, 2.0)
    result = db.query("app", "SELECT id FROM books;", max_rows=1000)
    call = fake_postgres.calls[0]
    assert call["sql"] == "SELECT id FROM books"
    assert call["statement"] == "SELECT"
    assert call["max_rows"] == 3  # server cap wins over the request
    assert call["timeout_ms"] == 5000
    assert result["rows"] == [[1], [2], [3]]
    assert result["truncated"] is True


def test_query_smaller_limit_is_respected(db: DatabaseTools, fake_postgres: FakePostgres) -> None:
    db.query("app", "SELECT 1", max_rows=1)
    assert fake_postgres.calls[0]["max_rows"] == 1


def test_write_is_rejected_before_connecting(
    db: DatabaseTools, fake_postgres: FakePostgres
) -> None:
    with pytest.raises(ToolError, match=r"\[invalid\] keyword DELETE"):
        db.query("app", "WITH x AS (DELETE FROM t RETURNING 1) SELECT * FROM x")
    assert fake_postgres.calls == []


def test_unknown_database_is_denied(db: DatabaseTools, ctx: ToolContext) -> None:
    with pytest.raises(ToolError, match="denied"):
        db.query("prod", "SELECT 1")
    record = ctx.audit.tail(1)[0]
    assert record["tool"] == "pg_query"
    assert record["outcome"] == "denied"


def test_dsn_never_reaches_the_audit_log(db: DatabaseTools, ctx: ToolContext) -> None:
    db.query("app", "SELECT 1")
    assert "s3cret" not in str(ctx.audit.tail(10))


PLAN = [
    {
        "Plan": {
            "Node Type": "Hash Join",
            "Total Cost": 1200.5,
            "Plan Rows": 10,
            "Actual Total Time": 85.0,
            "Actual Rows": 4000,
            "Plans": [
                {"Node Type": "Seq Scan", "Relation Name": "checkouts", "Total Cost": 900.0,
                 "Actual Total Time": 70.0},
                {"Node Type": "Index Scan", "Relation Name": "books",
                 "Index Name": "books_pkey", "Total Cost": 8.3, "Actual Total Time": 0.4},
            ],
        },
        "Planning Time": 0.3,
        "Execution Time": 86.1,
    }
]  # fmt: skip


def test_explain_wraps_query_and_summarises(db: DatabaseTools, fake_postgres: FakePostgres) -> None:
    fake_postgres.result = QueryResult(["QUERY PLAN"], [[PLAN]], False, 3.0)
    result = db.explain("app", "SELECT * FROM checkouts JOIN books USING (book_id)", analyze=True)
    sql = fake_postgres.calls[0]["sql"]
    assert sql.startswith("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT")
    assert fake_postgres.calls[0]["statement"] == "EXPLAIN"
    summary = result["summary"]
    assert summary["sequential_scans"] == ["checkouts"]
    assert summary["execution_ms"] == 86.1
    assert summary["hottest_nodes"][0]["node"] == "Hash Join"
    assert summary["node_count"] == 3


def test_explain_refuses_non_select(db: DatabaseTools) -> None:
    with pytest.raises(ToolError, match="SELECT-style"):
        db.explain("app", "SHOW work_mem")


def test_summarise_plan_accepts_json_text_and_rejects_garbage() -> None:
    import json

    assert summarise_plan(json.dumps(PLAN))["total_cost"] == 1200.5  # type: ignore[index]
    assert summarise_plan(None) is None
    assert summarise_plan([{}]) is None


def test_list_tables_groups_columns(db: DatabaseTools, fake_postgres: FakePostgres) -> None:
    fake_postgres.result = QueryResult(
        ["table_schema", "table_name", "table_type", "column_name", "data_type", "nullable"],
        [
            ["public", "books", "BASE TABLE", "book_id", "integer", False],
            ["public", "books", "BASE TABLE", "title", "text", False],
            ["public", "overdue", "VIEW", "book_id", "integer", True],
        ],
        False,
        1.0,
    )
    result = db.list_tables("app")
    assert fake_postgres.calls[0]["params"] == {"schema": "public"}
    assert [t["name"] for t in result["tables"]] == ["books", "overdue"]
    assert result["tables"][0]["columns"][1] == {"name": "title", "type": "text", "nullable": False}


def test_to_jsonable_conversions() -> None:
    uid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    row = [
        Decimal("1.50"),
        dt.datetime(2026, 1, 2, 3, 4, 5),
        dt.date(2026, 1, 2),
        dt.timedelta(minutes=2),
        uid,
        b"\x00\x01",
        {"tags": ("a", "b")},
        None,
        object,
    ]
    out = to_jsonable(row)
    assert out[:5] == ["1.50", "2026-01-02T03:04:05", "2026-01-02", 120.0, str(uid)]
    assert out[5] == {"base64": "AAE=", "bytes": 2, "truncated": False}
    assert out[6] == {"tags": ["a", "b"]}
    assert out[7] is None
    assert out[8] == "<class 'object'>"


# -- PsycopgBackend against a scripted connection ---------------------------------


class FakeCursor:
    def __init__(self, conn: FakeConnection, name: str | None) -> None:
        self.conn, self.name = conn, name
        self.description: list[Any] | None = None
        self._rows: list[tuple[Any, ...]] = []

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, sql: Any, params: Any = None) -> None:
        text = sql.decode() if isinstance(sql, bytes) else sql
        self.conn.log.append((self.name, text, params))
        if self.conn.fail_on and self.conn.fail_on in text:
            raise psycopg.errors.QueryCanceled("canceling statement due to statement timeout")
        if "set_config" in text or text.startswith("SET"):
            return
        self.description = [type("Col", (), {"name": "n"})()]
        self._rows = [(i,) for i in range(10)]

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        return self._rows[:size]


class FakeConnection:
    def __init__(self, fail_on: str | None = None) -> None:
        self.log: list[tuple[str | None, str, Any]] = []
        self.read_only = False
        self.rolled_back = False
        self.committed = False
        self.fail_on = fail_on

    def __enter__(self) -> FakeConnection:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def add_notice_handler(self, _handler: Any) -> None:
        return None

    def cursor(self, name: str | None = None) -> FakeCursor:
        return FakeCursor(self, name)

    def rollback(self) -> None:
        self.rolled_back = True

    def commit(self) -> None:  # pragma: no cover - must never be called
        self.committed = True


@pytest.fixture
def fake_conn(monkeypatch: pytest.MonkeyPatch) -> FakeConnection:
    conn = FakeConnection()
    captured: dict[str, Any] = {}

    def connect(dsn: str, **kwargs: Any) -> FakeConnection:
        captured.update(kwargs, dsn=dsn)
        return conn

    monkeypatch.setattr(psycopg, "connect", connect)
    conn.connect_kwargs = captured  # type: ignore[attr-defined]
    return conn


def test_backend_runs_inside_read_only_transaction(fake_conn: FakeConnection) -> None:
    result = PsycopgBackend().execute(
        "postgresql://x", "SELECT n FROM t", statement="SELECT", max_rows=4, timeout_ms=1500
    )
    assert fake_conn.read_only is True
    statements = [sql for _, sql, _ in fake_conn.log]
    assert statements[0] == "SET TRANSACTION READ ONLY"
    assert "statement_timeout" in statements[1]
    assert fake_conn.log[1][2] == ("1500ms", "1500ms", "3000ms")
    assert fake_conn.log[2][0] == "mcp_devtools_q"  # server-side cursor for SELECT
    assert fake_conn.rolled_back and not fake_conn.committed
    assert result.rows == [[0], [1], [2], [3]]
    assert result.truncated is True
    assert fake_conn.connect_kwargs["application_name"] == "mcp-devtools"  # type: ignore[attr-defined]


def test_backend_uses_client_cursor_for_show(fake_conn: FakeConnection) -> None:
    PsycopgBackend().execute("dsn", "SHOW work_mem", statement="SHOW", max_rows=5, timeout_ms=100)
    assert fake_conn.log[-1][0] is None


def test_backend_maps_errors_and_still_rolls_back(fake_conn: FakeConnection) -> None:
    fake_conn.fail_on = "pg_class"
    with pytest.raises(BackendError, match="statement timeout"):
        PsycopgBackend().execute(
            "dsn", "SELECT * FROM pg_class", statement="SELECT", max_rows=1, timeout_ms=100
        )
    assert fake_conn.rolled_back
