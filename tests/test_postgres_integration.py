"""Integration tests against a real Postgres (run in CI; skipped locally by default).

Set ``MCP_DEVTOOLS_TEST_PG_DSN`` to a database loaded with
``examples/compose/initdb/01-library.sql``, e.g. via ``docker compose up postgres``.
"""

from __future__ import annotations

import os

import pytest

from mcp_devtools.backends.postgres import PsycopgBackend
from mcp_devtools.config import Settings
from mcp_devtools.errors import BackendError
from mcp_devtools.tools.context import Backends, ToolContext
from mcp_devtools.tools.db_tools import DatabaseTools

DSN = os.environ.get("MCP_DEVTOOLS_TEST_PG_DSN")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN, reason="MCP_DEVTOOLS_TEST_PG_DSN not set"),
]


@pytest.fixture
def db(backends: Backends) -> DatabaseTools:
    settings = Settings.model_validate(
        {"postgres": {"databases": {"library": DSN}, "max_rows": 50, "statement_timeout_ms": 500}}
    )
    backends.postgres = PsycopgBackend()
    return DatabaseTools(ToolContext.for_testing(settings, backends))


def test_select_with_row_cap(db: DatabaseTools) -> None:
    result = db.query("library", "SELECT checkout_id FROM checkouts ORDER BY checkout_id")
    assert result["row_count"] == 50
    assert result["truncated"] is True
    assert result["rows"][0] == [1]


def test_types_are_json_friendly(db: DatabaseTools) -> None:
    result = db.query("library", "SELECT checked_out, now() - checked_out AS age FROM checkouts")
    checked_out, age = result["rows"][0]
    assert isinstance(checked_out, str) and checked_out.startswith("2025-01-01")
    assert isinstance(age, float)


def test_show_and_values(db: DatabaseTools) -> None:
    assert db.query("library", "SHOW transaction_read_only")["rows"] == [["on"]]
    assert db.query("library", "VALUES (1), (2)")["row_count"] == 2


def test_database_refuses_writes_even_if_validator_is_bypassed() -> None:
    assert DSN
    with pytest.raises(BackendError, match=r"25006|read-only"):
        PsycopgBackend().execute(
            DSN, "CREATE TABLE sneaky (id int)", statement="SHOW", max_rows=1, timeout_ms=1000
        )


def test_statement_timeout_is_enforced() -> None:
    assert DSN
    with pytest.raises(BackendError, match=r"57014|statement timeout"):
        PsycopgBackend().execute(
            DSN, "SELECT pg_sleep(2)", statement="SELECT", max_rows=1, timeout_ms=200
        )


def test_explain_finds_the_missing_index(db: DatabaseTools) -> None:
    result = db.explain(
        "library",
        "SELECT count(*) FROM checkouts WHERE member_id = 42 AND returned IS NULL",
        analyze=True,
    )
    assert "checkouts" in result["summary"]["sequential_scans"]
    assert result["summary"]["execution_ms"] is not None


def test_list_tables(db: DatabaseTools) -> None:
    tables = {t["name"] for t in db.list_tables("library")["tables"]}
    assert {"authors", "books", "members", "checkouts"} <= tables
