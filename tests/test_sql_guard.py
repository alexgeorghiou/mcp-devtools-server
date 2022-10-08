from __future__ import annotations

import pytest

from mcp_devtools.errors import ValidationError
from mcp_devtools.security.sql_guard import TokenKind, tokenize, validate_read_only


@pytest.mark.parametrize(
    ("sql", "statement"),
    [
        ("SELECT 1", "SELECT"),
        ("select * from users where id = 1;", "SELECT"),
        ("  WITH t AS (SELECT 1 AS n) SELECT n FROM t", "WITH"),
        ("EXPLAIN SELECT * FROM orders_archive", "EXPLAIN"),
        ("EXPLAIN (ANALYZE, BUFFERS) SELECT count(*) FROM events", "EXPLAIN"),
        ("SHOW server_version", "SHOW"),
        ("VALUES (1, 'a'), (2, 'b')", "VALUES"),
        ("TABLE pg_catalog.pg_namespace", "TABLE"),
        ("(SELECT 1) UNION ALL (SELECT 2)", "SELECT"),
        ("SELECT * FROM t ORDER BY id FETCH FIRST 5 ROWS ONLY", "SELECT"),
        ("SELECT comment, owner, start FROM tickets", "SELECT"),
    ],
)
def test_accepts_read_only_statements(sql: str, statement: str) -> None:
    assert validate_read_only(sql).statement == statement


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO t VALUES (1)",
        "update t set a = 1",
        "DELETE FROM t",
        "DROP TABLE t",
        "CREATE TABLE x (id int)",
        "ALTER TABLE t ADD COLUMN c int",
        "TRUNCATE t",
        "GRANT SELECT ON t TO public",
        "COPY t TO '/tmp/out.csv'",
        "VACUUM t",
        "BEGIN",
        "SET statement_timeout = 0",
        "DO $$ BEGIN PERFORM 1; END $$",
        "CALL refresh_everything()",
        "LOCK TABLE t",
    ],
)
def test_rejects_writes_and_session_control(sql: str) -> None:
    with pytest.raises(ValidationError):
        validate_read_only(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "WITH gone AS (DELETE FROM t RETURNING *) SELECT * FROM gone",
        "SELECT * INTO new_table FROM t",
        "SELECT * FROM t FOR UPDATE",
        "EXPLAIN ANALYZE DELETE FROM t",
        "SELECT pg_sleep(10)",
        "SELECT pg_terminate_backend(42)",
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT * FROM dblink('host=x', 'select 1') AS t(a int)",
        "SELECT set_config('statement_timeout', '0', false)",
        "select PG_SLEEP (1)",
    ],
)
def test_rejects_smuggled_side_effects(sql: str) -> None:
    with pytest.raises(ValidationError):
        validate_read_only(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1; DROP TABLE t",
        "SELECT 1;SELECT 2",
        "SELECT 1; -- harmless?\nDELETE FROM t",
    ],
)
def test_rejects_multiple_statements(sql: str) -> None:
    with pytest.raises(ValidationError, match="single statement"):
        validate_read_only(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 'DROP TABLE t; DELETE FROM x' AS text",
        'SELECT "update" FROM audit_view',
        "SELECT $$ insert into t values (1) $$",
        "SELECT $tag$ ; delete $tag$",
        "SELECT E'it\\'s ; drop' AS s",
        "SELECT 1 -- DROP TABLE t",
        "SELECT /* delete /* nested */ still comment */ 1",
        "SELECT pg_sleep_note FROM t",
    ],
)
def test_keywords_inside_literals_and_comments_are_ignored(sql: str) -> None:
    validate_read_only(sql)


@pytest.mark.parametrize(
    "sql", ["", "   ", ";", "-- only a comment", "SELECT 'unterminated", "SELECT /* open"]
)
def test_rejects_empty_or_malformed(sql: str) -> None:
    with pytest.raises(ValidationError):
        validate_read_only(sql)


def test_rejects_oversized_query() -> None:
    with pytest.raises(ValidationError, match="longer"):
        validate_read_only("SELECT " + "1," * 20_000 + "1")


def test_strips_trailing_semicolons() -> None:
    assert validate_read_only("SELECT 1 ;; ").sql == "SELECT 1"


def test_tokenizer_classifies_tokens() -> None:
    kinds = [t.kind for t in tokenize("SELECT \"Col\", 'x', 1.5e3 FROM t;")]
    assert kinds == [
        TokenKind.WORD,
        TokenKind.QUOTED_IDENT,
        TokenKind.PUNCT,
        TokenKind.STRING,
        TokenKind.PUNCT,
        TokenKind.NUMBER,
        TokenKind.WORD,
        TokenKind.WORD,
        TokenKind.SEMICOLON,
    ]
