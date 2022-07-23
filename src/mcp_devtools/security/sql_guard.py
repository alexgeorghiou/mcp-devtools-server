"""Static validation of SQL submitted to the read-only Postgres tool.

This is the first of two layers. The second, authoritative layer is the
database itself: every query runs inside ``SET TRANSACTION READ ONLY`` with a
``statement_timeout``. The validator exists so obviously-unsafe input is
rejected with a clear message before a connection is even opened, and so
side-effecting functions that a read-only transaction does *not* block (for
example ``pg_terminate_backend`` or ``dblink``) are refused.

The scanner understands enough of PostgreSQL's lexical rules (comments, nested
block comments, standard and ``E''`` strings, quoted identifiers and dollar
quoting) that keywords hidden inside literals neither trigger false positives
nor allow smuggling a second statement past the checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from mcp_devtools.errors import ValidationError

MAX_SQL_LENGTH = 20_000

ALLOWED_LEADING = frozenset({"SELECT", "WITH", "EXPLAIN", "SHOW", "VALUES", "TABLE"})

FORBIDDEN_KEYWORDS = frozenset(
    {
        # DML, including data-modifying CTEs and EXPLAIN ANALYZE of writes
        "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "COPY",
        # DDL and maintenance
        "CREATE", "ALTER", "DROP", "REINDEX", "CLUSTER", "VACUUM", "REFRESH",
        # privileges
        "GRANT", "REVOKE",
        # session / transaction control
        "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "SET", "RESET", "DISCARD",
        "LOCK", "LISTEN", "NOTIFY", "UNLISTEN", "PREPARE", "EXECUTE", "DEALLOCATE",
        "DECLARE",
        # procedural / server
        "CALL", "DO", "CHECKPOINT",
        # SELECT ... INTO creates a table
        "INTO",
    }
)  # fmt: skip
"""Words refused anywhere outside literals. Words that are common column names
(``comment``, ``owner``, ``start``...) are deliberately absent: they can only
act as statements in leading position, which the leading-keyword check covers."""

FORBIDDEN_FUNCTIONS = frozenset(
    {
        "pg_sleep", "pg_sleep_for", "pg_sleep_until",
        "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf", "pg_rotate_logfile",
        "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
        "pg_ls_logdir", "pg_ls_waldir", "pg_ls_tmpdir",
        "lo_import", "lo_export", "lo_unlink", "lo_create", "lo_from_bytea", "lo_put",
        "dblink", "dblink_exec", "dblink_connect", "dblink_send_query",
        "set_config", "setval", "nextval",
        "pg_advisory_lock", "pg_advisory_xact_lock", "pg_try_advisory_lock",
        "pg_create_restore_point", "pg_switch_wal", "pg_promote",
        "query_to_xml", "query_to_json", "query_to_xml_and_xmlschema",
    }
)  # fmt: skip


class TokenKind(StrEnum):
    WORD = "word"
    QUOTED_IDENT = "quoted_ident"
    STRING = "string"
    NUMBER = "number"
    SEMICOLON = "semicolon"
    PUNCT = "punct"


@dataclass(frozen=True, slots=True)
class Token:
    kind: TokenKind
    value: str


@dataclass(frozen=True, slots=True)
class ValidatedQuery:
    sql: str
    statement: str
    """Upper-cased leading keyword, e.g. ``SELECT`` or ``EXPLAIN``."""

    @property
    def is_explain(self) -> bool:
        return self.statement == "EXPLAIN"


_WORD_START = re.compile(r"[A-Za-z_\u0080-￿]")
_WORD_CHARS = re.compile(r"[A-Za-z0-9_$\u0080-￿]*")
_NUMBER = re.compile(r"\d+(\.\d*)?([eE][+-]?\d+)?|\.\d+([eE][+-]?\d+)?")
_DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


def tokenize(sql: str) -> list[Token]:
    """Split SQL into tokens, discarding comments and whitespace."""
    tokens: list[Token] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch.isspace():
            i += 1
        elif sql.startswith("--", i):
            nl = sql.find("\n", i)
            i = n if nl == -1 else nl + 1
        elif sql.startswith("/*", i):
            i = _skip_block_comment(sql, i)
        elif ch in "eE" and i + 1 < n and sql[i + 1] == "'":
            end = _scan_string(sql, i + 1, backslash_escapes=True)
            tokens.append(Token(TokenKind.STRING, sql[i:end]))
            i = end
        elif ch == "'":
            end = _scan_string(sql, i, backslash_escapes=False)
            tokens.append(Token(TokenKind.STRING, sql[i:end]))
            i = end
        elif ch == '"':
            end = _scan_quoted_ident(sql, i)
            tokens.append(Token(TokenKind.QUOTED_IDENT, sql[i + 1 : end - 1].replace('""', '"')))
            i = end
        elif ch == "$" and (m := _DOLLAR_TAG.match(sql, i)):
            tag = m.group(0)
            close = sql.find(tag, m.end())
            if close == -1:
                raise ValidationError("unterminated dollar-quoted string")
            tokens.append(Token(TokenKind.STRING, sql[i : close + len(tag)]))
            i = close + len(tag)
        elif _WORD_START.match(ch):
            m2 = _WORD_CHARS.match(sql, i + 1)
            end = m2.end() if m2 else i + 1
            tokens.append(Token(TokenKind.WORD, sql[i:end]))
            i = end
        elif ch.isdigit() or (ch == "." and i + 1 < n and sql[i + 1].isdigit()):
            m3 = _NUMBER.match(sql, i)
            end = m3.end() if m3 else i + 1
            tokens.append(Token(TokenKind.NUMBER, sql[i:end]))
            i = end
        elif ch == ";":
            tokens.append(Token(TokenKind.SEMICOLON, ";"))
            i += 1
        else:
            tokens.append(Token(TokenKind.PUNCT, ch))
            i += 1
    return tokens


def _skip_block_comment(sql: str, start: int) -> int:
    depth, i = 0, start
    while i < len(sql):
        if sql.startswith("/*", i):
            depth += 1
            i += 2
        elif sql.startswith("*/", i):
            depth -= 1
            i += 2
            if depth == 0:
                return i
        else:
            i += 1
    raise ValidationError("unterminated block comment")


def _scan_string(sql: str, quote: int, *, backslash_escapes: bool) -> int:
    i = quote + 1
    while i < len(sql):
        ch = sql[i]
        if backslash_escapes and ch == "\\":
            i += 2
            continue
        if ch == "'":
            if i + 1 < len(sql) and sql[i + 1] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    raise ValidationError("unterminated string literal")


def _scan_quoted_ident(sql: str, quote: int) -> int:
    i = quote + 1
    while i < len(sql):
        if sql[i] == '"':
            if i + 1 < len(sql) and sql[i + 1] == '"':
                i += 2
                continue
            return i + 1
        i += 1
    raise ValidationError("unterminated quoted identifier")


def validate_read_only(sql: str) -> ValidatedQuery:
    """Accept exactly one read-only statement or raise :class:`ValidationError`."""
    if len(sql) > MAX_SQL_LENGTH:
        raise ValidationError(f"query is longer than {MAX_SQL_LENGTH} characters")
    tokens = tokenize(sql)

    # Allow (and drop) trailing semicolons, but never a second statement.
    while tokens and tokens[-1].kind is TokenKind.SEMICOLON:
        tokens.pop()
    if not tokens:
        raise ValidationError("query is empty")
    if any(t.kind is TokenKind.SEMICOLON for t in tokens):
        raise ValidationError("only a single statement is allowed")

    first = tokens[0]
    leading = first.value.upper() if first.kind is TokenKind.WORD else ""
    if first.kind is TokenKind.PUNCT and first.value == "(":
        leading = _first_word(tokens)
    if leading not in ALLOWED_LEADING:
        raise ValidationError(
            f"statement type {leading or first.value!r} is not allowed; "
            f"allowed: {', '.join(sorted(ALLOWED_LEADING))}"
        )

    for index, token in enumerate(tokens):
        if token.kind is not TokenKind.WORD:
            continue
        upper = token.value.upper()
        if upper in FORBIDDEN_KEYWORDS:
            raise ValidationError(f"keyword {upper} is not allowed in read-only queries")
        if token.value.lower() in FORBIDDEN_FUNCTIONS and _is_call(tokens, index):
            raise ValidationError(f"function {token.value.lower()}() is not allowed")

    return ValidatedQuery(sql=sql.strip().rstrip(";").strip(), statement=leading)


def _first_word(tokens: list[Token]) -> str:
    for token in tokens:
        if token.kind is TokenKind.WORD:
            return token.value.upper()
    return ""


def _is_call(tokens: list[Token], index: int) -> bool:
    nxt = tokens[index + 1] if index + 1 < len(tokens) else None
    return nxt is not None and nxt.kind is TokenKind.PUNCT and nxt.value == "("
