from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_devtools.audit import AuditLog, JsonlAuditSink, MemoryAuditSink, build_audit_log
from mcp_devtools.errors import PermissionDenied
from mcp_devtools.security.redact import REDACTED, redact_text, redact_value


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        self.now += 0.25
        return self.now


def test_records_success_with_duration() -> None:
    sink = MemoryAuditSink()
    audit = AuditLog(sink, clock=FakeClock())
    with audit.record("git_log", {"repo": "web", "max_count": 5}) as handle:
        handle.extra["commits"] = 5

    (entry,) = sink.records
    assert entry["tool"] == "git_log"
    assert entry["outcome"] == "ok"
    assert entry["args"] == {"repo": "web", "max_count": 5}
    assert entry["duration_ms"] == 250.0
    assert entry["error"] is None
    assert entry["extra"] == {"commits": 5}
    assert entry["ts"].endswith("+00:00")


def test_records_denials_with_error_code() -> None:
    sink = MemoryAuditSink()
    audit = AuditLog(sink)
    with pytest.raises(PermissionDenied), audit.record("pg_query", {"database": "prod"}):
        raise PermissionDenied("database 'prod' is not allow-listed")
    assert sink.records[0]["outcome"] == "denied"
    assert "prod" in sink.records[0]["error"]


def test_records_unexpected_exceptions() -> None:
    sink = MemoryAuditSink()
    with pytest.raises(RuntimeError), AuditLog(sink).record("x", {}):
        raise RuntimeError("boom")
    assert sink.records[0]["outcome"] == "exception"
    assert sink.records[0]["error"] == "RuntimeError: boom"


def test_arguments_are_redacted() -> None:
    sink = MemoryAuditSink()
    args = {
        "dsn": "postgresql://u:pw@h/db",
        "url": "https://user:hunter2@example.com/x",
        "sql": "SELECT 1 -- password=abc",
        "headers": {"Authorization": "Bearer abc", "Accept": "text/html"},
    }
    with AuditLog(sink).record("http_probe", args):
        pass
    logged = sink.records[0]["args"]
    assert logged["dsn"] == REDACTED
    assert logged["url"] == f"https://user:{REDACTED}@example.com/x"
    assert logged["sql"] == f"SELECT 1 -- password={REDACTED}"
    assert logged["headers"] == {"Authorization": REDACTED, "Accept": "text/html"}


def test_long_values_are_clipped() -> None:
    value = redact_value({"sql": "x" * 2000})["sql"]
    assert len(value) < 600
    assert value.endswith("more>")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("host=db password=s3cret user=a", f"host=db password={REDACTED} user=a"),
        ("Authorization: Bearer eyJhbGciOi.x.y", f"Authorization: Bearer {REDACTED}"),
        ("?api_key=abc&x=1", f"?api_key={REDACTED}&x=1"),
        ("nothing to see", "nothing to see"),
    ],
)
def test_redact_text(raw: str, expected: str) -> None:
    assert redact_text(raw) == expected


def test_jsonl_sink_appends_and_tails(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "audit.jsonl"
    audit = build_audit_log(path)
    for i in range(5):
        with audit.record("t", {"i": i}):
            pass
    lines = path.read_text("utf-8").splitlines()
    assert len(lines) == 5
    assert json.loads(lines[0])["args"] == {"i": 0}
    assert [r["args"]["i"] for r in audit.tail(2)] == [3, 4]


def test_jsonl_tail_tolerates_corrupt_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text('{"tool":"a"}\nnot json\n', "utf-8")
    tail = JsonlAuditSink(path).tail(10)
    assert tail[0] == {"tool": "a"}
    assert "corrupt_line" in tail[1]


def test_tail_of_missing_file_is_empty(tmp_path: Path) -> None:
    assert JsonlAuditSink(tmp_path / "none.jsonl").tail(5) == []


def test_memory_sink_capacity() -> None:
    sink = MemoryAuditSink(capacity=2)
    for i in range(3):
        sink.write({"i": i})
    assert sink.tail(10) == [{"i": 1}, {"i": 2}]
