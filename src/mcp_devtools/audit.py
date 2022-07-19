"""Structured audit trail of every tool invocation.

Each call produces exactly one JSON line::

    {"ts": "...", "tool": "git_log", "args": {...}, "outcome": "ok",
     "duration_ms": 12.4, "error": null}

Arguments are passed through :func:`redact_value` before they are written so
DSNs, tokens and long payloads never land on disk verbatim.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from mcp_devtools.errors import DevToolsError
from mcp_devtools.security.redact import redact_text, redact_value


class AuditSink(Protocol):
    def write(self, record: Mapping[str, Any]) -> None: ...

    def tail(self, lines: int) -> list[dict[str, Any]]: ...


@dataclass
class MemoryAuditSink:
    """Keeps the most recent records in memory; used in tests and when no file is configured."""

    capacity: int = 1000
    records: deque[dict[str, Any]] = field(init=False)

    def __post_init__(self) -> None:
        self.records = deque(maxlen=self.capacity)

    def write(self, record: Mapping[str, Any]) -> None:
        self.records.append(dict(record))

    def tail(self, lines: int) -> list[dict[str, Any]]:
        return list(self.records)[-lines:]


class JsonlAuditSink:
    """Append-only JSON-lines file. Thread-safe within a process."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: Mapping[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def tail(self, lines: int) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self._lock, self.path.open("r", encoding="utf-8") as fh:
            recent = deque(fh, maxlen=lines)
        out: list[dict[str, Any]] = []
        for raw in recent:
            try:
                out.append(json.loads(raw))
            except json.JSONDecodeError:
                out.append({"corrupt_line": raw.rstrip("\n")[:200]})
        return out


@dataclass
class AuditOutcome:
    """Mutable handle a tool can use to attach extra, non-sensitive facts to its record."""

    extra: dict[str, Any] = field(default_factory=dict)


class AuditLog:
    def __init__(self, sink: AuditSink, *, clock: Any = time.perf_counter) -> None:
        self.sink = sink
        self._clock = clock

    @contextmanager
    def record(self, tool: str, args: Mapping[str, Any]) -> Iterator[AuditOutcome]:
        """Time a tool call and write one audit line whatever its result."""
        handle = AuditOutcome()
        started = self._clock()
        outcome, error = "ok", None
        try:
            yield handle
        except DevToolsError as exc:
            outcome, error = exc.code, redact_text(str(exc))
            raise
        except Exception as exc:
            outcome, error = "exception", f"{type(exc).__name__}: {redact_text(str(exc))}"
            raise
        finally:
            entry: dict[str, Any] = {
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "tool": tool,
                "args": redact_value(dict(args)),
                "outcome": outcome,
                "duration_ms": round((self._clock() - started) * 1000, 2),
                "error": error,
            }
            if handle.extra:
                entry["extra"] = redact_value(handle.extra)
            self.sink.write(entry)

    def tail(self, lines: int) -> list[dict[str, Any]]:
        return self.sink.tail(lines)


def build_audit_log(path: Path | None) -> AuditLog:
    return AuditLog(JsonlAuditSink(path) if path else MemoryAuditSink())
