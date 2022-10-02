"""In-memory stand-ins for the external systems behind each backend Protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_devtools.backends.docker import ContainerSummary
from mcp_devtools.backends.http import HopResult, TlsInfo
from mcp_devtools.backends.postgres import QueryResult
from mcp_devtools.errors import BackendError


@dataclass
class FakeDocker:
    containers: list[ContainerSummary] = field(default_factory=list)
    log_text: dict[str, str] = field(default_factory=dict)
    inspections: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[tuple[str, Any]] = field(default_factory=list)

    def list_containers(self, *, include_stopped: bool = False) -> list[ContainerSummary]:
        self.calls.append(("ps", include_stopped))
        return [c for c in self.containers if include_stopped or c.state == "running"]

    def logs(
        self, name: str, *, tail: int, since: str | None = None, timestamps: bool = True
    ) -> str:
        self.calls.append(("logs", (name, tail, since)))
        if name not in self.log_text:
            raise BackendError(f"no such container: {name}")
        return "\n".join(self.log_text[name].splitlines()[-tail:])

    def inspect(self, name: str) -> dict[str, Any]:
        self.calls.append(("inspect", name))
        if name not in self.inspections:
            raise BackendError(f"no such container: {name}")
        return self.inspections[name]


@dataclass
class FakePostgres:
    result: QueryResult = field(
        default_factory=lambda: QueryResult(["n"], [[1]], truncated=False, duration_ms=1.0)
    )
    calls: list[dict[str, Any]] = field(default_factory=list)

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
        self.calls.append(
            {
                "dsn": dsn,
                "sql": sql,
                "statement": statement,
                "max_rows": max_rows,
                "timeout_ms": timeout_ms,
                "params": params,
            }
        )
        rows = self.result.rows[:max_rows]
        truncated = len(self.result.rows) > max_rows
        return QueryResult(self.result.columns, rows, truncated, self.result.duration_ms)


def hop(
    url: str,
    status: int = 200,
    *,
    headers: dict[str, str] | None = None,
    peer: str = "93.184.215.14",
    tls: bool = True,
    body: str | None = None,
) -> HopResult:
    return HopResult(
        url=url,
        status=status,
        reason="OK" if status < 300 else "Redirect",
        http_version="HTTP/1.1",
        headers=headers or {"content-type": "text/html"},
        elapsed_ms=12.5,
        peer_address=peer,
        tls=TlsInfo(
            "TLSv1.3",
            "TLS_AES_128_GCM_SHA256",
            "commonName=example.com",
            "commonName=Test CA",
            "Jan  1 00:00:00 2026 GMT",
            "Dec 31 23:59:59 2026 GMT",
            ["example.com"],
        )
        if tls
        else None,
        body_preview=body,
    )


@dataclass
class FakeProber:
    responses: dict[str, HopResult] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    def fetch(self, url: str, *, method: str, timeout: float, read_body: bool) -> HopResult:
        self.calls.append(url)
        if url not in self.responses:
            raise AssertionError(f"unexpected probe of {url}")
        return self.responses[url]


@dataclass
class FakeResolver:
    table: dict[str, list[str]] = field(default_factory=dict)

    def __call__(self, host: str, port: int) -> list[str]:
        return self.table.get(host, [])
