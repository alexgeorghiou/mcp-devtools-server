"""Shared wiring for tool families: settings, policy, audit and backends."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, TypeVar

from mcp.server.mcpserver.exceptions import ToolError

from mcp_devtools.audit import AuditLog, MemoryAuditSink, build_audit_log
from mcp_devtools.backends.docker import DockerBackend, DockerCliBackend
from mcp_devtools.backends.git import GitBackend, SubprocessGitBackend
from mcp_devtools.backends.http import HttpProber, HttpxProber
from mcp_devtools.backends.logs import FileSystemLogSearcher, LogSearcher
from mcp_devtools.backends.postgres import PsycopgBackend, QueryBackend
from mcp_devtools.config import Settings
from mcp_devtools.errors import DevToolsError
from mcp_devtools.security.permissions import Policy
from mcp_devtools.security.ssrf import Resolver, SsrfGuard, system_resolver

T = TypeVar("T")


@dataclass
class Backends:
    git: GitBackend
    docker: DockerBackend
    postgres: QueryBackend
    http: HttpProber
    logs: LogSearcher
    resolver: Resolver = field(default=system_resolver)

    @classmethod
    def default(cls, settings: Settings) -> Backends:
        return cls(
            git=SubprocessGitBackend(timeout=settings.git.timeout_seconds),
            docker=DockerCliBackend(
                binary=settings.docker.docker_binary, timeout=settings.docker.timeout_seconds
            ),
            postgres=PsycopgBackend(connect_timeout=settings.postgres.connect_timeout_seconds),
            http=HttpxProber(),
            logs=FileSystemLogSearcher(
                file_globs=settings.logs.file_globs,
                max_file_bytes=settings.logs.max_file_bytes,
            ),
        )


def to_plain(value: Any) -> Any:
    """Dataclasses -> dicts, recursively, so tool results serialise cleanly."""
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, list):
        return [to_plain(v) for v in value]
    return value


class ToolContext:
    def __init__(
        self,
        settings: Settings,
        backends: Backends | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.settings = settings
        self.policy = Policy(settings)
        self.backends = backends or Backends.default(settings)
        self.audit = audit or build_audit_log(settings.server.audit_log)
        self.ssrf = SsrfGuard(self.policy, self.backends.resolver)

    @classmethod
    def for_testing(cls, settings: Settings, backends: Backends) -> ToolContext:
        return cls(settings, backends, AuditLog(MemoryAuditSink()))

    def run(self, tool: str, args: Mapping[str, Any], fn: Callable[[], T]) -> T:
        """Execute ``fn`` under the audit log, mapping known errors to MCP tool errors."""
        try:
            with self.audit.record(tool, args):
                return fn()
        except DevToolsError as exc:
            raise ToolError(f"[{exc.code}] {exc}") from exc
