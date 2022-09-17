"""Docker tools: list, logs and inspect for allow-listed containers."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_devtools.security.permissions import matches_any
from mcp_devtools.security.redact import redact_text
from mcp_devtools.tools.context import ToolContext, to_plain

READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)

Container = Annotated[
    str, Field(description="Container name; must match the docker.containers allow-list")
]


class DockerTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx
        self.docker = ctx.backends.docker
        self.cfg = ctx.settings.docker

    def ps(self, include_stopped: bool = False) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            self.ctx.policy.require_enabled("docker")
            visible = [
                c
                for c in self.docker.list_containers(include_stopped=include_stopped)
                if matches_any(c.name, self.cfg.containers)
            ]
            return {"count": len(visible), "containers": to_plain(visible)}

        return self.ctx.run("docker_ps", {"include_stopped": include_stopped}, run)

    def logs(
        self,
        container: str,
        tail: int = 200,
        since: str | None = None,
        grep: str | None = None,
    ) -> dict[str, Any]:
        args = {"container": container, "tail": tail, "since": since, "grep": grep}

        def run() -> dict[str, Any]:
            name = self.ctx.policy.container(container)
            lines_wanted = max(1, min(tail, self.cfg.max_log_lines))
            text = self.docker.logs(name, tail=lines_wanted, since=since)
            lines = text.splitlines()
            if grep:
                needle = grep.lower()
                lines = [line for line in lines if needle in line.lower()]
            return {
                "container": name,
                "line_count": len(lines),
                "lines": [redact_text(line) for line in lines],
            }

        return self.ctx.run("docker_logs", args, run)

    def inspect(self, container: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            name = self.ctx.policy.container(container)
            return self.docker.inspect(name)

        return self.ctx.run("docker_inspect", {"container": container}, run)


def register(server: MCPServer, ctx: ToolContext) -> None:
    tools = DockerTools(ctx)

    @server.tool(annotations=READ_ONLY)
    def docker_ps(
        include_stopped: Annotated[bool, Field(description="Include exited containers")] = False,
    ) -> dict[str, Any]:
        """List allow-listed containers with image, state, status and ports."""
        return tools.ps(include_stopped)

    @server.tool(annotations=READ_ONLY)
    def docker_logs(
        container: Container,
        tail: Annotated[int, Field(ge=1, le=10_000, description="Lines from the end")] = 200,
        since: Annotated[str | None, Field(description="Relative (15m, 2h) or ISO date")] = None,
        grep: Annotated[str | None, Field(description="Case-insensitive substring filter")] = None,
    ) -> dict[str, Any]:
        """Fetch recent container logs (stdout and stderr), with secrets masked."""
        return tools.logs(container, tail, since, grep)

    @server.tool(annotations=READ_ONLY)
    def docker_inspect(container: Container) -> dict[str, Any]:
        """Summarised `docker inspect`: state, exit code, health, restarts, ports, mounts."""
        return tools.inspect(container)
