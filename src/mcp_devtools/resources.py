"""MCP resources: server config, audit tail, and repository files at HEAD."""

from __future__ import annotations

import json
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError

from mcp_devtools.errors import DevToolsError
from mcp_devtools.tools.context import ToolContext

README_CANDIDATES = ("README.md", "README.rst", "README.txt", "README")


def read_repo_file(ctx: ToolContext, repo: str, path: str) -> str:
    try:
        with ctx.audit.record("resource:repo_file", {"repo": repo, "path": path}):
            root = ctx.policy.repo(repo)
            return ctx.backends.git.read_file(
                root, path, rev="HEAD", max_bytes=ctx.settings.git.max_output_bytes
            )
    except DevToolsError as exc:
        raise ResourceError(f"[{exc.code}] {exc}") from exc


def read_repo_readme(ctx: ToolContext, repo: str) -> str:
    last: ResourceError | None = None
    for candidate in README_CANDIDATES:
        try:
            return read_repo_file(ctx, repo, candidate)
        except ResourceError as exc:
            if "[denied]" in str(exc) or "[disabled]" in str(exc):
                raise
            last = exc
    raise ResourceError(f"no README found in {repo!r}") from last


def register(server: MCPServer, ctx: ToolContext) -> None:
    settings = ctx.settings

    if settings.server.expose_config_resource:

        @server.resource(
            "devtools://config",
            name="server-config",
            description="Effective server configuration (DSNs reduced to aliases).",
            mime_type="application/json",
        )
        def server_config() -> str:
            view: dict[str, Any] = settings.public_view()
            view["enabled_tools"] = settings.enabled_tools()
            return json.dumps(view, indent=2)

    @server.resource(
        "devtools://audit/tail",
        name="audit-tail",
        description="Most recent audit log entries (JSON lines, newest last).",
        mime_type="application/x-ndjson",
    )
    def audit_tail() -> str:
        records = ctx.audit.tail(settings.server.audit_tail_lines)
        return "\n".join(json.dumps(r, separators=(",", ":")) for r in records)

    if settings.git.enabled:

        @server.resource(
            "repo://{repo}/readme",
            name="repo-readme",
            description="README of an allow-listed repository at HEAD.",
            mime_type="text/markdown",
        )
        def repo_readme(repo: str) -> str:
            return read_repo_readme(ctx, repo)

        @server.resource(
            "repo://{repo}/files/{+path}",
            name="repo-file",
            description="Any tracked file of an allow-listed repository at HEAD.",
            mime_type="text/plain",
        )
        def repo_file(repo: str, path: str) -> str:
            return read_repo_file(ctx, repo, path)
