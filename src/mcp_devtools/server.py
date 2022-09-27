"""Server assembly: build an :class:`MCPServer` from settings and backends."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from mcp_devtools import __version__, prompts, resources
from mcp_devtools.config import Settings
from mcp_devtools.tools import db_tools, docker_tools, git_tools, http_tools, log_tools
from mcp_devtools.tools.context import Backends, ToolContext

INSTRUCTIONS = """\
Developer tools with guard rails. Every resource you can touch (repositories,
containers, databases, hosts, log directories) is referred to by the alias the
operator configured; call `git_list_repos` or read `devtools://config` to discover
them. All tools are read-only. Requests outside the allow-lists fail with a
[denied] error - do not retry them with variations."""

_FAMILIES = {
    "git": git_tools.register,
    "docker": docker_tools.register,
    "postgres": db_tools.register,
    "http": http_tools.register,
    "logs": log_tools.register,
}


def build_server(
    settings: Settings,
    *,
    backends: Backends | None = None,
    context: ToolContext | None = None,
) -> MCPServer:
    """Create the server. Disabled tool families are not registered at all."""
    ctx = context or ToolContext(settings, backends)
    server = MCPServer(
        name=settings.server.name,
        title="MCP DevTools",
        instructions=INSTRUCTIONS,
        version=__version__,
    )
    for name in settings.enabled_tools():
        _FAMILIES[name](server, ctx)
    resources.register(server, ctx)
    prompts.register(server, settings)
    return server
