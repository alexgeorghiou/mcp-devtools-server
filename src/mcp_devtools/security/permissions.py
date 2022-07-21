"""Allow-list checks shared by every tool family.

The policy object is intentionally dumb: it answers "may this tool touch that
resource?" from the loaded :class:`~mcp_devtools.config.Settings` and raises
:class:`PermissionDenied` otherwise. Tools call it *before* doing any work.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path

from mcp_devtools.config import Settings, ToolName
from mcp_devtools.errors import PermissionDenied, ToolDisabled


def matches_any(value: str, patterns: list[str]) -> bool:
    """Case-insensitive fnmatch against a list of patterns (exact names are patterns too)."""
    lowered = value.lower()
    return any(fnmatchcase(lowered, pattern.lower()) for pattern in patterns)


class Policy:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def require_enabled(self, tool: ToolName) -> None:
        if not self.settings.is_enabled(tool):
            raise ToolDisabled(f"the {tool} tools are disabled in this server's configuration")

    def repo(self, alias: str) -> Path:
        self.require_enabled("git")
        repos = self.settings.git.repos
        if alias not in repos:
            raise PermissionDenied(
                f"repository {alias!r} is not allow-listed; known: {sorted(repos) or 'none'}"
            )
        return repos[alias]

    def container(self, name: str) -> str:
        self.require_enabled("docker")
        if not name or not matches_any(name, self.settings.docker.containers):
            raise PermissionDenied(f"container {name!r} is not allow-listed")
        return name

    def database(self, alias: str) -> str:
        self.require_enabled("postgres")
        dbs = self.settings.postgres.databases
        if alias not in dbs:
            raise PermissionDenied(
                f"database {alias!r} is not allow-listed; known: {sorted(dbs) or 'none'}"
            )
        return dbs[alias]

    def host(self, host: str) -> str:
        self.require_enabled("http")
        if not host or not matches_any(host.rstrip("."), self.settings.http.allowed_hosts):
            raise PermissionDenied(f"host {host!r} is not allow-listed")
        return host

    def port(self, port: int) -> int:
        if port not in self.settings.http.allowed_ports:
            raise PermissionDenied(f"port {port} is not allow-listed")
        return port

    def log_dir(self, alias: str) -> Path:
        self.require_enabled("logs")
        dirs = self.settings.logs.directories
        if alias not in dirs:
            raise PermissionDenied(
                f"log directory {alias!r} is not allow-listed; known: {sorted(dirs) or 'none'}"
            )
        return dirs[alias]
