"""Exception hierarchy shared by tools, backends and guards.

Every error raised to an MCP client derives from :class:`DevToolsError` so the
server can distinguish "the request was refused / failed in a known way" from
genuine bugs, and so the audit log can record a stable outcome code.
"""

from __future__ import annotations


class DevToolsError(Exception):
    """Base class for all expected, client-facing errors."""

    code: str = "error"


class ConfigError(DevToolsError):
    """The configuration file or environment is invalid."""

    code = "config_error"


class PermissionDenied(DevToolsError):
    """The requested resource is not on the tool's allow-list."""

    code = "denied"


class ToolDisabled(PermissionDenied):
    """The tool family is switched off in configuration."""

    code = "disabled"


class ValidationError(DevToolsError):
    """Arguments were syntactically valid but semantically rejected."""

    code = "invalid"


class BackendError(DevToolsError):
    """The underlying command, database or network call failed."""

    code = "backend_error"
