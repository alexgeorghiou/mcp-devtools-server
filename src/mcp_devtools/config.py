"""Configuration model and loader.

Configuration comes from a YAML or TOML file plus a small set of environment
variables. Everything that grants access (repositories, containers, database
DSNs, hosts, log directories) is an explicit allow-list: an empty list means
"nothing is allowed", never "everything is allowed".

String values may reference environment variables as ``${NAME}`` or
``${NAME:-default}`` so secrets such as database passwords never have to live
in the file itself.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic import ValidationError as PydanticValidationError

from mcp_devtools.errors import ConfigError

ENV_CONFIG_PATH = "MCP_DEVTOOLS_CONFIG"
ENV_AUDIT_LOG = "MCP_DEVTOOLS_AUDIT_LOG"
ENV_DISABLE = "MCP_DEVTOOLS_DISABLE"

_ENV_REF = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?P<default>[^}]*))?\}")

ToolName = Literal["git", "docker", "postgres", "http", "logs"]
TOOL_NAMES: tuple[ToolName, ...] = ("git", "docker", "postgres", "http", "logs")


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ServerSettings(_Section):
    name: str = "devtools"
    audit_log: Path | None = None
    audit_tail_lines: int = Field(default=50, ge=1, le=5000)
    expose_config_resource: bool = True


class GitSettings(_Section):
    enabled: bool = True
    repos: dict[str, Path] = Field(default_factory=dict)
    max_output_bytes: int = Field(default=200_000, ge=1_000)
    max_log_entries: int = Field(default=200, ge=1)
    timeout_seconds: float = Field(default=15.0, gt=0)

    @field_validator("repos")
    @classmethod
    def _resolve_repos(cls, value: dict[str, Path]) -> dict[str, Path]:
        return {alias: path.expanduser().resolve() for alias, path in value.items()}


class DockerSettings(_Section):
    enabled: bool = True
    containers: list[str] = Field(
        default_factory=list,
        description="Container names or fnmatch patterns that may be inspected.",
    )
    max_log_lines: int = Field(default=500, ge=1, le=10_000)
    timeout_seconds: float = Field(default=15.0, gt=0)
    docker_binary: str = "docker"


class PostgresSettings(_Section):
    enabled: bool = True
    databases: dict[str, str] = Field(
        default_factory=dict, description="Alias -> libpq DSN / connection URI."
    )
    max_rows: int = Field(default=500, ge=1, le=50_000)
    statement_timeout_ms: int = Field(default=5_000, ge=100, le=300_000)
    connect_timeout_seconds: int = Field(default=5, ge=1, le=60)


class HttpSettings(_Section):
    enabled: bool = True
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Hostnames or fnmatch patterns (e.g. '*.example.dev').",
    )
    allow_private_networks: bool = False
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443, 8080, 8443])
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_redirects: int = Field(default=3, ge=0, le=10)


class LogSettings(_Section):
    enabled: bool = True
    directories: dict[str, Path] = Field(default_factory=dict)
    max_results: int = Field(default=200, ge=1, le=10_000)
    max_context_lines: int = Field(default=5, ge=0, le=50)
    max_file_bytes: int = Field(default=50 * 1024 * 1024, ge=1024)
    file_globs: list[str] = Field(default_factory=lambda: ["*.log", "*.log.*", "*.jsonl", "*.txt"])

    @field_validator("directories")
    @classmethod
    def _resolve_dirs(cls, value: dict[str, Path]) -> dict[str, Path]:
        return {alias: path.expanduser().resolve() for alias, path in value.items()}


class Settings(_Section):
    server: ServerSettings = Field(default_factory=ServerSettings)
    git: GitSettings = Field(default_factory=GitSettings)
    docker: DockerSettings = Field(default_factory=DockerSettings)
    postgres: PostgresSettings = Field(default_factory=PostgresSettings)
    http: HttpSettings = Field(default_factory=HttpSettings)
    logs: LogSettings = Field(default_factory=LogSettings)

    def is_enabled(self, tool: ToolName) -> bool:
        section: Any = getattr(self, tool)
        return bool(section.enabled)

    def enabled_tools(self) -> list[ToolName]:
        return [name for name in TOOL_NAMES if self.is_enabled(name)]

    def public_view(self) -> dict[str, Any]:
        """Config as exposed to clients: DSNs are reduced to alias names only."""
        data = self.model_dump(mode="json")
        data["postgres"]["databases"] = sorted(self.postgres.databases)
        return data


def expand_env(value: Any, env: Mapping[str, str]) -> Any:
    """Recursively substitute ``${VAR}`` / ``${VAR:-default}`` in string values."""
    if isinstance(value, str):

        def _sub(match: re.Match[str]) -> str:
            name, default = match.group("name"), match.group("default")
            if name in env:
                return env[name]
            if default is not None:
                return default
            raise ConfigError(f"environment variable {name!r} is referenced but not set")

        return _ENV_REF.sub(_sub, value)
    if isinstance(value, list):
        return [expand_env(item, env) for item in value]
    if isinstance(value, dict):
        return {key: expand_env(item, env) for key, item in value.items()}
    return value


def _read_file(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc

    suffix = path.suffix.lower()
    try:
        if suffix == ".toml":
            data: Any = tomllib.loads(text)
        elif suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(text) or {}
        else:
            raise ConfigError(f"unsupported config format {suffix!r}; use .yaml, .yml or .toml")
    except (yaml.YAMLError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot parse {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


def _apply_env_overrides(data: dict[str, Any], env: Mapping[str, str]) -> dict[str, Any]:
    if audit := env.get(ENV_AUDIT_LOG):
        data.setdefault("server", {})["audit_log"] = audit
    if disabled := env.get(ENV_DISABLE):
        for raw in disabled.split(","):
            name = raw.strip().lower()
            if not name:
                continue
            if name not in TOOL_NAMES:
                raise ConfigError(f"{ENV_DISABLE}: unknown tool {name!r}")
            data.setdefault(name, {})["enabled"] = False
    return data


def load_settings(
    path: Path | str | None = None,
    env: Mapping[str, str] | None = None,
) -> Settings:
    """Load settings from ``path`` (or ``$MCP_DEVTOOLS_CONFIG``) and the environment.

    With no file at all the server starts with every allow-list empty, which is
    safe but not very useful; the CLI warns about this.
    """
    env = os.environ if env is None else env
    raw_path = path if path is not None else env.get(ENV_CONFIG_PATH)

    data: dict[str, Any] = {}
    base_dir = Path.cwd()
    if raw_path:
        file_path = Path(raw_path).expanduser()
        data = _read_file(file_path)
        base_dir = file_path.resolve().parent

    data = expand_env(data, env)
    data = _apply_env_overrides(data, env)
    _make_paths_relative_to(data, base_dir)

    try:
        return Settings.model_validate(data)
    except PydanticValidationError as exc:
        raise ConfigError(f"invalid configuration:\n{exc}") from exc


def _make_paths_relative_to(data: dict[str, Any], base: Path) -> None:
    """Resolve relative paths in the file against the file's directory, not the CWD."""

    def _fix(value: Any) -> Any:
        if isinstance(value, str) and value and not Path(value).expanduser().is_absolute():
            return str(base / value)
        return value

    server = data.get("server")
    if isinstance(server, dict) and "audit_log" in server:
        server["audit_log"] = _fix(server["audit_log"])
    for section, key in (("git", "repos"), ("logs", "directories")):
        block = data.get(section)
        if isinstance(block, dict) and isinstance(block.get(key), dict):
            block[key] = {alias: _fix(p) for alias, p in block[key].items()}
