from __future__ import annotations

from pathlib import Path

import pytest

from mcp_devtools.config import Settings, expand_env, load_settings
from mcp_devtools.errors import ConfigError

YAML = """
server:
  audit_log: audit/devtools.jsonl
git:
  repos:
    web: ./checkouts/web
postgres:
  databases:
    app: "postgresql://reader:${PG_PASSWORD}@localhost:5432/app"
  max_rows: 100
http:
  allowed_hosts: ["status.example.com"]
logs:
  directories:
    api: /var/log/api
"""


def test_defaults_are_deny_all() -> None:
    settings = Settings()
    assert settings.git.repos == {}
    assert settings.docker.containers == []
    assert settings.postgres.databases == {}
    assert settings.http.allowed_hosts == []
    assert settings.http.allow_private_networks is False
    assert settings.enabled_tools() == ["git", "docker", "postgres", "http", "logs"]


def test_load_yaml_with_env_and_relative_paths(tmp_path: Path) -> None:
    cfg = tmp_path / "devtools.yaml"
    cfg.write_text(YAML, "utf-8")
    settings = load_settings(cfg, env={"PG_PASSWORD": "pw"})

    assert settings.postgres.databases["app"] == "postgresql://reader:pw@localhost:5432/app"
    assert settings.postgres.max_rows == 100
    assert settings.git.repos["web"] == (tmp_path / "checkouts" / "web").resolve()
    assert settings.server.audit_log == tmp_path / "audit" / "devtools.jsonl"
    assert settings.logs.directories["api"].name == "api"


def test_load_toml(tmp_path: Path) -> None:
    cfg = tmp_path / "devtools.toml"
    cfg.write_text('[docker]\ncontainers = ["api-*"]\n\n[http]\nenabled = false\n', "utf-8")
    settings = load_settings(cfg, env={})
    assert settings.docker.containers == ["api-*"]
    assert "http" not in settings.enabled_tools()


def test_config_path_from_environment(tmp_path: Path) -> None:
    cfg = tmp_path / "c.yml"
    cfg.write_text("docker:\n  containers: [web]\n", "utf-8")
    assert load_settings(env={"MCP_DEVTOOLS_CONFIG": str(cfg)}).docker.containers == ["web"]


def test_disable_via_environment() -> None:
    settings = load_settings(env={"MCP_DEVTOOLS_DISABLE": "docker, postgres"})
    assert settings.enabled_tools() == ["git", "http", "logs"]


def test_unknown_tool_in_disable_list() -> None:
    with pytest.raises(ConfigError, match="unknown tool"):
        load_settings(env={"MCP_DEVTOOLS_DISABLE": "kubernetes"})


def test_audit_log_override(tmp_path: Path) -> None:
    target = tmp_path / "a.jsonl"
    settings = load_settings(env={"MCP_DEVTOOLS_AUDIT_LOG": str(target)})
    assert settings.server.audit_log == target


def test_missing_env_reference_fails_loudly() -> None:
    with pytest.raises(ConfigError, match="PG_PASSWORD"):
        expand_env({"dsn": "postgresql://u:${PG_PASSWORD}@h/db"}, {})


def test_env_default_value() -> None:
    assert expand_env(["${HOST:-localhost}"], {}) == ["localhost"]


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("bad.yaml", "git: [unclosed", "cannot parse"),
        ("list.yaml", "- a\n- b\n", "mapping"),
        ("conf.ini", "[x]", "unsupported"),
        ("typo.yaml", "gti:\n  repos: {}\n", "invalid configuration"),
        ("range.yaml", "postgres:\n  max_rows: 0\n", "invalid configuration"),
    ],
)
def test_invalid_files(tmp_path: Path, name: str, content: str, message: str) -> None:
    cfg = tmp_path / name
    cfg.write_text(content, "utf-8")
    with pytest.raises(ConfigError, match=message):
        load_settings(cfg, env={})


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_settings(tmp_path / "nope.yaml", env={})


def test_public_view_hides_dsns(settings: Settings) -> None:
    view = settings.public_view()
    assert view["postgres"]["databases"] == ["app"]
    assert "s3cret" not in str(view)


def test_example_config_is_valid() -> None:
    example = Path(__file__).parent.parent / "examples" / "devtools.example.yaml"
    settings = load_settings(example, env={"DEVTOOLS_PG_PASSWORD": "x"})
    assert settings.enabled_tools()
