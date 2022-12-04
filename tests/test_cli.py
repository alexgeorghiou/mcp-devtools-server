from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from typer.testing import CliRunner

from mcp_devtools import __version__
from mcp_devtools.cli import _is_loopback, app
from mcp_devtools.http_auth import BearerTokenMiddleware

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_check_config_prints_redacted_view(tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "postgres:\n"
        "  databases:\n"
        "    app: postgresql://u:topsecret@h/db\n"
        "docker:\n"
        "  enabled: false\n",
        "utf-8",
    )
    result = runner.invoke(app, ["check-config", "--config", str(cfg)])
    assert result.exit_code == 0, result.output
    view = json.loads(result.stdout)
    assert view["postgres"]["databases"] == ["app"]
    assert "docker" not in view["enabled_tools"]
    assert "topsecret" not in result.stdout


def test_check_config_reports_errors(tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("http:\n  timeout_seconds: -1\n", "utf-8")
    result = runner.invoke(app, ["check-config", "-c", str(cfg)])
    assert result.exit_code == 2
    assert "configuration error" in result.output


@pytest.mark.parametrize(
    ("sql", "code"), [("SELECT 1", 0), ("DELETE FROM t", 1), ("SELECT 1; SELECT 2", 1)]
)
def test_validate_sql(sql: str, code: int) -> None:
    assert runner.invoke(app, ["validate-sql", sql]).exit_code == code


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("localhost", True),
        ("0.0.0.0", False),
        ("myhost", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert _is_loopback(host) is expected


def _app() -> Starlette:
    async def ok(_request: object) -> PlainTextResponse:
        return PlainTextResponse("ok")

    return Starlette(routes=[Route("/mcp", ok, methods=["GET", "POST"]), Route("/health", ok)])


def test_bearer_token_middleware() -> None:
    client = TestClient(BearerTokenMiddleware(_app(), "t0ken", exempt_paths=frozenset({"/health"})))
    assert client.post("/mcp").status_code == 401
    assert client.post("/mcp", headers={"Authorization": "Bearer wrong"}).status_code == 401
    denied = client.get("/mcp", headers={"Authorization": "Basic t0ken"})
    assert denied.headers["www-authenticate"].startswith("Bearer")
    assert client.post("/mcp", headers={"Authorization": "Bearer t0ken"}).text == "ok"
    assert client.get("/health").status_code == 200


def test_bearer_token_must_not_be_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        BearerTokenMiddleware(_app(), "")
