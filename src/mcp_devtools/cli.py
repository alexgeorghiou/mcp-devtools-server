"""Command line entry point: ``mcp-devtools serve|check-config|validate-sql``."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from mcp_devtools import __version__
from mcp_devtools.config import Settings, load_settings
from mcp_devtools.errors import DevToolsError
from mcp_devtools.http_auth import ENV_HTTP_TOKEN, BearerTokenMiddleware
from mcp_devtools.security.sql_guard import validate_read_only
from mcp_devtools.server import build_server

app = typer.Typer(
    name="mcp-devtools",
    help="Model Context Protocol server exposing guarded developer tools.",
    no_args_is_help=True,
    add_completion=False,
)

log = logging.getLogger("mcp_devtools")


class Transport(StrEnum):
    stdio = "stdio"
    http = "http"


ConfigOption = Annotated[
    Path | None,
    typer.Option(
        "--config",
        "-c",
        help="YAML/TOML config file (default: $MCP_DEVTOOLS_CONFIG).",
        exists=True,
        dir_okay=False,
    ),
]


def _load(config: Path | None) -> Settings:
    try:
        return load_settings(config)
    except DevToolsError as exc:
        typer.secho(f"configuration error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@app.command()
def serve(
    config: ConfigOption = None,
    transport: Annotated[
        Transport, typer.Option("--transport", "-t", help="stdio or streamable HTTP.")
    ] = Transport.stdio,
    host: Annotated[str, typer.Option(help="Bind address for --transport http.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port for --transport http.")] = 8765,
    path: Annotated[str, typer.Option(help="Endpoint path for --transport http.")] = "/mcp",
    stateless: Annotated[
        bool, typer.Option(help="Stateless HTTP mode (no session affinity needed).")
    ] = False,
    log_level: Annotated[str, typer.Option(help="Python log level.")] = "INFO",
) -> None:
    """Run the MCP server."""
    # stdout belongs to the protocol on stdio, so all logging goes to stderr.
    logging.basicConfig(
        level=log_level.upper(),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    settings = _load(config)
    enabled = settings.enabled_tools()
    log.info("mcp-devtools %s starting; tools enabled: %s", __version__, ", ".join(enabled))
    if not config and not os.environ.get("MCP_DEVTOOLS_CONFIG"):
        log.warning("no config file given: every allow-list is empty, so tools will deny access")

    server = build_server(settings)
    if transport is Transport.stdio:
        server.run("stdio")
        return

    import uvicorn

    token = os.environ.get(ENV_HTTP_TOKEN, "")
    if not _is_loopback(host) and not token:
        log.warning(
            "binding %s without %s set: the endpoint is unauthenticated", host, ENV_HTTP_TOKEN
        )
    asgi = server.streamable_http_app(
        streamable_http_path=path, stateless_http=stateless, host=host
    )
    asgi_app = BearerTokenMiddleware(asgi, token) if token else asgi
    log.info("streamable HTTP endpoint: http://%s:%d%s", host, port, path)
    uvicorn.run(asgi_app, host=host, port=port, log_level=log_level.lower())


@app.command("check-config")
def check_config(config: ConfigOption = None) -> None:
    """Validate the configuration and print the effective, redacted view."""
    settings = _load(config)
    view = settings.public_view()
    view["enabled_tools"] = settings.enabled_tools()
    typer.echo(json.dumps(view, indent=2))


@app.command("validate-sql")
def validate_sql(sql: Annotated[str, typer.Argument(help="SQL text to check.")]) -> None:
    """Check whether a statement would be accepted by the read-only query tool."""
    try:
        checked = validate_read_only(sql)
    except DevToolsError as exc:
        typer.secho(f"rejected: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    typer.secho(f"accepted ({checked.statement})", fg=typer.colors.GREEN)


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
