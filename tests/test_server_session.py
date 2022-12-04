"""End-to-end tests through a real MCP client session, connected in memory."""

from __future__ import annotations

import json

import pytest
from mcp.client import Client
from mcp.types import TextContent

from mcp_devtools.config import Settings
from mcp_devtools.server import build_server
from mcp_devtools.tools.context import Backends, ToolContext

pytestmark = pytest.mark.anyio

ALL_TOOLS = {
    "git_list_repos", "git_log", "git_show", "git_diff", "git_blame", "git_status",
    "docker_ps", "docker_logs", "docker_inspect",
    "pg_query", "pg_explain", "pg_list_tables",
    "http_probe",
    "logs_list_files", "logs_search",
}  # fmt: skip


def _text(result: object) -> str:
    content = result.content[0]  # type: ignore[attr-defined]
    assert isinstance(content, TextContent)
    return content.text


async def test_lists_all_tools_with_read_only_annotations(ctx: ToolContext) -> None:
    async with Client(build_server(ctx.settings, context=ctx)) as client:
        tools = (await client.list_tools()).tools
    assert {t.name for t in tools} == ALL_TOOLS
    for tool in tools:
        assert tool.annotations is not None and tool.annotations.read_only_hint is True
        assert tool.description
    git_log = next(t for t in tools if t.name == "git_log")
    assert git_log.input_schema["required"] == ["repo"]


async def test_call_tool_returns_structured_content(ctx: ToolContext) -> None:
    async with Client(build_server(ctx.settings, context=ctx)) as client:
        result = await client.call_tool("git_log", {"repo": "sample", "max_count": 2})
    assert result.is_error is False
    assert result.structured_content is not None
    assert result.structured_content["count"] == 2
    assert json.loads(_text(result))["repo"] == "sample"


async def test_denied_call_is_an_error_result_and_audited(ctx: ToolContext) -> None:
    async with Client(build_server(ctx.settings, context=ctx)) as client:
        result = await client.call_tool("pg_query", {"database": "prod", "sql": "SELECT 1"})
        audit = await client.read_resource("devtools://audit/tail")
    assert result.is_error is True
    assert "[denied]" in _text(result)
    last = json.loads(audit.contents[0].text.splitlines()[-1])  # type: ignore[union-attr]
    assert (last["tool"], last["outcome"]) == ("pg_query", "denied")


async def test_argument_validation_happens_before_the_tool(ctx: ToolContext) -> None:
    async with Client(build_server(ctx.settings, context=ctx)) as client:
        result = await client.call_tool("git_log", {"repo": "sample", "max_count": 0})
    assert result.is_error is True
    assert ctx.audit.tail(5) == []


async def test_mixed_tools_in_one_session(ctx: ToolContext) -> None:
    async with Client(build_server(ctx.settings, context=ctx)) as client:
        ps = await client.call_tool("docker_ps", {})
        probe = await client.call_tool("http_probe", {"url": "https://example.com/"})
        found = await client.call_tool("logs_search", {"directory": "app", "pattern": "retrying"})
        query = await client.call_tool("pg_query", {"database": "app", "sql": "SELECT 1"})
    assert ps.structured_content["containers"][0]["name"] == "web"  # type: ignore[index]
    assert probe.structured_content["status"] == 200  # type: ignore[index]
    assert found.structured_content["match_count"] == 1  # type: ignore[index]
    assert query.structured_content["rows"] == [[1]]  # type: ignore[index]
    assert [r["tool"] for r in ctx.audit.tail(10)] == [
        "docker_ps",
        "http_probe",
        "logs_search",
        "pg_query",
    ]


async def test_resources(ctx: ToolContext) -> None:
    async with Client(build_server(ctx.settings, context=ctx)) as client:
        listed = {str(r.uri) for r in (await client.list_resources()).resources}
        templates = {
            t.uri_template for t in (await client.list_resource_templates()).resource_templates
        }
        config = await client.read_resource("devtools://config")
        readme = await client.read_resource("repo://sample/readme")
        source = await client.read_resource("repo://sample/files/src/app.py")
    assert {"devtools://config", "devtools://audit/tail"} <= listed
    assert templates == {"repo://{repo}/readme", "repo://{repo}/files/{+path}"}
    config_doc = json.loads(config.contents[0].text)  # type: ignore[union-attr]
    assert config_doc["postgres"]["databases"] == ["app"]
    assert "s3cret" not in config.contents[0].text  # type: ignore[union-attr]
    assert readme.contents[0].text.startswith("# Sample")  # type: ignore[union-attr]
    assert "hello {name}" in source.contents[0].text  # type: ignore[union-attr]


async def test_resource_outside_allow_list_fails(ctx: ToolContext) -> None:
    async with Client(build_server(ctx.settings, context=ctx)) as client:
        with pytest.raises(Exception, match=r"denied|not allow-listed"):
            await client.read_resource("repo://other/readme")


async def test_prompts(ctx: ToolContext) -> None:
    async with Client(build_server(ctx.settings, context=ctx)) as client:
        names = {p.name for p in (await client.list_prompts()).prompts}
        review = await client.get_prompt("review_recent_commits", {"repo": "sample", "count": "5"})
        diagnose = await client.get_prompt(
            "diagnose_failing_container", {"container": "web", "log_dir": "app"}
        )
        slow = await client.get_prompt(
            "explain_slow_query", {"database": "app", "sql": "SELECT * FROM books"}
        )
    assert names == {"review_recent_commits", "diagnose_failing_container", "explain_slow_query"}
    assert "max_count=5" in review.messages[0].content.text  # type: ignore[union-attr]
    assert "logs_search" in diagnose.messages[0].content.text  # type: ignore[union-attr]
    assert "SELECT * FROM books" in slow.messages[0].content.text  # type: ignore[union-attr]


async def test_disabled_families_are_not_registered(settings: Settings, backends: Backends) -> None:
    trimmed = settings.model_copy(
        update={
            "docker": settings.docker.model_copy(update={"enabled": False}),
            "postgres": settings.postgres.model_copy(update={"enabled": False}),
            "server": settings.server.model_copy(update={"expose_config_resource": False}),
        }
    )
    ctx = ToolContext.for_testing(trimmed, backends)
    async with Client(build_server(trimmed, context=ctx)) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        prompts = {p.name for p in (await client.list_prompts()).prompts}
        resources = {str(r.uri) for r in (await client.list_resources()).resources}
    assert not any(name.startswith(("docker_", "pg_")) for name in tools)
    assert "git_log" in tools
    assert prompts == {"review_recent_commits"}
    assert "devtools://config" not in resources


async def test_server_identity(ctx: ToolContext) -> None:
    server = build_server(ctx.settings, context=ctx)
    assert server.name == "devtools"
    assert "allow-lists" in (server.instructions or "")
