"""Log search tools over allow-listed directories."""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_devtools.backends.logs import LogQuery
from mcp_devtools.security.redact import redact_text
from mcp_devtools.tools.context import ToolContext

READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False, idempotent_hint=True)

LogDir = Annotated[str, Field(description="Log directory alias from logs.directories")]


class LogTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx
        self.searcher = ctx.backends.logs
        self.cfg = ctx.settings.logs

    def list_files(self, directory: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            root = self.ctx.policy.log_dir(directory)
            files = self.searcher.list_files(root)
            return {
                "directory": directory,
                "files": [{"path": p, "bytes": size} for p, size in files],
            }

        return self.ctx.run("logs_list_files", {"directory": directory}, run)

    def search(
        self,
        directory: str,
        pattern: str,
        regex: bool = False,
        ignore_case: bool = True,
        path: str = ".",
        file_glob: str | None = None,
        context_lines: int = 2,
        max_results: int | None = None,
    ) -> dict[str, Any]:
        args = {
            "directory": directory,
            "pattern": pattern,
            "regex": regex,
            "path": path,
            "file_glob": file_glob,
            "context_lines": context_lines,
            "max_results": max_results,
        }

        def run() -> dict[str, Any]:
            root = self.ctx.policy.log_dir(directory)
            query = LogQuery(
                pattern=pattern,
                regex=regex,
                ignore_case=ignore_case,
                subpath=path,
                file_glob=file_glob,
                context=max(0, min(context_lines, self.cfg.max_context_lines)),
                max_results=max(1, min(max_results or self.cfg.max_results, self.cfg.max_results)),
            )
            result = self.searcher.search(root, query)
            matches = []
            for match in result.matches:
                item = asdict(match)
                item["text"] = redact_text(item["text"])
                item["before"] = [redact_text(x) for x in item["before"]]
                item["after"] = [redact_text(x) for x in item["after"]]
                matches.append(item)
            return {
                "directory": directory,
                "match_count": len(matches),
                "files_scanned": result.files_scanned,
                "truncated": result.truncated,
                "timed_out": result.timed_out,
                "partially_scanned_files": result.partial_files,
                "matches": matches,
            }

        return self.ctx.run("logs_search", args, run)


def register(server: MCPServer, ctx: ToolContext) -> None:
    tools = LogTools(ctx)

    @server.tool(annotations=READ_ONLY)
    def logs_list_files(directory: LogDir) -> dict[str, Any]:
        """List searchable log files in an allow-listed directory, newest first."""
        return tools.list_files(directory)

    @server.tool(annotations=READ_ONLY)
    def logs_search(
        directory: LogDir,
        pattern: Annotated[str, Field(description="Substring, or a regex when regex=true")],
        regex: bool = False,
        ignore_case: bool = True,
        path: Annotated[str, Field(description="Sub-directory or file inside the root")] = ".",
        file_glob: Annotated[str | None, Field(description="e.g. 'api-*.log'")] = None,
        context_lines: Annotated[int, Field(ge=0, le=50)] = 2,
        max_results: Annotated[int | None, Field(ge=1)] = None,
    ) -> dict[str, Any]:
        """Search log files (newest first) and return matching lines with context."""
        return tools.search(
            directory, pattern, regex, ignore_case, path, file_glob, context_lines, max_results
        )
