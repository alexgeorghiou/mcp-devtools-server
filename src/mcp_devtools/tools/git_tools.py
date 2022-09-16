"""Git tools: log, show, diff, blame and status over allow-listed repositories."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_devtools.tools.context import ToolContext, to_plain

READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False, idempotent_hint=True)

Repo = Annotated[str, Field(description="Repository alias from the server's git.repos allow-list")]
Rev = Annotated[str, Field(description="Revision: branch, tag, SHA, HEAD~N or A..B range")]


class GitTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx
        self.git = ctx.backends.git
        self.cfg = ctx.settings.git

    def list_repos(self) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            self.ctx.policy.require_enabled("git")
            return {"repos": sorted(self.cfg.repos)}

        return self.ctx.run("git_list_repos", {}, run)

    def log(
        self,
        repo: str,
        rev: str = "HEAD",
        max_count: int = 20,
        path: str | None = None,
        author: str | None = None,
        since: str | None = None,
        grep: str | None = None,
    ) -> dict[str, Any]:
        args = {
            "repo": repo,
            "rev": rev,
            "max_count": max_count,
            "path": path,
            "author": author,
            "since": since,
            "grep": grep,
        }

        def run() -> dict[str, Any]:
            root = self.ctx.policy.repo(repo)
            count = max(1, min(max_count, self.cfg.max_log_entries))
            commits = self.git.log(
                root, rev=rev, max_count=count, path=path, author=author, since=since, grep=grep
            )
            return {"repo": repo, "rev": rev, "count": len(commits), "commits": to_plain(commits)}

        return self.ctx.run("git_log", args, run)

    def show(self, repo: str, rev: str = "HEAD") -> dict[str, Any]:
        def run() -> dict[str, Any]:
            root = self.ctx.policy.repo(repo)
            detail = self.git.show(root, rev, max_bytes=self.cfg.max_output_bytes)
            return {"repo": repo, **to_plain(detail)}

        return self.ctx.run("git_show", {"repo": repo, "rev": rev}, run)

    def diff(
        self,
        repo: str,
        base: str | None = None,
        target: str | None = None,
        path: str | None = None,
        context_lines: int = 3,
    ) -> dict[str, Any]:
        args = {
            "repo": repo,
            "base": base,
            "target": target,
            "path": path,
            "context_lines": context_lines,
        }

        def run() -> dict[str, Any]:
            root = self.ctx.policy.repo(repo)
            result = self.git.diff(
                root,
                base=base,
                target=target,
                path=path,
                context_lines=max(0, min(context_lines, 20)),
                max_bytes=self.cfg.max_output_bytes,
            )
            return {"repo": repo, **to_plain(result)}

        return self.ctx.run("git_diff", args, run)

    def blame(
        self,
        repo: str,
        path: str,
        start_line: int | None = None,
        end_line: int | None = None,
        rev: str | None = None,
    ) -> dict[str, Any]:
        args = {
            "repo": repo,
            "path": path,
            "start_line": start_line,
            "end_line": end_line,
            "rev": rev,
        }

        def run() -> dict[str, Any]:
            root = self.ctx.policy.repo(repo)
            lines = self.git.blame(root, path, rev=rev, start=start_line, end=end_line)
            return {"repo": repo, "path": path, "lines": to_plain(lines)}

        return self.ctx.run("git_blame", args, run)

    def status(self, repo: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            root = self.ctx.policy.repo(repo)
            status = self.git.status(root)
            return {"repo": repo, "clean": status.clean, **to_plain(status)}

        return self.ctx.run("git_status", {"repo": repo}, run)


def register(server: MCPServer, ctx: ToolContext) -> None:
    tools = GitTools(ctx)

    @server.tool(annotations=READ_ONLY)
    def git_list_repos() -> dict[str, Any]:
        """List the repository aliases this server is allowed to read."""
        return tools.list_repos()

    @server.tool(annotations=READ_ONLY)
    def git_log(
        repo: Repo,
        rev: Rev = "HEAD",
        max_count: Annotated[int, Field(ge=1, le=500, description="Maximum commits")] = 20,
        path: Annotated[str | None, Field(description="Only commits touching this path")] = None,
        author: Annotated[str | None, Field(description="Filter by author name/email")] = None,
        since: Annotated[str | None, Field(description="e.g. '2 weeks ago' or 2026-01-31")] = None,
        grep: Annotated[str | None, Field(description="Case-insensitive message filter")] = None,
    ) -> dict[str, Any]:
        """Show commit history (sha, author, date, subject), newest first."""
        return tools.log(repo, rev, max_count, path, author, since, grep)

    @server.tool(annotations=READ_ONLY)
    def git_show(repo: Repo, rev: Rev = "HEAD") -> dict[str, Any]:
        """Show one commit: metadata, message body, diffstat and (size-capped) patch."""
        return tools.show(repo, rev)

    @server.tool(annotations=READ_ONLY)
    def git_diff(
        repo: Repo,
        base: Annotated[str | None, Field(description="Base revision; omit for worktree")] = None,
        target: Annotated[str | None, Field(description="Target revision (requires base)")] = None,
        path: Annotated[str | None, Field(description="Limit to this path")] = None,
        context_lines: Annotated[int, Field(ge=0, le=20)] = 3,
    ) -> dict[str, Any]:
        """Diff the working tree, or base vs worktree, or base..target. Output is size-capped."""
        return tools.diff(repo, base, target, path, context_lines)

    @server.tool(annotations=READ_ONLY)
    def git_blame(
        repo: Repo,
        path: Annotated[str, Field(description="File path relative to the repository root")],
        start_line: Annotated[int | None, Field(ge=1)] = None,
        end_line: Annotated[int | None, Field(ge=1)] = None,
        rev: Annotated[str | None, Field(description="Blame as of this revision")] = None,
    ) -> dict[str, Any]:
        """Attribute each line of a file (or a line range) to the commit that last changed it."""
        return tools.blame(repo, path, start_line, end_line, rev)

    @server.tool(annotations=READ_ONLY)
    def git_status(repo: Repo) -> dict[str, Any]:
        """Current branch, upstream divergence and changed/untracked files."""
        return tools.status(repo)
