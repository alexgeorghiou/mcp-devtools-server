from __future__ import annotations

from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_devtools.backends.git import (
    SubprocessGitBackend,
    parse_porcelain_blame,
    parse_status_v2,
    validate_rev,
)
from mcp_devtools.errors import ValidationError
from mcp_devtools.tools.context import ToolContext
from mcp_devtools.tools.git_tools import GitTools


@pytest.fixture
def git(ctx: ToolContext) -> GitTools:
    return GitTools(ctx)


def test_list_repos(git: GitTools) -> None:
    assert git.list_repos() == {"repos": ["sample"]}


def test_log_returns_newest_first(git: GitTools) -> None:
    result = git.log("sample")
    subjects = [c["subject"] for c in result["commits"]]
    assert subjects == ["refactor: type the greeter", "feat: add greeter", "docs: add readme"]
    assert result["commits"][0]["author"] == "Test Author"
    assert len(result["commits"][0]["sha"]) == 40


def test_log_filters(git: GitTools) -> None:
    assert git.log("sample", max_count=1)["count"] == 1
    assert git.log("sample", path="README.md")["count"] == 1
    assert git.log("sample", grep="GREETER")["count"] == 2
    assert git.log("sample", author="nobody@else")["count"] == 0
    assert git.log("sample", rev="HEAD~1")["commits"][0]["subject"] == "feat: add greeter"
    assert git.log("sample", since="2000-01-01")["count"] == 3


def test_log_caps_max_count(ctx: ToolContext) -> None:
    calls: list[int] = []
    real = ctx.backends.git

    class Spy(SubprocessGitBackend):
        def log(self, repo: Path, **kwargs: object) -> list:  # type: ignore[override]
            calls.append(kwargs["max_count"])  # type: ignore[arg-type]
            return real.log(repo, **kwargs)  # type: ignore[arg-type]

    ctx.backends.git = Spy()
    GitTools(ctx).log("sample", max_count=10_000)
    assert calls == [ctx.settings.git.max_log_entries]


def test_show_includes_body_stat_and_patch(git: GitTools) -> None:
    result = git.show("sample", "HEAD")
    assert result["commit"]["subject"] == "refactor: type the greeter"
    assert result["body"] == "Uses an f-string."
    assert "src/app.py" in result["stat"]
    assert "+def greet(name: str) -> str:" in result["patch"]
    assert result["truncated"] is False


def test_diff_worktree_and_range(git: GitTools) -> None:
    worktree = git.diff("sample")
    assert "hello, {name}!" in worktree["patch"]
    ranged = git.diff("sample", base="HEAD~2", target="HEAD", path="src")
    assert "src/app.py" in ranged["stat"]
    assert "README" not in ranged["patch"]


def test_diff_target_requires_base(git: GitTools) -> None:
    with pytest.raises(ToolError, match="requires 'base'"):
        git.diff("sample", target="HEAD")


def test_diff_truncates_large_output(ctx: ToolContext) -> None:
    small = ctx.settings.git.model_copy(update={"max_output_bytes": 1000})
    ctx.settings = ctx.settings.model_copy(update={"git": small})
    tools = GitTools(ctx)
    tools.cfg = small
    out = tools.diff("sample", base="HEAD~2", context_lines=0)
    assert len(out["patch"].encode()) <= 1000


def test_blame_attributes_lines_including_uncommitted(git: GitTools) -> None:
    first, second = git.blame("sample", "src/app.py")["lines"]
    assert first["content"] == "def greet(name: str) -> str:"
    assert first["summary"] == "refactor: type the greeter"
    assert first["date"].endswith("+00:00")
    # Without a revision git blames the working tree, so the dirty line is unattributed.
    assert second["content"] == "    return f'hello, {name}!'"
    assert second["sha"] == "0" * 12


def test_blame_range_and_old_revision(git: GitTools) -> None:
    result = git.blame("sample", "src/app.py", start_line=2, end_line=2, rev="HEAD~1")
    assert len(result["lines"]) == 1
    assert result["lines"][0]["content"] == "    return 'hi ' + name"


def test_status_shows_changes(git: GitTools) -> None:
    status = git.status("sample")
    assert status["branch"] == "main"
    assert status["clean"] is False
    entries = {e["path"]: e["code"] for e in status["entries"]}
    assert entries == {"src/app.py": ".M", "NOTES.txt": "??"}


@pytest.mark.parametrize(
    "call",
    [
        lambda g: g.log("sample", rev="--output=/tmp/pwned"),
        lambda g: g.log("sample", rev="HEAD; rm -rf /"),
        lambda g: g.show("sample", "-p"),
        lambda g: g.blame("sample", "../../etc/passwd"),
        lambda g: g.diff("sample", path="/etc"),
        lambda g: g.log("sample", since="$(whoami)"),
    ],
)
def test_injection_attempts_are_rejected(git: GitTools, call) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ToolError, match=r"\[(invalid|denied)\]"):
        call(git)


def test_unknown_repo_is_denied_and_audited(git: GitTools, ctx: ToolContext) -> None:
    with pytest.raises(ToolError, match="denied"):
        git.status("elsewhere")
    assert ctx.audit.tail(1)[0]["outcome"] == "denied"


def test_unknown_revision_is_a_backend_error(git: GitTools) -> None:
    with pytest.raises(ToolError, match="backend_error"):
        git.show("sample", "does-not-exist")


def test_read_file_at_head(git_repo: Path) -> None:
    text = SubprocessGitBackend().read_file(git_repo, "src/app.py", max_bytes=10_000)
    assert "hello {name}" in text  # committed version, not the dirty worktree


@pytest.mark.parametrize("rev", ["main", "HEAD~3", "v1.2.0", "a1b2c3d", "main..feature/x", "@{u}"])
def test_valid_revisions(rev: str) -> None:
    assert validate_rev(rev) == rev


@pytest.mark.parametrize("rev", ["-n", "--all", "", "a b", "x" * 201, "HEAD|cat"])
def test_invalid_revisions(rev: str) -> None:
    with pytest.raises(ValidationError):
        validate_rev(rev)


def test_parse_status_v2_handles_all_record_types() -> None:
    out = "\n".join(
        [
            "# branch.oid 0123456789abcdef0123456789abcdef01234567",
            "# branch.head feature",
            "# branch.upstream origin/feature",
            "# branch.ab +2 -1",
            "1 M. N... 100644 100644 100644 aaa bbb src/a.py",
            "2 R. N... 100644 100644 100644 aaa bbb R100 new name.py\told.py",
            "u UU N... 100644 100644 100644 100644 a b c conflict.py",
            "? untracked.txt",
        ]
    )
    status = parse_status_v2(out)
    assert (status.branch, status.upstream, status.ahead, status.behind) == (
        "feature",
        "origin/feature",
        2,
        1,
    )
    assert status.head == "0123456789ab"
    assert [e.path for e in status.entries] == [
        "src/a.py",
        "new name.py <- old.py",
        "conflict.py",
        "untracked.txt",
    ]


def test_parse_blame_reuses_metadata_for_repeated_commits() -> None:
    sha = "a" * 40
    out = "\n".join(
        [
            f"{sha} 1 1 2",
            "author Ada",
            "author-time 0",
            "summary first",
            "\tline one",
            f"{sha} 2 2",
            "\tline two",
        ]
    )
    lines = parse_porcelain_blame(out)
    assert [(entry.line, entry.author, entry.content) for entry in lines] == [
        (1, "Ada", "line one"),
        (2, "Ada", "line two"),
    ]
    assert lines[0].date == "1970-01-01T00:00:00+00:00"
