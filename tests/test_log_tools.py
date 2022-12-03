from __future__ import annotations

import gzip
import os
import time
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_devtools.backends.logs import FileSystemLogSearcher, LogQuery
from mcp_devtools.tools.context import ToolContext
from mcp_devtools.tools.log_tools import LogTools


@pytest.fixture
def logs(ctx: ToolContext) -> LogTools:
    return LogTools(ctx)


def test_substring_search_with_context(logs: LogTools) -> None:
    result = logs.search("app", "upstream timeout", context_lines=1)
    (match,) = result["matches"]
    assert match["file"] == "api/api.log"
    assert match["line"] == 4
    assert match["before"] == ["2026-03-01T10:00:05Z WARN slow request path=/search took=950ms"]
    assert match["after"] == ["2026-03-01T10:00:07Z INFO retrying"]


def test_case_insensitive_by_default_and_skips_non_log_files(logs: LogTools) -> None:
    files = {m["file"] for m in logs.search("app", "error", context_lines=0)["matches"]}
    assert files == {"api/api.log", "worker.log"}  # ignored.bin is not a log glob


def test_case_sensitive(logs: LogTools) -> None:
    result = logs.search("app", "ERROR", ignore_case=False, context_lines=0)
    assert result["match_count"] == 2


def test_regex_search(logs: LogTools) -> None:
    result = logs.search("app", r"took=\d{3,}ms", regex=True, context_lines=0)
    assert result["match_count"] == 1


def test_secrets_in_matches_are_redacted(logs: LogTools) -> None:
    (match,) = logs.search("app", "connect failed", context_lines=0)["matches"]
    assert match["text"].endswith("password=***")


def test_subpath_and_glob(logs: LogTools) -> None:
    assert logs.search("app", "job", path=".", file_glob="worker*")["match_count"] == 3
    assert logs.search("app", "INFO", path="api")["files_scanned"] == 1


def test_max_results_truncates(logs: LogTools) -> None:
    result = logs.search("app", "INFO", max_results=2, context_lines=0)
    assert result["match_count"] == 2
    assert result["truncated"] is True


@pytest.mark.parametrize("path", ["../", "api/../../", "/etc", "C:\\Windows"])
def test_path_traversal_is_denied(logs: LogTools, path: str) -> None:
    with pytest.raises(ToolError, match="denied"):
        logs.search("app", "x", path=path)


def test_unknown_directory_and_bad_regex(logs: LogTools) -> None:
    with pytest.raises(ToolError, match="denied"):
        logs.search("system", "x")
    with pytest.raises(ToolError, match="invalid regular expression"):
        logs.search("app", "(unclosed", regex=True)
    with pytest.raises(ToolError, match="does not exist"):
        logs.search("app", "x", path="missing")


def test_list_files_newest_first(logs: LogTools, log_dir: Path) -> None:
    os.utime(log_dir / "worker.log", (time.time() + 60, time.time() + 60))
    files = logs.list_files("app")["files"]
    assert [f["path"] for f in files] == ["worker.log", "api/api.log"]
    assert files[0]["bytes"] > 0


def test_overlapping_context_windows(tmp_path: Path) -> None:
    (tmp_path / "x.log").write_text("a\nhit 1\nhit 2\nb\nc\n", "utf-8")
    searcher = FileSystemLogSearcher(file_globs=["*.log"], max_file_bytes=10_000)
    result = searcher.search(tmp_path, LogQuery(pattern="hit", context=2))
    assert [(m.line, m.before, m.after) for m in result.matches] == [
        (2, ["a"], ["hit 2", "b"]),
        (3, ["a", "hit 1"], ["b", "c"]),
    ]


def test_match_at_end_of_file_flushes(tmp_path: Path) -> None:
    (tmp_path / "x.log").write_text("a\nlast hit", "utf-8")
    searcher = FileSystemLogSearcher(file_globs=["*.log"], max_file_bytes=10_000)
    (match,) = searcher.search(tmp_path, LogQuery(pattern="hit", context=3)).matches
    assert match.after == []


def test_large_files_scan_only_the_tail(tmp_path: Path) -> None:
    lines = [f"line {i} {'OLD' if i < 500 else 'NEW'}" for i in range(1000)]
    (tmp_path / "big.log").write_text("\n".join(lines), "utf-8")
    searcher = FileSystemLogSearcher(file_globs=["*.log"], max_file_bytes=2_000)
    result = searcher.search(tmp_path, LogQuery(pattern="OLD", max_results=1000, context=0))
    assert result.matches == []
    assert result.partial_files == ["big.log"]


def test_gzip_rotated_logs(tmp_path: Path) -> None:
    with gzip.open(tmp_path / "app.log.1.gz", "wt", encoding="utf-8") as fh:
        fh.write("old ERROR from yesterday\n")
    searcher = FileSystemLogSearcher(file_globs=["*.log.*"], max_file_bytes=10_000)
    (match,) = searcher.search(tmp_path, LogQuery(pattern="error", context=0)).matches
    assert match.file == "app.log.1.gz"


def test_time_budget(tmp_path: Path) -> None:
    (tmp_path / "x.log").write_text("hit\n" * 5000, "utf-8")
    searcher = FileSystemLogSearcher(
        file_globs=["*.log"], max_file_bytes=1_000_000, time_budget_seconds=-1
    )
    result = searcher.search(tmp_path, LogQuery(pattern="hit", context=0, max_results=10_000))
    assert result.timed_out is True
    assert 0 < len(result.matches) < 5000


@pytest.mark.parametrize("pattern", ["", "x" * 501])
def test_pattern_limits(tmp_path: Path, pattern: str) -> None:
    searcher = FileSystemLogSearcher(file_globs=["*.log"], max_file_bytes=1000)
    with pytest.raises(Exception, match="pattern"):
        searcher.search(tmp_path, LogQuery(pattern=pattern))
