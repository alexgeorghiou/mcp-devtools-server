"""Log search over allow-listed directories.

Design notes:

* the search root comes from configuration and the optional sub-path is
  confined to it (symlinks that escape are refused);
* files are visited newest first, and only the *tail* of very large files is
  scanned, because recent lines are what an incident investigation needs;
* regular expressions are length-limited, lines are clipped before matching
  and the whole search has a wall-clock budget, which bounds the damage of a
  pathological pattern;
* rotated ``.gz`` logs are read transparently.
"""

from __future__ import annotations

import gzip
import io
import re
import time
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Protocol

from mcp_devtools.errors import ValidationError
from mcp_devtools.security.paths import confine

MAX_PATTERN_LENGTH = 500
MAX_LINE_CHARS = 2_000
MAX_FILES = 500


@dataclass(frozen=True, slots=True)
class LogMatch:
    file: str
    line: int
    text: str
    before: list[str] = field(default_factory=list)
    after: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class LogSearchResult:
    matches: list[LogMatch]
    files_scanned: int
    truncated: bool
    timed_out: bool
    partial_files: list[str]


@dataclass(frozen=True, slots=True)
class LogQuery:
    pattern: str
    regex: bool = False
    ignore_case: bool = True
    subpath: str = "."
    file_glob: str | None = None
    context: int = 2
    max_results: int = 100


class LogSearcher(Protocol):
    def search(self, root: Path, query: LogQuery) -> LogSearchResult: ...

    def list_files(self, root: Path) -> list[tuple[str, int]]: ...


def compile_pattern(query: LogQuery) -> re.Pattern[str]:
    if not query.pattern:
        raise ValidationError("pattern must not be empty")
    if len(query.pattern) > MAX_PATTERN_LENGTH:
        raise ValidationError(f"pattern is longer than {MAX_PATTERN_LENGTH} characters")
    flags = re.IGNORECASE if query.ignore_case else 0
    source = query.pattern if query.regex else re.escape(query.pattern)
    try:
        return re.compile(source, flags)
    except re.error as exc:
        raise ValidationError(f"invalid regular expression: {exc}") from exc


class FileSystemLogSearcher:
    def __init__(
        self,
        *,
        file_globs: list[str],
        max_file_bytes: int,
        time_budget_seconds: float = 5.0,
    ) -> None:
        self.file_globs = file_globs
        self.max_file_bytes = max_file_bytes
        self.time_budget = time_budget_seconds

    def _candidates(self, root: Path, start: Path, file_glob: str | None) -> list[Path]:
        globs = [file_glob] if file_glob else self.file_globs
        if start.is_file():
            files = [start]
        else:
            files = [
                p
                for p in start.rglob("*")
                if p.is_file() and any(fnmatch(p.name, g) for g in globs)
            ]
        resolved_root = root.resolve()
        safe = [p for p in files if p.resolve().is_relative_to(resolved_root)]
        safe.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return safe[:MAX_FILES]

    def list_files(self, root: Path) -> list[tuple[str, int]]:
        base = root.resolve()
        files = self._candidates(root, base, None)
        return [(p.resolve().relative_to(base).as_posix(), p.stat().st_size) for p in files]

    def search(self, root: Path, query: LogQuery) -> LogSearchResult:
        pattern = compile_pattern(query)
        start = confine(root, query.subpath)
        if not start.exists():
            raise ValidationError(f"path {query.subpath!r} does not exist in this log directory")
        deadline = time.monotonic() + self.time_budget

        matches: list[LogMatch] = []
        partial: list[str] = []
        scanned = 0
        truncated = timed_out = False
        resolved_root = root.resolve()

        for path in self._candidates(root, start, query.file_glob):
            rel = path.resolve().relative_to(resolved_root).as_posix()
            scanned += 1
            lines, was_partial = self._read_lines(path)
            if was_partial:
                partial.append(rel)
            for match in _scan(lines, pattern, query.context, rel, deadline):
                if match is None:
                    timed_out = True
                    break
                matches.append(match)
                if len(matches) >= query.max_results:
                    truncated = True
                    break
            if truncated or timed_out:
                break
        return LogSearchResult(matches, scanned, truncated, timed_out, partial)

    def _read_lines(self, path: Path) -> tuple[Iterable[str], bool]:
        if path.suffix == ".gz":
            with gzip.open(path, "rb") as gz:
                raw = gz.read(self.max_file_bytes + 1)
            partial = len(raw) > self.max_file_bytes
            return io.StringIO(raw[: self.max_file_bytes].decode("utf-8", "replace")), partial
        size = path.stat().st_size
        with path.open("rb") as fh:
            partial = size > self.max_file_bytes
            if partial:
                fh.seek(size - self.max_file_bytes)
                fh.readline()  # drop the cut-off first line
            data = fh.read()
        return io.StringIO(data.decode("utf-8", errors="replace")), partial


_Pending = tuple[int, str, list[str], list[str]]
"""(line number, line, context before, context after collected so far)"""


def _scan(
    lines: Iterable[str],
    pattern: re.Pattern[str],
    context: int,
    rel: str,
    deadline: float,
) -> Iterator[LogMatch | None]:
    """Yield matches with context; yields ``None`` once if the time budget runs out."""
    before: deque[str] = deque(maxlen=context)
    pending: list[_Pending] = []
    for number, raw in enumerate(lines, start=1):
        if number % 512 == 0 and time.monotonic() > deadline:
            yield from _flush(pending, rel)
            yield None
            return
        line = raw.rstrip("\r\n")[:MAX_LINE_CHARS]
        still_open: list[_Pending] = []
        for item in pending:
            item[3].append(line)
            if len(item[3]) >= context:
                yield LogMatch(rel, item[0], item[1], item[2], item[3])
            else:
                still_open.append(item)
        pending = still_open
        if pattern.search(line):
            if context == 0:
                yield LogMatch(rel, number, line, [], [])
            else:
                pending.append((number, line, list(before), []))
        before.append(line)
    yield from _flush(pending, rel)


def _flush(pending: list[_Pending], rel: str) -> Iterator[LogMatch]:
    for number, line, before, after in pending:
        yield LogMatch(rel, number, line, before, after)
