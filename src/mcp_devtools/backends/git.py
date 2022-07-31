"""Git backend: a typed interface plus an implementation that shells out to ``git``.

Hardening applied to every invocation:

* arguments are passed as a list (no shell) and user-supplied revisions are
  validated so they can never be parsed as options;
* user-supplied paths are confined to the repository and always placed after
  ``--``;
* option-valued inputs are attached (``--author=value``) rather than passed as
  separate argv entries;
* external diff drivers, textconv filters, fsmonitor hooks, pagers and
  credential prompts are disabled, so reading a hostile repository cannot
  execute code configured inside it;
* output is size-capped and the process is time-limited.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from mcp_devtools.errors import BackendError, ValidationError
from mcp_devtools.security.paths import confine

_REV = re.compile(r"^[A-Za-z0-9_./~^@{}:+-]{1,200}$")
_DATE = re.compile(r"^[A-Za-z0-9 :.,+-]{1,64}$")
_FIELD = "\x1f"
_RECORD = "\x1e"


def validate_rev(rev: str) -> str:
    """Accept branch names, tags, SHAs, ``HEAD~3``, ``main..feature`` and similar."""
    if not _REV.match(rev) or rev.startswith("-"):
        raise ValidationError(f"invalid revision {rev!r}")
    return rev


@dataclass(frozen=True, slots=True)
class Commit:
    sha: str
    short_sha: str
    author: str
    email: str
    date: str
    subject: str


@dataclass(frozen=True, slots=True)
class CommitDetail:
    commit: Commit
    body: str
    stat: str
    patch: str
    truncated: bool


@dataclass(frozen=True, slots=True)
class DiffResult:
    base: str | None
    target: str | None
    stat: str
    patch: str
    truncated: bool


@dataclass(frozen=True, slots=True)
class BlameLine:
    line: int
    sha: str
    author: str
    date: str
    summary: str
    content: str


@dataclass(frozen=True, slots=True)
class StatusEntry:
    code: str
    path: str


@dataclass(frozen=True, slots=True)
class RepoStatus:
    branch: str | None
    upstream: str | None
    ahead: int
    behind: int
    head: str | None
    entries: list[StatusEntry] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.entries


class GitBackend(Protocol):
    def log(
        self,
        repo: Path,
        *,
        rev: str = "HEAD",
        max_count: int = 20,
        path: str | None = None,
        author: str | None = None,
        since: str | None = None,
        grep: str | None = None,
    ) -> list[Commit]: ...

    def show(self, repo: Path, rev: str, *, max_bytes: int) -> CommitDetail: ...

    def diff(
        self,
        repo: Path,
        *,
        base: str | None = None,
        target: str | None = None,
        path: str | None = None,
        context_lines: int = 3,
        max_bytes: int,
    ) -> DiffResult: ...

    def blame(
        self,
        repo: Path,
        path: str,
        *,
        rev: str | None = None,
        start: int | None = None,
        end: int | None = None,
    ) -> list[BlameLine]: ...

    def status(self, repo: Path) -> RepoStatus: ...

    def read_file(self, repo: Path, path: str, *, rev: str = "HEAD", max_bytes: int) -> str: ...


def _truncate(text: str, max_bytes: int) -> tuple[str, bool]:
    data = text.encode("utf-8", errors="replace")
    if len(data) <= max_bytes:
        return text, False
    return data[:max_bytes].decode("utf-8", errors="ignore"), True


class SubprocessGitBackend:
    """Runs the ``git`` binary found on ``PATH``."""

    SAFE_CONFIG = (
        "core.fsmonitor=false",
        "core.pager=cat",
        "diff.external=",
        "core.quotePath=false",
        "color.ui=false",
        "log.showSignature=false",
    )

    def __init__(self, *, binary: str = "git", timeout: float = 15.0) -> None:
        self.binary = binary
        self.timeout = timeout

    # -- plumbing -----------------------------------------------------------------

    def _run(self, repo: Path, args: list[str]) -> str:
        cmd = [self.binary, "--no-pager"]
        for item in self.SAFE_CONFIG:
            cmd += ["-c", item]
        cmd += ["-C", str(repo), *args]
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "LC_ALL": "C",
        }
        env.pop("GIT_DIR", None)
        env.pop("GIT_WORK_TREE", None)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                env=env,
                check=False,
            )
        except FileNotFoundError as exc:
            raise BackendError(f"git executable {self.binary!r} not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise BackendError(f"git timed out after {self.timeout:.0f}s") from exc
        stdout = proc.stdout.decode("utf-8", errors="replace")
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", errors="replace").strip()
            raise BackendError(f"git {args[0]} failed: {stderr or f'exit {proc.returncode}'}")
        return stdout

    @staticmethod
    def _rel(repo: Path, path: str) -> str:
        target = confine(repo, path)
        rel = target.relative_to(repo.resolve()).as_posix()
        return rel or "."

    # -- commands -----------------------------------------------------------------

    _LOG_FORMAT = _FIELD.join(["%H", "%h", "%an", "%ae", "%aI", "%s"]) + _RECORD

    def _parse_commits(self, out: str) -> list[Commit]:
        commits: list[Commit] = []
        for raw in out.split(_RECORD):
            raw = raw.strip("\n")
            if not raw:
                continue
            parts = raw.split(_FIELD)
            if len(parts) != 6:
                continue
            commits.append(Commit(*parts))
        return commits

    def log(
        self,
        repo: Path,
        *,
        rev: str = "HEAD",
        max_count: int = 20,
        path: str | None = None,
        author: str | None = None,
        since: str | None = None,
        grep: str | None = None,
    ) -> list[Commit]:
        args = ["log", f"--max-count={int(max_count)}", f"--format={self._LOG_FORMAT}"]
        if author:
            args.append(f"--author={author}")
        if since:
            if not _DATE.match(since):
                raise ValidationError(f"invalid 'since' value {since!r}")
            args.append(f"--since={since}")
        if grep:
            args += [f"--grep={grep}", "--fixed-strings", "--regexp-ignore-case"]
        args += [validate_rev(rev), "--"]
        if path:
            args.append(self._rel(repo, path))
        return self._parse_commits(self._run(repo, args))

    def show(self, repo: Path, rev: str, *, max_bytes: int) -> CommitDetail:
        rev = validate_rev(rev)
        header = self._run(repo, ["show", "-s", f"--format={self._LOG_FORMAT}%b", rev, "--"]).split(
            _RECORD, 1
        )
        commits = self._parse_commits(header[0] + _RECORD)
        if not commits:
            raise BackendError(f"revision {rev!r} is not a commit")
        body = header[1].strip() if len(header) > 1 else ""
        stat = self._run(repo, ["show", "--stat", "--format=", rev, "--"]).strip()
        patch = self._run(
            repo, ["show", "--no-ext-diff", "--no-textconv", "--format=", "--patch", rev, "--"]
        )
        patch, truncated = _truncate(patch, max_bytes)
        return CommitDetail(commits[0], body, stat, patch, truncated)

    def diff(
        self,
        repo: Path,
        *,
        base: str | None = None,
        target: str | None = None,
        path: str | None = None,
        context_lines: int = 3,
        max_bytes: int,
    ) -> DiffResult:
        if target and not base:
            raise ValidationError("'target' requires 'base'")
        revs = [validate_rev(r) for r in (base, target) if r]
        pathspec = [self._rel(repo, path)] if path else []
        tail = [*revs, "--", *pathspec]
        stat = self._run(repo, ["diff", "--stat", *tail]).strip()
        patch = self._run(
            repo, ["diff", "--no-ext-diff", "--no-textconv", f"--unified={context_lines}", *tail]
        )
        patch, truncated = _truncate(patch, max_bytes)
        return DiffResult(base, target, stat, patch, truncated)

    def blame(
        self,
        repo: Path,
        path: str,
        *,
        rev: str | None = None,
        start: int | None = None,
        end: int | None = None,
    ) -> list[BlameLine]:
        args = ["blame", "--porcelain"]
        if start is not None or end is not None:
            lo = max(1, start or 1)
            hi = end if end is not None else lo + 199
            if hi < lo:
                raise ValidationError("'end' must be greater than or equal to 'start'")
            args.append(f"-L{lo},{hi}")
        if rev:
            args.append(validate_rev(rev))
        args += ["--", self._rel(repo, path)]
        return parse_porcelain_blame(self._run(repo, args))

    def status(self, repo: Path) -> RepoStatus:
        out = self._run(repo, ["status", "--porcelain=v2", "--branch", "--untracked-files=normal"])
        return parse_status_v2(out)

    def read_file(self, repo: Path, path: str, *, rev: str = "HEAD", max_bytes: int) -> str:
        rel = self._rel(repo, path)
        text = self._run(repo, ["show", "--no-textconv", f"{validate_rev(rev)}:{rel}"])
        text, truncated = _truncate(text, max_bytes)
        return text + ("\n... [truncated]" if truncated else "")


def _epoch_to_iso(raw: str) -> str:
    try:
        return datetime.fromtimestamp(int(raw), tz=UTC).isoformat()
    except ValueError:
        return raw


def parse_porcelain_blame(out: str) -> list[BlameLine]:
    """Parse ``git blame --porcelain``; commit metadata appears only on first use of a SHA."""
    meta: dict[str, dict[str, str]] = {}
    lines: list[BlameLine] = []
    current_sha: str | None = None
    current_line = 0
    for raw in out.splitlines():
        if raw.startswith("\t"):
            if current_sha is None:
                continue
            info = meta.get(current_sha, {})
            lines.append(
                BlameLine(
                    line=current_line,
                    sha=current_sha[:12],
                    author=info.get("author", ""),
                    date=_epoch_to_iso(info.get("author-time", "")),
                    summary=info.get("summary", ""),
                    content=raw[1:],
                )
            )
            continue
        head, _, rest = raw.partition(" ")
        if len(head) == 40 and all(c in "0123456789abcdef" for c in head):
            current_sha = head
            current_line = int(rest.split()[1])
            meta.setdefault(head, {})
        elif current_sha is not None:
            meta[current_sha][head] = rest
    return lines


def parse_status_v2(out: str) -> RepoStatus:
    branch = upstream = head = None
    ahead = behind = 0
    entries: list[StatusEntry] = []
    for line in out.splitlines():
        if line.startswith("# branch.head "):
            value = line.removeprefix("# branch.head ")
            branch = None if value == "(detached)" else value
        elif line.startswith("# branch.oid "):
            value = line.removeprefix("# branch.oid ")
            head = None if value == "(initial)" else value[:12]
        elif line.startswith("# branch.upstream "):
            upstream = line.removeprefix("# branch.upstream ")
        elif line.startswith("# branch.ab "):
            a, b = line.removeprefix("# branch.ab ").split()
            ahead, behind = int(a), abs(int(b))
        elif line.startswith("1 "):
            parts = line.split(" ", 8)
            entries.append(StatusEntry(parts[1], parts[8]))
        elif line.startswith("2 "):
            parts = line.split(" ", 9)
            entries.append(StatusEntry(parts[1], parts[9].replace("\t", " <- ")))
        elif line.startswith("u "):
            parts = line.split(" ", 10)
            entries.append(StatusEntry(parts[1], parts[10]))
        elif line.startswith("? "):
            entries.append(StatusEntry("??", line[2:]))
    return RepoStatus(branch, upstream, ahead, behind, head, entries)
