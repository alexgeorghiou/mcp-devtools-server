from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from mcp_devtools.backends.docker import ContainerSummary
from mcp_devtools.backends.git import SubprocessGitBackend
from mcp_devtools.backends.logs import FileSystemLogSearcher
from mcp_devtools.config import Settings
from mcp_devtools.tools.context import Backends, ToolContext
from tests.fakes import FakeDocker, FakePostgres, FakeProber, FakeResolver, hop


def _git(repo: Path, *args: str) -> str:
    env = {
        "GIT_AUTHOR_NAME": "Test Author",
        "GIT_AUTHOR_EMAIL": "author@example.test",
        "GIT_COMMITTER_NAME": "Test Author",
        "GIT_COMMITTER_EMAIL": "author@example.test",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(repo.parent),
        "PATH": os.environ["PATH"],
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
    }
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env
    ).stdout


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A small real repository with three commits and one uncommitted change."""
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "README.md").write_text("# Sample\n\nA tiny repository for tests.\n", "utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "docs: add readme")

    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text("def greet(name):\n    return 'hi ' + name\n", "utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "feat: add greeter")

    (src / "app.py").write_text(
        "def greet(name: str) -> str:\n    return f'hello {name}'\n", "utf-8"
    )
    _git(repo, "commit", "-q", "-am", "refactor: type the greeter", "-m", "Uses an f-string.")

    (repo / "NOTES.txt").write_text("scratch\n", "utf-8")
    (src / "app.py").write_text(
        "def greet(name: str) -> str:\n    return f'hello, {name}!'\n", "utf-8"
    )
    return repo


@pytest.fixture
def log_dir(tmp_path: Path) -> Path:
    root = tmp_path / "logs"
    (root / "api").mkdir(parents=True)
    (root / "api" / "api.log").write_text(
        "\n".join(
            [
                "2026-03-01T10:00:00Z INFO starting api",
                "2026-03-01T10:00:01Z INFO listening on :8080",
                "2026-03-01T10:00:05Z WARN slow request path=/search took=950ms",
                "2026-03-01T10:00:06Z ERROR upstream timeout calling search-index",
                "2026-03-01T10:00:07Z INFO retrying",
                "2026-03-01T10:00:08Z ERROR connect failed password=hunter2",
                "2026-03-01T10:00:09Z INFO recovered",
            ]
        )
        + "\n",
        "utf-8",
    )
    (root / "worker.log").write_text("job 1 ok\njob 2 Error: disk quota\njob 3 ok\n", "utf-8")
    (root / "ignored.bin").write_bytes(b"\x00ERROR\x00")
    return root


@pytest.fixture
def settings(git_repo: Path, log_dir: Path) -> Settings:
    data: dict[str, Any] = {
        "git": {"repos": {"sample": str(git_repo)}},
        "docker": {"containers": ["web", "worker-*"], "max_log_lines": 50},
        "postgres": {
            "databases": {"app": "postgresql://reader:s3cret@db.internal:5432/app"},
            "max_rows": 3,
        },
        "http": {"allowed_hosts": ["example.com", "*.example.org"], "max_redirects": 2},
        "logs": {"directories": {"app": str(log_dir)}, "max_results": 10},
    }
    return Settings.model_validate(data)


@pytest.fixture
def fake_docker() -> FakeDocker:
    return FakeDocker(
        containers=[
            ContainerSummary("a1", "web", "nginx:1.27", "running", "Up 2 hours", "80/tcp"),
            ContainerSummary("b2", "worker-1", "app:latest", "exited", "Exited (137)", ""),
            ContainerSummary("c3", "secret-db", "postgres:17", "running", "Up", "5432/tcp"),
        ],
        log_text={
            "web": "line one\nGET /health 200\nAuthorization: Bearer abc.def\nGET / 500",
            "worker-1": "\n".join(f"tick {i}" for i in range(100)),
        },
        inspections={"web": {"name": "web", "state": {"status": "running", "exit_code": 0}}},
    )


@pytest.fixture
def fake_postgres() -> FakePostgres:
    return FakePostgres()


@pytest.fixture
def fake_prober() -> FakeProber:
    return FakeProber({"https://example.com/": hop("https://example.com/")})


@pytest.fixture
def fake_resolver() -> FakeResolver:
    return FakeResolver(
        {
            "example.com": ["93.184.215.14"],
            "api.example.org": ["2606:2800:220:1:248:1893:25c8:1946"],
            "internal.example.org": ["10.0.0.7"],
            "rebind.example.org": ["93.184.215.14", "127.0.0.1"],
        }
    )


@pytest.fixture
def backends(
    settings: Settings,
    fake_docker: FakeDocker,
    fake_postgres: FakePostgres,
    fake_prober: FakeProber,
    fake_resolver: FakeResolver,
) -> Backends:
    return Backends(
        git=SubprocessGitBackend(),
        docker=fake_docker,
        postgres=fake_postgres,
        http=fake_prober,
        logs=FileSystemLogSearcher(file_globs=settings.logs.file_globs, max_file_bytes=10_000),
        resolver=fake_resolver,
    )


@pytest.fixture
def ctx(settings: Settings, backends: Backends) -> ToolContext:
    return ToolContext.for_testing(settings, backends)
