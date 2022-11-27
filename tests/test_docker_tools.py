from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_devtools.backends.docker import DockerCliBackend, summarise_inspect
from mcp_devtools.errors import BackendError, ValidationError
from mcp_devtools.tools.context import ToolContext
from mcp_devtools.tools.docker_tools import DockerTools
from tests.fakes import FakeDocker


@pytest.fixture
def docker(ctx: ToolContext) -> DockerTools:
    return DockerTools(ctx)


def test_ps_only_shows_allow_listed_containers(docker: DockerTools) -> None:
    assert [c["name"] for c in docker.ps()["containers"]] == ["web"]
    names = [c["name"] for c in docker.ps(include_stopped=True)["containers"]]
    assert names == ["web", "worker-1"]  # secret-db is running but not allow-listed


def test_logs_are_capped_and_redacted(docker: DockerTools, fake_docker: FakeDocker) -> None:
    result = docker.logs("web", tail=10_000)
    assert fake_docker.calls[-1] == ("logs", ("web", 50, None))
    assert "Authorization: Bearer ***" in result["lines"]
    assert result["line_count"] == 4


def test_logs_grep_and_tail(docker: DockerTools) -> None:
    assert docker.logs("web", grep="get")["lines"] == ["GET /health 200", "GET / 500"]
    assert docker.logs("worker-1", tail=3)["lines"] == ["tick 97", "tick 98", "tick 99"]


def test_inspect(docker: DockerTools) -> None:
    assert docker.inspect("web")["state"]["status"] == "running"


@pytest.mark.parametrize("name", ["secret-db", "--privileged", "../web", ""])
def test_non_allow_listed_containers_are_denied(
    docker: DockerTools, fake_docker: FakeDocker, name: str
) -> None:
    with pytest.raises(ToolError, match="denied"):
        docker.logs(name)
    assert not [c for c in fake_docker.calls if c[0] == "logs"]


def test_backend_failure_surfaces_as_tool_error(docker: DockerTools) -> None:
    with pytest.raises(ToolError, match="backend_error"):
        docker.inspect("worker-2")


RAW_INSPECT: dict[str, Any] = {
    "Id": "f00dfeedbeef0123456789",
    "Name": "/web",
    "Created": "2026-01-01T00:00:00Z",
    "RestartCount": 4,
    "State": {
        "Status": "restarting",
        "Running": False,
        "Restarting": True,
        "OOMKilled": True,
        "ExitCode": 137,
        "Error": "",
        "Health": {
            "Status": "unhealthy",
            "Log": [{"ExitCode": 1, "Output": "curl: (7) connection refused"}],
        },
    },
    "Config": {
        "Image": "nginx:1.27",
        "Cmd": ["nginx", "-g", "daemon off;"],
        "Env": ["PATH=/usr/bin", "DB_PASSWORD=hunter2", "API_TOKEN=abc", "MODE=prod"],
        "Labels": {"com.example.team": "platform"},
    },
    "HostConfig": {"RestartPolicy": {"Name": "always"}, "Memory": 268435456, "NanoCpus": 5e8},
    "NetworkSettings": {"Networks": {"backend": {}, "frontend": {}}, "Ports": {}},
    "Mounts": [{"Type": "volume", "Destination": "/data", "RW": True, "Source": "/var/x"}],
}


def test_summarise_inspect_masks_secret_env() -> None:
    summary = summarise_inspect(RAW_INSPECT)
    assert summary["name"] == "web"
    assert summary["id"] == "f00dfeedbeef"
    assert summary["env"] == ["PATH=/usr/bin", "DB_PASSWORD=***", "API_TOKEN=***", "MODE=prod"]
    assert summary["state"]["oom_killed"] is True
    assert summary["state"]["health"] == "unhealthy"
    assert summary["state"]["last_health_checks"][0]["exit_code"] == 1
    assert summary["networks"] == ["backend", "frontend"]
    assert summary["cpus"] == 0.5
    assert "Source" not in json.dumps(summary["mounts"])
    assert "hunter2" not in json.dumps(summary)


class Recorder:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr
        self.argv: list[str] = []

    def __call__(self, argv: list[str], **_: Any) -> subprocess.CompletedProcess[bytes]:
        self.argv = argv
        return subprocess.CompletedProcess(
            argv, self.returncode, self.stdout.encode(), self.stderr.encode()
        )


def test_cli_backend_builds_safe_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = Recorder("out")
    monkeypatch.setattr(subprocess, "run", rec)
    DockerCliBackend().logs("web", tail=5, since="15m")
    assert rec.argv == ["docker", "logs", "--tail=5", "--timestamps", "--since=15m", "--", "web"]


def test_cli_backend_parses_ps(monkeypatch: pytest.MonkeyPatch) -> None:
    row = {"ID": "abcdef1234567890", "Names": "web", "Image": "nginx", "State": "running",
           "Status": "Up 1 hour", "Ports": "0.0.0.0:80->80/tcp"}  # fmt: skip
    monkeypatch.setattr(subprocess, "run", Recorder(json.dumps(row) + "\n\n"))
    (summary,) = DockerCliBackend().list_containers(include_stopped=True)
    assert (summary.id, summary.name, summary.state) == ("abcdef123456", "web", "running")


def test_cli_backend_inspect(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = Recorder(json.dumps([RAW_INSPECT]))
    monkeypatch.setattr(subprocess, "run", rec)
    assert DockerCliBackend().inspect("web")["restart_count"] == 4
    assert rec.argv[-2:] == ["--", "web"]


def test_cli_backend_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", Recorder(returncode=1, stderr="No such container"))
    with pytest.raises(BackendError, match="No such container"):
        DockerCliBackend().inspect("web")


@pytest.mark.parametrize("since", ["yesterday", "1w", "$(id)"])
def test_cli_backend_rejects_bad_since(since: str) -> None:
    with pytest.raises(ValidationError):
        DockerCliBackend().logs("web", tail=1, since=since)


def test_cli_backend_missing_binary() -> None:
    with pytest.raises(BackendError, match="not found"):
        DockerCliBackend(binary="definitely-not-docker-xyz").list_containers()
