"""Docker backend: read-only container queries via the ``docker`` CLI.

Using the CLI rather than the Docker SDK keeps the dependency footprint small
and means the server honours whatever context, socket and TLS settings the
operator already has (``DOCKER_HOST``, ``docker context use`` ...). Only
read-only sub-commands are ever invoked: ``ps``, ``logs`` and ``inspect``.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Protocol

from mcp_devtools.errors import BackendError, ValidationError
from mcp_devtools.security.redact import REDACTED, redact_value

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SINCE = re.compile(r"^(\d+[smhd]|\d{4}-\d{2}-\d{2}(T[0-9:.]+Z?)?)$")
_SECRET_ENV = re.compile(r"(pass|secret|token|key|credential|dsn|auth)", re.IGNORECASE)


def validate_container_name(name: str) -> str:
    if not _NAME.match(name):
        raise ValidationError(f"invalid container name {name!r}")
    return name


@dataclass(frozen=True, slots=True)
class ContainerSummary:
    id: str
    name: str
    image: str
    state: str
    status: str
    ports: str


class DockerBackend(Protocol):
    def list_containers(self, *, include_stopped: bool = False) -> list[ContainerSummary]: ...

    def logs(
        self, name: str, *, tail: int, since: str | None = None, timestamps: bool = True
    ) -> str: ...

    def inspect(self, name: str) -> dict[str, Any]: ...


def summarise_inspect(raw: dict[str, Any]) -> dict[str, Any]:
    """Reduce ``docker inspect`` output to the fields useful for diagnosis.

    Environment variables whose names look sensitive have their values masked;
    the full raw document (which may contain secrets) is never returned.
    """
    state = raw.get("State") or {}
    config = raw.get("Config") or {}
    host = raw.get("HostConfig") or {}
    networks = (raw.get("NetworkSettings") or {}).get("Networks") or {}
    env: list[str] = []
    for item in config.get("Env") or []:
        key, sep, _value = str(item).partition("=")
        env.append(f"{key}={REDACTED}" if sep and _SECRET_ENV.search(key) else str(item))
    health = state.get("Health") or {}
    return redact_value(
        {
            "id": str(raw.get("Id", ""))[:12],
            "name": str(raw.get("Name", "")).lstrip("/"),
            "image": config.get("Image"),
            "created": raw.get("Created"),
            "state": {
                "status": state.get("Status"),
                "running": state.get("Running"),
                "restarting": state.get("Restarting"),
                "oom_killed": state.get("OOMKilled"),
                "exit_code": state.get("ExitCode"),
                "error": state.get("Error") or None,
                "started_at": state.get("StartedAt"),
                "finished_at": state.get("FinishedAt"),
                "health": health.get("Status"),
                "last_health_checks": [
                    {"exit_code": h.get("ExitCode"), "output": str(h.get("Output", ""))[-300:]}
                    for h in (health.get("Log") or [])[-3:]
                ],
            },
            "restart_count": raw.get("RestartCount"),
            "restart_policy": (host.get("RestartPolicy") or {}).get("Name"),
            "command": config.get("Cmd"),
            "entrypoint": config.get("Entrypoint"),
            "env": env,
            "labels": config.get("Labels") or {},
            "ports": (raw.get("NetworkSettings") or {}).get("Ports") or {},
            "networks": sorted(networks),
            "mounts": [
                {"type": m.get("Type"), "destination": m.get("Destination"), "rw": m.get("RW")}
                for m in raw.get("Mounts") or []
            ],
            "memory_limit": host.get("Memory"),
            "cpus": (host.get("NanoCpus") or 0) / 1e9 or None,
        }
    )


class DockerCliBackend:
    def __init__(self, *, binary: str = "docker", timeout: float = 15.0) -> None:
        self.binary = binary
        self.timeout = timeout

    def _run(self, args: list[str], *, merge_stderr: bool = False) -> str:
        try:
            proc = subprocess.run(
                [self.binary, *args],
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise BackendError(f"docker executable {self.binary!r} not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise BackendError(f"docker {args[0]} timed out after {self.timeout:.0f}s") from exc
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        if proc.returncode != 0:
            raise BackendError(f"docker {args[0]} failed: {stderr.strip() or proc.returncode}")
        return stdout + stderr if merge_stderr else stdout

    def list_containers(self, *, include_stopped: bool = False) -> list[ContainerSummary]:
        args = ["ps", "--no-trunc", "--format", "{{json .}}"]
        if include_stopped:
            args.insert(1, "--all")
        result: list[ContainerSummary] = []
        for line in self._run(args).splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            result.append(
                ContainerSummary(
                    id=str(row.get("ID", ""))[:12],
                    name=str(row.get("Names", "")).split(",")[0],
                    image=str(row.get("Image", "")),
                    state=str(row.get("State", "")),
                    status=str(row.get("Status", "")),
                    ports=str(row.get("Ports", "")),
                )
            )
        return result

    def logs(
        self, name: str, *, tail: int, since: str | None = None, timestamps: bool = True
    ) -> str:
        args = ["logs", f"--tail={int(tail)}"]
        if timestamps:
            args.append("--timestamps")
        if since:
            if not _SINCE.match(since):
                raise ValidationError(f"invalid 'since' value {since!r}; use e.g. 15m or 2h")
            args.append(f"--since={since}")
        args += ["--", validate_container_name(name)]
        # Containers write to both streams; docker logs replays them separately.
        return self._run(args, merge_stderr=True)

    def inspect(self, name: str) -> dict[str, Any]:
        out = self._run(["inspect", "--type=container", "--", validate_container_name(name)])
        try:
            docs = json.loads(out)
        except json.JSONDecodeError as exc:
            raise BackendError("docker inspect returned invalid JSON") from exc
        if not docs:
            raise BackendError(f"container {name!r} not found")
        return summarise_inspect(docs[0])
