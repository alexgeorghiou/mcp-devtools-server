from __future__ import annotations

import os
from pathlib import Path

import pytest

from mcp_devtools.config import Settings
from mcp_devtools.errors import PermissionDenied, ToolDisabled, ValidationError
from mcp_devtools.security.paths import confine
from mcp_devtools.security.permissions import Policy, matches_any


@pytest.fixture
def policy(settings: Settings) -> Policy:
    return Policy(settings)


def test_repo_allow_list(policy: Policy, git_repo: Path) -> None:
    assert policy.repo("sample") == git_repo.resolve()
    with pytest.raises(PermissionDenied, match="known: \\['sample'\\]"):
        policy.repo("other")


def test_container_patterns(policy: Policy) -> None:
    assert policy.container("web") == "web"
    assert policy.container("worker-7") == "worker-7"
    for name in ("secret-db", "webx", "", "worker"):
        with pytest.raises(PermissionDenied):
            policy.container(name)


def test_database_allow_list(policy: Policy) -> None:
    assert policy.database("app").startswith("postgresql://")
    with pytest.raises(PermissionDenied):
        policy.database("prod")


def test_host_and_port(policy: Policy) -> None:
    assert policy.host("example.com.") == "example.com."
    assert policy.host("a.example.org")
    with pytest.raises(PermissionDenied):
        policy.host("example.org")
    assert policy.port(443) == 443
    with pytest.raises(PermissionDenied):
        policy.port(6379)


def test_log_dirs(policy: Policy) -> None:
    assert policy.log_dir("app").is_dir()
    with pytest.raises(PermissionDenied):
        policy.log_dir("system")


def test_disabled_family_is_refused_even_with_allow_list(settings: Settings) -> None:
    off = settings.model_copy(update={"git": settings.git.model_copy(update={"enabled": False})})
    with pytest.raises(ToolDisabled, match="git tools are disabled"):
        Policy(off).repo("sample")


def test_matches_any_is_case_insensitive() -> None:
    assert matches_any("API-1", ["api-*"])
    assert not matches_any("api", [])


class TestConfine:
    def test_inside_root(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        assert confine(tmp_path, "a") == (tmp_path / "a").resolve()
        assert confine(tmp_path, "") == tmp_path.resolve()
        assert confine(tmp_path, "./a/") == (tmp_path / "a").resolve()

    @pytest.mark.parametrize(
        "path",
        ["../etc", "a/../../x", "..\\windows", "/etc/passwd", "C:\\Windows", "\\\\server\\share"],
    )
    def test_escapes_are_refused(self, tmp_path: Path, path: str) -> None:
        with pytest.raises(PermissionDenied):
            confine(tmp_path, path)

    def test_nul_byte(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError):
            confine(tmp_path, "a\x00b")

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_symlink_escape(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        root = tmp_path / "root"
        root.mkdir()
        (root / "link").symlink_to(outside, target_is_directory=True)
        with pytest.raises(PermissionDenied, match="outside"):
            confine(root, "link")
