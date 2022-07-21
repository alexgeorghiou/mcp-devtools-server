"""Path confinement: resolve a user-supplied relative path strictly inside a root."""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath

from mcp_devtools.errors import PermissionDenied, ValidationError


def confine(root: Path, relative: str) -> Path:
    """Return ``root / relative`` resolved, refusing anything that escapes ``root``.

    Rejects absolute paths, drive letters, NUL bytes and ``..`` segments up front,
    then resolves symlinks and checks containment again, so a symlink inside the
    root that points outside it is refused as well.
    """
    if "\x00" in relative:
        raise ValidationError("path contains a NUL byte")
    candidate = relative.strip() or "."
    if (
        PurePosixPath(candidate).is_absolute()
        or PureWindowsPath(candidate).is_absolute()
        or PureWindowsPath(candidate).drive
    ):
        raise PermissionDenied("absolute paths are not allowed; use a path relative to the root")
    parts = candidate.replace("\\", "/").split("/")
    if ".." in parts:
        raise PermissionDenied("path traversal ('..') is not allowed")

    resolved_root = root.resolve()
    target = (resolved_root / candidate).resolve()
    if target != resolved_root and not target.is_relative_to(resolved_root):
        raise PermissionDenied("path resolves outside the allowed directory")
    return target
