"""Redaction of secrets in values that end up in the audit log or in errors."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "***"

_SENSITIVE_KEYS = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|dsn|credential)",
    re.IGNORECASE,
)
# postgresql://user:pw@host/db  -> postgresql://user:***@host/db
_URI_PASSWORD = re.compile(r"(?P<prefix>[a-z][a-z0-9+.-]*://[^:/@\s]+:)(?P<pw>[^@\s]+)(?=@)", re.I)
# key=value pairs in libpq DSNs or query strings
_KV_SECRET = re.compile(
    r"(?P<key>\b(?:password|passwd|pwd|token|api_key|apikey|secret)\s*=\s*)(?P<val>[^\s&;]+)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?P<scheme>\bBearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE)

MAX_AUDIT_STRING = 512


def redact_text(text: str) -> str:
    """Mask credentials embedded in URIs, DSNs and authorization headers."""
    text = _URI_PASSWORD.sub(lambda m: m.group("prefix") + REDACTED, text)
    text = _KV_SECRET.sub(lambda m: m.group("key") + REDACTED, text)
    return _BEARER.sub(lambda m: m.group("scheme") + REDACTED, text)


def redact_value(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact a JSON-like value; keys that look sensitive are masked wholesale."""
    if key is not None and _SENSITIVE_KEYS.search(key):
        return REDACTED
    if isinstance(value, str):
        cleaned = redact_text(value)
        if len(cleaned) > MAX_AUDIT_STRING:
            cleaned = cleaned[:MAX_AUDIT_STRING] + f"...<{len(cleaned) - MAX_AUDIT_STRING} more>"
        return cleaned
    if isinstance(value, Mapping):
        return {str(k): redact_value(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_value(v) for v in value]
    if isinstance(value, int | float | bool) or value is None:
        return value
    return redact_text(repr(value))
