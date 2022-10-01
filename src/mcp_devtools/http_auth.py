"""Optional static bearer-token check for the streamable-HTTP transport.

stdio needs no authentication (the client spawned the process), but an HTTP
listener is reachable by anything that can reach the port. When a token is
configured every request must carry ``Authorization: Bearer <token>``.
"""

from __future__ import annotations

import hmac
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

ENV_HTTP_TOKEN = "MCP_DEVTOOLS_HTTP_TOKEN"  # noqa: S105 - env var name, not a secret


class BearerTokenMiddleware:
    def __init__(self, app: ASGIApp, token: str, *, exempt_paths: frozenset[str] = frozenset()):
        if not token:
            raise ValueError("token must not be empty")
        self.app = app
        self._expected = f"Bearer {token}".encode()
        self.exempt_paths = exempt_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in self.exempt_paths:
            await self.app(scope, receive, send)
            return
        supplied = b""
        for key, value in scope.get("headers", []):
            if key == b"authorization":
                supplied = value
                break
        if not hmac.compare_digest(supplied, self._expected):
            await _unauthorised(send)
            return
        await self.app(scope, receive, send)


async def _unauthorised(send: Send) -> None:
    body = b'{"error":"unauthorized"}'
    headers: list[Any] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        (b"www-authenticate", b'Bearer realm="mcp-devtools"'),
    ]
    await send({"type": "http.response.start", "status": 401, "headers": headers})
    await send({"type": "http.response.body", "body": body})
