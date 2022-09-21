"""HTTP probe tool: status, latency, headers, TLS and redirect chain, SSRF-guarded."""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any, Literal
from urllib.parse import urljoin

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_devtools.backends.http import HopResult
from mcp_devtools.security.redact import REDACTED
from mcp_devtools.tools.context import ToolContext

PROBE = ToolAnnotations(read_only_hint=True, open_world_hint=True)

SENSITIVE_RESPONSE_HEADERS = {"set-cookie", "www-authenticate", "proxy-authenticate"}
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)


def _hop_view(hop: HopResult, include_body: bool) -> dict[str, Any]:
    headers = {
        k: (REDACTED if k in SENSITIVE_RESPONSE_HEADERS else v) for k, v in hop.headers.items()
    }
    view: dict[str, Any] = {
        "url": hop.url,
        "status": hop.status,
        "reason": hop.reason,
        "http_version": hop.http_version,
        "elapsed_ms": hop.elapsed_ms,
        "peer_address": hop.peer_address,
        "headers": headers,
        "tls": asdict(hop.tls) if hop.tls else None,
        "error": hop.error,
    }
    if include_body:
        view["body_preview"] = hop.body_preview
    return view


class HttpTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx
        self.prober = ctx.backends.http
        self.cfg = ctx.settings.http

    def probe(
        self,
        url: str,
        method: Literal["GET", "HEAD"] = "GET",
        follow_redirects: bool = True,
        include_body: bool = False,
    ) -> dict[str, Any]:
        args = {"url": url, "method": method, "follow_redirects": follow_redirects}

        def run() -> dict[str, Any]:
            self.ctx.policy.require_enabled("http")
            hops: list[HopResult] = []
            current = url
            max_hops = self.cfg.max_redirects if follow_redirects else 0
            while True:
                target = self.ctx.ssrf.check_url(current)
                hop = self.prober.fetch(
                    target.url,
                    method=method,
                    timeout=self.cfg.timeout_seconds,
                    read_body=include_body and method == "GET",
                )
                self.ctx.ssrf.check_peer(hop.peer_address)
                hops.append(hop)
                if not hop.is_redirect or len(hops) > max_hops:
                    break
                current = urljoin(current, hop.location or "")

            final = hops[-1]
            total_ms = round(sum(h.elapsed_ms for h in hops), 2)
            return {
                "url": url,
                "final_url": final.url,
                "ok": final.error is None and final.status is not None and final.status < 400,
                "status": final.status,
                "total_ms": total_ms,
                "redirects": len(hops) - 1,
                "redirect_limit_hit": final.is_redirect,
                "missing_security_headers": [h for h in SECURITY_HEADERS if h not in final.headers]
                if final.status
                else [],
                "tls_expires": final.tls.not_after if final.tls else None,
                "hops": [_hop_view(h, include_body) for h in hops],
            }

        return self.ctx.run("http_probe", args, run)


def register(server: MCPServer, ctx: ToolContext) -> None:
    tools = HttpTools(ctx)

    @server.tool(annotations=PROBE)
    def http_probe(
        url: Annotated[str, Field(description="http(s) URL on an allow-listed host")],
        method: Literal["GET", "HEAD"] = "GET",
        follow_redirects: Annotated[
            bool, Field(description="Follow redirects, re-checking each hop")
        ] = True,
        include_body: Annotated[bool, Field(description="Include a 2 KB body preview")] = False,
    ) -> dict[str, Any]:
        """Probe an endpoint: status, latency, headers, TLS certificate and redirect chain."""
        return tools.probe(url, method, follow_redirects, include_body)
