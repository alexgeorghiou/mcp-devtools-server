from __future__ import annotations

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_devtools.backends.http import HttpxProber, tls_info_from_ssl_object
from mcp_devtools.tools.context import ToolContext
from mcp_devtools.tools.http_tools import HttpTools
from tests.fakes import FakeProber, hop


@pytest.fixture
def http(ctx: ToolContext) -> HttpTools:
    return HttpTools(ctx)


def test_probe_reports_status_tls_and_missing_headers(http: HttpTools) -> None:
    result = http.probe("https://example.com/")
    assert result["ok"] is True
    assert result["status"] == 200
    assert result["redirects"] == 0
    assert result["tls_expires"] == "Dec 31 23:59:59 2026 GMT"
    assert "strict-transport-security" in result["missing_security_headers"]
    assert "body_preview" not in result["hops"][0]


def test_probe_follows_and_rechecks_redirects(http: HttpTools, fake_prober: FakeProber) -> None:
    fake_prober.responses = {
        "http://example.com/": hop(
            "http://example.com/", 301, headers={"location": "https://example.com/"}
        ),
        "https://example.com/": hop("https://example.com/", 302, headers={"location": "/home"}),
        "https://example.com/home": hop("https://example.com/home"),
    }
    result = http.probe("http://example.com/")
    assert result["final_url"] == "https://example.com/home"
    assert result["redirects"] == 2
    assert result["total_ms"] == 37.5


def test_redirect_to_disallowed_host_is_blocked(http: HttpTools, fake_prober: FakeProber) -> None:
    fake_prober.responses = {
        "https://example.com/": hop(
            "https://example.com/", 302, headers={"location": "http://169.254.169.254/latest"}
        )
    }
    with pytest.raises(ToolError, match="denied"):
        http.probe("https://example.com/")
    assert fake_prober.calls == ["https://example.com/"]


def test_redirect_into_private_network_is_blocked(http: HttpTools, fake_prober: FakeProber) -> None:
    fake_prober.responses = {
        "https://example.com/": hop(
            "https://example.com/", 302, headers={"location": "https://internal.example.org/"}
        )
    }
    with pytest.raises(ToolError, match="non-public"):
        http.probe("https://example.com/")


def test_redirect_limit(http: HttpTools, fake_prober: FakeProber) -> None:
    fake_prober.responses = {
        f"https://example.com/{i}": hop(
            f"https://example.com/{i}", 302, headers={"location": f"/{i + 1}"}
        )
        for i in range(10)
    }
    result = http.probe("https://example.com/0")
    assert result["redirects"] == 2
    assert result["redirect_limit_hit"] is True
    assert len(fake_prober.calls) == 3


def test_no_follow(http: HttpTools, fake_prober: FakeProber) -> None:
    fake_prober.responses = {
        "https://example.com/": hop("https://example.com/", 301, headers={"location": "/x"})
    }
    result = http.probe("https://example.com/", follow_redirects=False)
    assert result["status"] == 301
    assert result["ok"] is True
    assert len(fake_prober.calls) == 1


def test_peer_address_rebinding_is_caught(http: HttpTools, fake_prober: FakeProber) -> None:
    fake_prober.responses = {"https://example.com/": hop("https://example.com/", peer="10.0.0.1")}
    with pytest.raises(ToolError, match=r"non-public address 10.0.0.1"):
        http.probe("https://example.com/")


def test_sensitive_response_headers_are_masked(http: HttpTools, fake_prober: FakeProber) -> None:
    fake_prober.responses = {
        "https://example.com/": hop(
            "https://example.com/", headers={"set-cookie": "sid=abc", "server": "nginx"}
        )
    }
    headers = http.probe("https://example.com/")["hops"][0]["headers"]
    assert headers == {"set-cookie": "***", "server": "nginx"}


def test_connection_errors_are_results_not_exceptions(ctx: ToolContext) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    ctx.backends.http = HttpxProber(transport=httpx.MockTransport(refuse))
    result = HttpTools(ctx).probe("https://example.com/")
    assert result["ok"] is False
    assert result["status"] is None
    assert "ConnectError" in result["hops"][0]["error"]


def test_httpx_prober_reads_preview_and_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["user-agent"].startswith("mcp-devtools-probe/")
        return httpx.Response(
            200, headers={"X-Frame-Options": "DENY"}, content=b"x" * 5000, request=request
        )

    result = HttpxProber(transport=httpx.MockTransport(handler)).fetch(
        "https://example.com/", method="GET", timeout=1, read_body=True
    )
    assert result.status == 200
    assert result.headers["x-frame-options"] == "DENY"
    assert result.body_preview is not None and len(result.body_preview) == 2048
    assert result.peer_address is None  # mock transport has no socket


def test_tls_info_extraction() -> None:
    class FakeSsl:
        def getpeercert(self) -> dict[str, object]:
            return {
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("organizationName", "Test CA"),), (("commonName", "R1"),)),
                "notBefore": "Jan 1 00:00:00 2026 GMT",
                "notAfter": "Apr 1 00:00:00 2026 GMT",
                "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            }

        def cipher(self) -> tuple[str, str, int]:
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def version(self) -> str:
            return "TLSv1.3"

    info = tls_info_from_ssl_object(FakeSsl())
    assert info is not None
    assert info.subject == "commonName=example.com"
    assert info.issuer == "organizationName=Test CA, commonName=R1"
    assert info.subject_alt_names == ["example.com", "www.example.com"]
    assert tls_info_from_ssl_object(None) is None
