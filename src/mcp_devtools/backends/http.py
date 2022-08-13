"""HTTP probe backend: one request, one hop, no redirects, minimal body.

Redirect following and SSRF checks live in the tool layer so every hop is
re-validated; this module only performs a single request and reports what
happened on the wire, including the peer address and TLS session details.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from mcp_devtools import __version__

USER_AGENT = f"mcp-devtools-probe/{__version__}"
BODY_PREVIEW_BYTES = 2048


@dataclass(frozen=True, slots=True)
class TlsInfo:
    version: str | None
    cipher: str | None
    subject: str | None
    issuer: str | None
    not_before: str | None
    not_after: str | None
    subject_alt_names: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class HopResult:
    url: str
    status: int | None
    reason: str | None
    http_version: str | None
    headers: dict[str, str]
    elapsed_ms: float
    peer_address: str | None
    tls: TlsInfo | None
    body_preview: str | None
    error: str | None = None

    @property
    def location(self) -> str | None:
        return self.headers.get("location")

    @property
    def is_redirect(self) -> bool:
        return self.status in {301, 302, 303, 307, 308} and self.location is not None


class HttpProber(Protocol):
    def fetch(self, url: str, *, method: str, timeout: float, read_body: bool) -> HopResult: ...


def _name(parts: Any) -> str | None:
    if not parts:
        return None
    flat = [f"{k}={v}" for rdn in parts for (k, v) in rdn]
    return ", ".join(flat) or None


def tls_info_from_ssl_object(ssl_object: Any) -> TlsInfo | None:
    if ssl_object is None:
        return None
    cert = ssl_object.getpeercert() or {}
    cipher = ssl_object.cipher()
    return TlsInfo(
        version=ssl_object.version(),
        cipher=cipher[0] if cipher else None,
        subject=_name(cert.get("subject")),
        issuer=_name(cert.get("issuer")),
        not_before=cert.get("notBefore"),
        not_after=cert.get("notAfter"),
        subject_alt_names=[value for (_kind, value) in cert.get("subjectAltName", ())],
    )


class HttpxProber:
    """Real prober. ``trust_env=False`` so proxies cannot bypass the SSRF peer check."""

    def __init__(self, *, verify: bool = True, transport: httpx.BaseTransport | None = None):
        self.verify = verify
        self.transport = transport

    def fetch(self, url: str, *, method: str, timeout: float, read_body: bool) -> HopResult:
        started = time.perf_counter()
        try:
            with httpx.Client(
                verify=self.verify,
                follow_redirects=False,
                trust_env=False,
                timeout=timeout,
                headers={"user-agent": USER_AGENT},
                transport=self.transport,
            ) as client:
                request = client.build_request(method, url)
                response = client.send(request, stream=True)
                try:
                    elapsed = round((time.perf_counter() - started) * 1000, 2)
                    stream = response.extensions.get("network_stream")
                    peer = _peer(stream)
                    tls = tls_info_from_ssl_object(
                        stream.get_extra_info("ssl_object") if stream else None
                    )
                    preview = _read_preview(response) if read_body else None
                finally:
                    response.close()
        except httpx.HTTPError as exc:
            return HopResult(
                url=url,
                status=None,
                reason=None,
                http_version=None,
                headers={},
                elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
                peer_address=None,
                tls=None,
                body_preview=None,
                error=f"{type(exc).__name__}: {exc}",
            )
        return HopResult(
            url=url,
            status=response.status_code,
            reason=response.reason_phrase,
            http_version=response.http_version,
            headers={k.lower(): v for k, v in response.headers.items()},
            elapsed_ms=elapsed,
            peer_address=peer,
            tls=tls,
            body_preview=preview,
        )


def _peer(stream: Any) -> str | None:
    if stream is None:
        return None
    addr = stream.get_extra_info("server_addr")
    if isinstance(addr, tuple) and addr:
        return str(addr[0])
    return None


def _read_preview(response: httpx.Response) -> str:
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= BODY_PREVIEW_BYTES:
            break
    data = b"".join(chunks)[:BODY_PREVIEW_BYTES]
    return data.decode(response.encoding or "utf-8", errors="replace")
