from __future__ import annotations

import pytest

from mcp_devtools.config import Settings
from mcp_devtools.errors import PermissionDenied, ValidationError
from mcp_devtools.security.permissions import Policy
from mcp_devtools.security.ssrf import SsrfGuard, is_public_address
from tests.fakes import FakeResolver


@pytest.fixture
def guard(settings: Settings, fake_resolver: FakeResolver) -> SsrfGuard:
    return SsrfGuard(Policy(settings), fake_resolver)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1%eth0",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "2002:7f00:0001::",
        "not-an-ip",
    ],
)
def test_non_public_addresses_are_detected(address: str) -> None:
    assert not is_public_address(address)


@pytest.mark.parametrize("address", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_pass(address: str) -> None:
    assert is_public_address(address)


def test_allowed_public_host(guard: SsrfGuard) -> None:
    target = guard.check_url("https://example.com/status")
    assert target.host == "example.com"
    assert target.port == 443
    assert target.addresses == ("93.184.215.14",)


def test_wildcard_host_and_ipv6(guard: SsrfGuard) -> None:
    assert guard.check_url("http://API.example.org/").port == 80


def test_host_not_on_allow_list(guard: SsrfGuard) -> None:
    with pytest.raises(PermissionDenied, match="not allow-listed"):
        guard.check_url("https://evil.test/")


def test_wildcard_does_not_match_apex_lookalike(guard: SsrfGuard) -> None:
    with pytest.raises(PermissionDenied):
        guard.check_url("https://example.org.evil.test/")


def test_allow_listed_host_resolving_to_private_ip_is_blocked(guard: SsrfGuard) -> None:
    with pytest.raises(PermissionDenied, match="non-public"):
        guard.check_url("https://internal.example.org/")


def test_any_private_answer_blocks_the_host(guard: SsrfGuard) -> None:
    with pytest.raises(PermissionDenied, match=r"127.0.0.1"):
        guard.check_url("https://rebind.example.org/")


def test_private_networks_can_be_opted_in(settings: Settings, fake_resolver: FakeResolver) -> None:
    opened = settings.model_copy(
        update={"http": settings.http.model_copy(update={"allow_private_networks": True})}
    )
    guard = SsrfGuard(Policy(opened), fake_resolver)
    assert guard.check_url("https://internal.example.org/").addresses == ("10.0.0.7",)
    guard.check_peer("10.0.0.7")


@pytest.mark.parametrize(
    ("url", "error"),
    [
        ("ftp://example.com/", ValidationError),
        ("file:///etc/passwd", ValidationError),
        ("gopher://example.com/", ValidationError),
        ("https://user:pw@example.com/", ValidationError),
        ("https:///nohost", ValidationError),
        ("https://example.com:22/", PermissionDenied),
        ("https://example.com:99999/", ValidationError),
    ],
)
def test_rejects_bad_urls(guard: SsrfGuard, url: str, error: type[Exception]) -> None:
    with pytest.raises(error):
        guard.check_url(url)


def test_literal_ip_must_still_be_allow_listed(guard: SsrfGuard) -> None:
    with pytest.raises(PermissionDenied):
        guard.check_url("http://169.254.169.254/latest/meta-data/")


def test_unresolvable_host(guard: SsrfGuard, settings: Settings) -> None:
    with pytest.raises(ValidationError, match="did not resolve"):
        SsrfGuard(Policy(settings), FakeResolver({})).check_url("https://example.com/")


def test_peer_check_blocks_rebinding(guard: SsrfGuard) -> None:
    guard.check_peer("93.184.215.14")
    guard.check_peer(None)
    with pytest.raises(PermissionDenied):
        guard.check_peer("127.0.0.1")
