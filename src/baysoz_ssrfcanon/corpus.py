# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Deterministic adversarial SSRF corpus generator.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from .ipcanon import UNSPECIFIED_IPV4
from .model import AddressClass, CorpusCase

_TECHNIQUES = (
    ("octal-ipv4", "0177.0.0.1", AddressClass.LOOPBACK, "inet_aton octal loopback"),
    ("hex-ipv4", "0x7f000001", AddressClass.LOOPBACK, "hexadecimal numeric loopback"),
    ("decimal-ipv4", "2130706433", AddressClass.LOOPBACK, "32-bit decimal loopback"),
    ("short-ipv4", "127.1", AddressClass.LOOPBACK, "abbreviated dotted quad"),
    ("mapped-ipv6", "[::ffff:127.0.0.1]", AddressClass.LOOPBACK, "IPv4-mapped loopback"),
    ("ipv6-loopback", "[::1]", AddressClass.LOOPBACK, "bracketed IPv6 loopback"),
    ("percent-host", "%31%32%37.0.0.1", AddressClass.LOOPBACK, "percent-decoded host"),
    (
        "userinfo",
        "trusted.example.com@127.0.0.1",
        AddressClass.LOOPBACK,
        "userinfo prefix confusion",
    ),
    ("backslash", "trusted.example.com\\@127.0.0.1", AddressClass.LOOPBACK, "separator confusion"),
    ("trailing-dot", "localhost.", AddressClass.UNRESOLVED, "DNS trailing-dot bypass"),
    ("metadata-ip", "169.254.169.254", AddressClass.METADATA, "cloud metadata endpoint"),
    ("metadata-name", "metadata.google.internal", AddressClass.METADATA, "metadata hostname"),
    ("link-local-v6", "[fe80::1]", AddressClass.LINK_LOCAL, "IPv6 link-local"),
    ("unspecified", UNSPECIFIED_IPV4, AddressClass.UNSPECIFIED, "unspecified IPv4 address"),
)


def _with_host(seed: str, host: str) -> str:
    parts = urlsplit(seed)
    path = parts.path or "/"
    if "\\" in host:
        suffix = path
        if parts.query:
            suffix = f"{suffix}?{parts.query}"
        if parts.fragment:
            suffix = f"{suffix}#{parts.fragment}"
        return f"{parts.scheme}://{host}{suffix}"
    netloc = host
    if parts.port is not None:
        netloc = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, path, parts.query, parts.fragment))


def forge(seed: str = "https://trusted.example.com/app") -> tuple[CorpusCase, ...]:
    """Build a stable corpus of real canonicalization bypass candidates."""
    cases = [
        CorpusCase(
            case_id=f"SSRF-{index:02d}",
            technique=technique,
            url=_with_host(seed, host),
            expected_class=expected,
            rationale=rationale,
        )
        for index, (technique, host, expected, rationale) in enumerate(_TECHNIQUES, start=1)
    ]
    return tuple(cases)
