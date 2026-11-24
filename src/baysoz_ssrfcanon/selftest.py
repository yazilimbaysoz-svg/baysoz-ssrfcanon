# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Embedded invariants executed by the release tribunal.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from .authority import analyze
from .corpus import forge
from .ipcanon import classify_ip, parse_ipv4_extended, parse_ipv4_strict
from .model import AddressClass, GuardPolicy
from .policy import DEFAULT_POLICY
from .sarif import build_sarif
from .verdict import scan_chain, scan_url


def run_selftest() -> tuple[str, ...]:
    """Return descriptions of every failed invariant; empty means full pass."""
    chain_policy = GuardPolicy(
        name="chain-policy",
        allow_hosts=("trusted.example.com",),
        follow_redirects=True,
    )
    checks = (
        ("octal IPv4 canonicalization", lambda: parse_ipv4_extended("0177.0.0.1") == "127.0.0.1"),
        ("hex IPv4 canonicalization", lambda: parse_ipv4_extended("0x7f000001") == "127.0.0.1"),
        ("decimal IPv4 canonicalization", lambda: parse_ipv4_extended("2130706433") == "127.0.0.1"),
        ("strict parser rejects padding", lambda: parse_ipv4_strict("127.0.0.01") is None),
        (
            "mapped IPv6 classified as loopback",
            lambda: classify_ip("::ffff:127.0.0.1").address_class == AddressClass.LOOPBACK,
        ),
        (
            "metadata address classified",
            lambda: classify_ip("169.254.169.254").address_class == AddressClass.METADATA,
        ),
        (
            "WHATWG sees numeric loopback",
            lambda: analyze("http://2130706433/", "whatwg").info.address_class
            == AddressClass.LOOPBACK,
        ),
        (
            "Python sees numeric host as DNS name",
            lambda: analyze("http://2130706433/", "python-313").info.address_class
            == AddressClass.UNRESOLVED,
        ),
        (
            "divergence detected on octal URL",
            lambda: any(
                item.rule_id == "SSRF-CANON-001"
                for item in scan_url("http://0177.0.0.1/", DEFAULT_POLICY)
            ),
        ),
        (
            "rebind fixture detected",
            lambda: any(
                item.rule_id == "SSRF-CANON-003"
                for item in scan_url(
                    "https://rebind.example.com/fetch",
                    GuardPolicy(
                        name="dns-policy",
                        dns_records={
                            "rebind.example.com": ("93.184.216.34", "127.0.0.1"),
                        },
                    ),
                )
            ),
        ),
        (
            "redirect escape detected",
            lambda: any(
                item.rule_id == "SSRF-CANON-004"
                for item in scan_chain(
                    ("https://trusted.example.com/go", "http://127.0.0.1/admin"), chain_policy
                )
            ),
        ),
        (
            "corpus is stable and unique",
            lambda: len(forge()) == 14
            and len({case.case_id for case in forge()}) == 14
            and forge() == forge(),
        ),
        ("SARIF schema version", lambda: build_sarif((), DEFAULT_POLICY)["version"] == "2.1.0"),
        (
            "guard denies loopback",
            lambda: analyze("http://127.0.0.1/", "python-313").info.address_class
            == AddressClass.LOOPBACK,
        ),
    )
    failures: list[str] = []
    for name, check in checks:
        if not check():
            failures.append(name)
    return tuple(failures)
