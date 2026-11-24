# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Differential verdict tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from baysoz_ssrfcanon.model import GuardPolicy
from baysoz_ssrfcanon.policy import DEFAULT_POLICY
from baysoz_ssrfcanon.verdict import scan_chain, scan_url

RULES = {finding.rule_id for finding in scan_url("http://0177.0.0.1/", DEFAULT_POLICY)}


def test_octal_divergence_is_reported() -> None:
    findings = scan_url("http://0177.0.0.1/", DEFAULT_POLICY)
    assert "SSRF-CANON-001" in {finding.rule_id for finding in findings}
    profiles = {finding.profile for finding in findings}
    assert {"whatwg", "libc-numeric"}.issubset(profiles)
    assert all("CWE-918" in finding.tags for finding in findings)


def test_plain_public_url_is_clean() -> None:
    assert scan_url("https://example.com/", DEFAULT_POLICY) == ()


def test_loopback_literal_is_denied_by_guard_without_divergence() -> None:
    findings = scan_url("http://127.0.0.1/", DEFAULT_POLICY)
    assert all(finding.rule_id != "SSRF-CANON-001" for finding in findings)


def test_guard_gap_is_reported() -> None:
    policy = GuardPolicy(name="permissive", deny_loopback=False)
    findings = scan_url("http://127.0.0.1/", policy)
    assert "SSRF-CANON-002" in {finding.rule_id for finding in findings}


def test_dns_rebinding_window() -> None:
    policy = GuardPolicy(
        name="dns",
        dns_records={"rebind.example.com": ("93.184.216.34", "169.254.169.254")},
    )
    findings = scan_url("https://rebind.example.com/fetch", policy)
    assert "SSRF-CANON-003" in {finding.rule_id for finding in findings}
    assert findings[0].address_class.value == "metadata"


def test_dns_pinning_removes_rebinding_window() -> None:
    policy = GuardPolicy(
        name="pinned",
        pin_dns=True,
        dns_records={"rebind.example.com": ("93.184.216.34", "127.0.0.1")},
    )
    assert scan_url("https://rebind.example.com/fetch", policy) == ()


def test_redirect_chain_escape() -> None:
    policy = GuardPolicy(name="chain", follow_redirects=True)
    findings = scan_chain(
        ("https://trusted.example.com/go", "http://169.254.169.254/latest/meta-data/"),
        policy,
    )
    assert "SSRF-CANON-004" in {finding.rule_id for finding in findings}


def test_redirect_chain_without_follow_is_inert() -> None:
    policy = GuardPolicy(name="no-redirect", follow_redirects=False)
    findings = scan_chain(
        ("https://trusted.example.com/go", "http://127.0.0.1/"),
        policy,
    )
    assert "SSRF-CANON-004" not in {finding.rule_id for finding in findings}


def test_results_are_deterministic() -> None:
    first = scan_url("http://0x7f000001/", DEFAULT_POLICY)
    assert first == scan_url("http://0x7f000001/", DEFAULT_POLICY)
