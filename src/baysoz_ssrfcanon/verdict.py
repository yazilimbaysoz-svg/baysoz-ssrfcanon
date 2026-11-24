# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Differential verdict engine and SARIF-ready findings.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from .authority import PROFILES, analyze
from .dns import resolve
from .guard import effective_authority, evaluate
from .ipcanon import classify_ip
from .model import (
    BLOCKED_CLASSES,
    SEVERITY_BY_CLASS,
    AddressClass,
    Finding,
    GuardPolicy,
)


def _finding(
    rule_id: str,
    title: str,
    detail: str,
    url: str,
    profile: str,
    address_class: AddressClass,
    tags: tuple[str, ...],
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=SEVERITY_BY_CLASS.get(address_class, "warning"),
        title=title,
        detail=detail,
        url=url,
        profile=profile,
        address_class=address_class,
        tags=tags,
    )


def scan_url(url: str, policy: GuardPolicy) -> tuple[Finding, ...]:
    """Compare one URL across every parser profile against the declared guard."""
    guard_authority = analyze(url, policy.profile)
    guard_effective = effective_authority(guard_authority, policy)
    decision = evaluate(guard_authority, policy)
    findings: list[Finding] = []

    if decision.allowed and guard_effective.info.address_class in BLOCKED_CLASSES:
        findings.append(
            _finding(
                "SSRF-CANON-002",
                "Guard accepts a forbidden address class",
                f"guard={policy.profile} saw {guard_effective.info.address_class.value} "
                f"via {guard_effective.info.reason} but allowed the request",
                url,
                policy.profile,
                guard_effective.info.address_class,
                ("CWE-918", "guard-gap"),
            )
        )

    for profile in PROFILES:
        if profile == policy.profile:
            continue
        authority = effective_authority(analyze(url, profile), policy)
        observed = authority.info.address_class
        expected = guard_effective.info.address_class
        if observed == expected:
            continue
        if observed not in BLOCKED_CLASSES and expected not in BLOCKED_CLASSES:
            continue
        blocked = observed if observed in BLOCKED_CLASSES else expected
        findings.append(
            _finding(
                "SSRF-CANON-001",
                "SSRF guard canonicalization divergence",
                f"guard={policy.profile} saw {expected.value} ({guard_effective.info.reason}); "
                f"{profile} saw {observed.value} ({authority.info.reason}) "
                f"for host {authority.host}",
                url,
                profile,
                blocked,
                ("CWE-918", "parser-differential"),
            )
        )

    if not guard_authority.info.is_literal:
        answers = resolve(guard_authority.host, policy.dns_records)
        if len(answers) > 1 and not policy.pin_dns and decision.allowed:
            for answer in answers[1:]:
                info = classify_ip(answer)
                if info.address_class in BLOCKED_CLASSES:
                    findings.append(
                        _finding(
                            "SSRF-CANON-003",
                            "DNS rebinding window between check and fetch",
                            f"guard checked {answers[0]} but {answer} "
                            f"({info.address_class.value}) may be returned at fetch time; "
                            "pin_dns is disabled",
                            url,
                            policy.profile,
                            info.address_class,
                            ("CWE-918", "toctou", "dns"),
                        )
                    )

    return tuple(findings)


def scan_chain(urls: tuple[str, ...], policy: GuardPolicy) -> tuple[Finding, ...]:
    """Scan an offline redirect chain and flag hops that escape an accepted guard."""
    findings = [finding for url in urls for finding in scan_url(url, policy)]
    if not policy.follow_redirects:
        return tuple(findings)
    for index, url in enumerate(urls):
        if index == 0 or index > policy.redirect_limit:
            continue
        authority = effective_authority(analyze(url, policy.profile), policy)
        if authority.info.address_class in BLOCKED_CLASSES:
            findings.append(
                _finding(
                    "SSRF-CANON-004",
                    "Redirect chain reaches a forbidden authority",
                    f"hop {index} resolves to {authority.info.address_class.value} "
                    f"({authority.info.reason}) while redirects are followed",
                    url,
                    policy.profile,
                    authority.info.address_class,
                    ("CWE-918", "redirect"),
                )
            )
    return tuple(findings)
