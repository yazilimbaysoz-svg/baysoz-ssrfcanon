# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Offline DNS fixture resolution for deterministic SSRF analysis.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from .ipcanon import parse_ipv4_strict, parse_ipv6
from .model import AddressClass, AddressInfo


def normalize_host(host: str) -> str:
    return host.lower().rstrip(".")


def resolve(host: str, records: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Resolve a host from the offline fixture; numeric literals resolve to themselves."""
    key = normalize_host(host)
    if key in records:
        return records[key]
    literal = parse_ipv4_strict(key) or parse_ipv6(key.strip("[]"))
    if literal is not None:
        return (literal,)
    return ()


def effective_info(host: str, records: dict[str, tuple[str, ...]]) -> AddressInfo:
    """Classify a host using the first fixture answer, as a naive guard would."""
    answers = resolve(host, records)
    if not answers:
        return AddressInfo(host, AddressClass.UNRESOLVED, "no-dns-fixture-record", False)
    from .ipcanon import classify_ip

    first = classify_ip(answers[0])
    return AddressInfo(first.address, first.address_class, f"dns-answer:{first.reason}", False)


def rebind_targets(host: str, records: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Return later fixture answers that can appear after the guard checked the host."""
    return resolve(host, records)[1:]
