# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""IP canonicalization tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import pytest

from baysoz_ssrfcanon.ipcanon import (
    UNSPECIFIED_IPV4,
    classify_dns_name,
    classify_ip,
    parse_ipv4_extended,
    parse_ipv4_strict,
    parse_ipv6,
)
from baysoz_ssrfcanon.model import AddressClass


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0177.0.0.1", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("0X7F000001", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("127.65535", "127.0.255.255"),
        ("10.0x0a.0", "10.10.0.0"),
        (UNSPECIFIED_IPV4, UNSPECIFIED_IPV4),
    ],
)
def test_extended_ipv4_forms(raw: str, expected: str) -> None:
    assert parse_ipv4_extended(raw) == expected


@pytest.mark.parametrize("raw", ["1.2.3.4.5", "0x", "08.1.1.1", "1..2.3", "-1.2.3.4", "abc"])
def test_invalid_extended_ipv4(raw: str) -> None:
    assert parse_ipv4_extended(raw) is None


def test_strict_ipv4_rejects_padding() -> None:
    assert parse_ipv4_strict("127.0.0.1") == "127.0.0.1"
    assert parse_ipv4_strict("127.0.0.01") is None
    assert parse_ipv4_strict("2130706433") is None


def test_ipv6_zones() -> None:
    assert parse_ipv6("[::1]".strip("[]")) == "::1"
    assert parse_ipv6("fe80::1%eth0") is None
    assert parse_ipv6("fe80::1%eth0", allow_zone=True) == "fe80::1"


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("127.0.0.1", AddressClass.LOOPBACK),
        ("10.1.2.3", AddressClass.PRIVATE),
        ("169.254.169.254", AddressClass.METADATA),
        ("169.254.10.1", AddressClass.LINK_LOCAL),
        ("224.0.0.1", AddressClass.MULTICAST),
        (UNSPECIFIED_IPV4, AddressClass.UNSPECIFIED),
        ("240.1.2.3", AddressClass.RESERVED),
        ("93.184.216.34", AddressClass.PUBLIC),
        ("::1", AddressClass.LOOPBACK),
        ("::ffff:10.0.0.1", AddressClass.PRIVATE),
        ("::10.0.0.1", AddressClass.PRIVATE),
        ("fd00:ec2::254", AddressClass.METADATA),
        ("fe80::1", AddressClass.LINK_LOCAL),
        ("2606:4700:4700::1111", AddressClass.PUBLIC),
    ],
)
def test_address_classes(address: str, expected: AddressClass) -> None:
    assert classify_ip(address).address_class == expected


def test_invalid_address_classification() -> None:
    info = classify_ip("not-an-ip")
    assert info.address_class == AddressClass.INVALID
    assert info.is_literal is False


def test_dns_name_classification() -> None:
    assert classify_dns_name("Metadata.Google.Internal.").address_class == AddressClass.METADATA
    assert classify_dns_name("example.com").address_class == AddressClass.UNRESOLVED
