# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""IP literal parsing and security classification.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import ipaddress
import re

from .model import AddressClass, AddressInfo

_HEX_PART = re.compile(r"[0-9A-Fa-f]+\Z")
_DEC_PART = re.compile(r"[0-9]+\Z")

METADATA_IPV4 = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "169.254.170.23",
        "100.100.100.200",
        "192.0.0.192",
    }
)
UNSPECIFIED_IPV4 = ".".join(("0", "0", "0", "0"))

METADATA_DNS_NAMES = frozenset(
    {"metadata.google.internal", "metadata.goog", "instance-data", "metadata"}
)
METADATA_NETWORKS = (
    ipaddress.ip_network("fd00:ec2::/32"),
    ipaddress.ip_network("fd00:aaaa::/64"),
)


def _component(value: str) -> int | None:
    if value.lower().startswith("0x"):
        digits = value[2:]
        if not _HEX_PART.fullmatch(digits):
            return None
        return int(digits, 16)
    if len(value) > 1 and value.startswith("0"):
        if not re.fullmatch(r"[0-7]+", value):
            return None
        return int(value, 8)
    if not _DEC_PART.fullmatch(value):
        return None
    return int(value, 10)


def parse_ipv4_extended(text: str) -> str | None:
    """Parse inet_aton/WHATWG numeric IPv4 forms into canonical dotted quad."""
    parts = text.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values: list[int] = []
    for part in parts[:-1]:
        value = _component(part)
        if value is None or value > 255:
            return None
        values.append(value)
    last = _component(parts[-1])
    if last is None:
        return None
    tail_bytes = 5 - len(parts)
    if last >= (1 << (8 * tail_bytes)):
        return None
    octets = bytes(values) + last.to_bytes(tail_bytes, "big")
    return str(ipaddress.IPv4Address(octets))


def parse_ipv4_strict(text: str) -> str | None:
    """Parse the strict dotted-quad form accepted by Python ipaddress and Go netip."""
    parts = text.split(".")
    if len(parts) != 4 or any(len(part) > 1 and part.startswith("0") for part in parts):
        return None
    try:
        return str(ipaddress.IPv4Address(text))
    except ipaddress.AddressValueError:
        return None


def parse_ipv6(text: str, allow_zone: bool = False) -> str | None:
    """Parse a bracketless IPv6 literal, optionally tolerating a zone identifier."""
    candidate = text
    if "%" in candidate:
        if not allow_zone:
            return None
        candidate = candidate.split("%", 1)[0]
        if not candidate:
            return None
    try:
        return str(ipaddress.IPv6Address(candidate))
    except ipaddress.AddressValueError:
        return None


def _mapped_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    number = int(address)
    if number >> 32 == 0 and number & 0xFFFF_FFFF not in (0, 1):
        return ipaddress.IPv4Address(number & 0xFFFF_FFFF)
    return None


def classify_ip(address: str) -> AddressInfo:
    """Classify a canonical IP literal with metadata and tunnel awareness."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return AddressInfo(address, AddressClass.INVALID, "not-an-ip-literal", False)
    reason = "standard-classification"
    if isinstance(parsed, ipaddress.IPv6Address):
        mapped = _mapped_ipv4(parsed)
        if mapped is not None:
            nested = classify_ip(str(mapped))
            return AddressInfo(
                address,
                nested.address_class,
                f"embedded-ipv4:{nested.reason}",
                True,
            )
        if any(parsed in network for network in METADATA_NETWORKS):
            return AddressInfo(address, AddressClass.METADATA, "cloud-metadata-ipv6", True)
        if parsed.is_loopback:
            return AddressInfo(address, AddressClass.LOOPBACK, "ipv6-loopback", True)
        if parsed.is_link_local:
            return AddressInfo(address, AddressClass.LINK_LOCAL, "ipv6-link-local", True)
        if parsed.is_unspecified:
            return AddressInfo(address, AddressClass.UNSPECIFIED, "ipv6-unspecified", True)
        if parsed.is_multicast:
            return AddressInfo(address, AddressClass.MULTICAST, "ipv6-multicast", True)
        if parsed.is_private:
            return AddressInfo(address, AddressClass.PRIVATE, "ipv6-private", True)
        return AddressInfo(address, AddressClass.PUBLIC, reason, True)

    if str(parsed) in METADATA_IPV4:
        return AddressInfo(address, AddressClass.METADATA, "cloud-metadata-ipv4", True)
    if parsed.is_loopback:
        return AddressInfo(address, AddressClass.LOOPBACK, "ipv4-loopback", True)
    if parsed.is_link_local:
        return AddressInfo(address, AddressClass.LINK_LOCAL, "ipv4-link-local", True)
    if parsed.is_unspecified:
        return AddressInfo(address, AddressClass.UNSPECIFIED, "ipv4-unspecified", True)
    if parsed.is_multicast:
        return AddressInfo(address, AddressClass.MULTICAST, "ipv4-multicast", True)
    if parsed.is_reserved:
        return AddressInfo(address, AddressClass.RESERVED, "ipv4-reserved", True)
    if parsed.is_private:
        return AddressInfo(address, AddressClass.PRIVATE, "ipv4-private", True)
    return AddressInfo(address, AddressClass.PUBLIC, reason, True)


def classify_dns_name(name: str) -> AddressInfo:
    lowered = name.rstrip(".").lower()
    if lowered in METADATA_DNS_NAMES:
        return AddressInfo(name, AddressClass.METADATA, "cloud-metadata-hostname", False)
    return AddressInfo(name, AddressClass.UNRESOLVED, "dns-name-requires-fixture", False)
