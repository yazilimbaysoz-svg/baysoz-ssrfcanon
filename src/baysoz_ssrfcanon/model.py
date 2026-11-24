# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Shared domain model for the SSRF canonicalization oracle.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"


class AddressClass(str, Enum):
    PUBLIC = "public"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    PRIVATE = "private"
    METADATA = "metadata"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    UNSPECIFIED = "unspecified"
    UNRESOLVED = "unresolved"
    INVALID = "invalid"


BLOCKED_CLASSES = frozenset(
    {
        AddressClass.LOOPBACK,
        AddressClass.LINK_LOCAL,
        AddressClass.PRIVATE,
        AddressClass.METADATA,
        AddressClass.RESERVED,
        AddressClass.MULTICAST,
        AddressClass.UNSPECIFIED,
    }
)

SEVERITY_BY_CLASS = {
    AddressClass.METADATA: "error",
    AddressClass.LOOPBACK: "error",
    AddressClass.PRIVATE: "error",
    AddressClass.LINK_LOCAL: "error",
    AddressClass.RESERVED: "warning",
    AddressClass.MULTICAST: "warning",
    AddressClass.UNSPECIFIED: "warning",
}


@dataclass(frozen=True, slots=True)
class AddressInfo:
    address: str
    address_class: AddressClass
    reason: str
    is_literal: bool


@dataclass(frozen=True, slots=True)
class Authority:
    profile: str
    url: str
    scheme: str
    raw_host: str
    host: str
    port: int | None
    info: AddressInfo
    notes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class GuardPolicy:
    name: str
    profile: str = "python-313"
    allow_hosts: tuple[str, ...] = ()
    deny_hosts: tuple[str, ...] = ()
    allow_ports: tuple[int, ...] = (80, 443)
    deny_loopback: bool = True
    deny_private: bool = True
    deny_link_local: bool = True
    deny_metadata: bool = True
    deny_reserved: bool = True
    follow_redirects: bool = False
    redirect_limit: int = 3
    pin_dns: bool = False
    dns_records: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GuardDecision:
    allowed: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    url: str
    profile: str
    address_class: AddressClass
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CorpusCase:
    case_id: str
    technique: str
    url: str
    expected_class: AddressClass
    rationale: str
