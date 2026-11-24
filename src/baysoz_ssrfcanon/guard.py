# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Guard decision engine.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from .dns import effective_info
from .model import (
    BLOCKED_CLASSES,
    AddressClass,
    Authority,
    GuardDecision,
    GuardPolicy,
)

CLASS_FLAG = {
    AddressClass.LOOPBACK: "deny_loopback",
    AddressClass.PRIVATE: "deny_private",
    AddressClass.LINK_LOCAL: "deny_link_local",
    AddressClass.METADATA: "deny_metadata",
    AddressClass.RESERVED: "deny_reserved",
    AddressClass.MULTICAST: "deny_reserved",
    AddressClass.UNSPECIFIED: "deny_reserved",
}


def effective_authority(authority: Authority, policy: GuardPolicy) -> Authority:
    """Return an authority whose address class accounts for offline DNS answers."""
    if authority.info.address_class != AddressClass.UNRESOLVED:
        return authority
    info = effective_info(authority.host, policy.dns_records)
    return Authority(
        profile=authority.profile,
        url=authority.url,
        scheme=authority.scheme,
        raw_host=authority.raw_host,
        host=authority.host,
        port=authority.port,
        info=info,
        notes=authority.notes,
    )


def evaluate(authority: Authority, policy: GuardPolicy) -> GuardDecision:
    """Apply the declared guard rules to one interpreted authority."""
    resolved = effective_authority(authority, policy)
    reasons: list[str] = []
    host = resolved.host.lower().rstrip(".")
    if resolved.info.address_class == AddressClass.INVALID:
        reasons.append("malformed-authority")
    if host in {name.lower() for name in policy.deny_hosts}:
        reasons.append("host-in-deny-list")
    if policy.allow_hosts and host not in {name.lower() for name in policy.allow_hosts}:
        reasons.append("host-not-in-allow-list")
    if resolved.port is not None and policy.allow_ports and resolved.port not in policy.allow_ports:
        reasons.append("port-not-allowed")
    if resolved.info.address_class in BLOCKED_CLASSES:
        flag = CLASS_FLAG[resolved.info.address_class]
        if getattr(policy, flag):
            reasons.append(f"blocked-class:{resolved.info.address_class.value}")
    return GuardDecision(not reasons, tuple(reasons))
