# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Declarative guard policy loading and validation.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from .authority import PROFILES
from .model import GuardPolicy

DEFAULT_POLICY = GuardPolicy(name="default-python-guard")


def load_policy(path: str | Path) -> GuardPolicy:
    """Load a TOML guard description without executing code or contacting services."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    guard = data.get("guard", {})
    records = {
        str(name).lower().rstrip("."): tuple(str(ip) for ip in answers)
        for name, answers in data.get("dns", {}).items()
    }
    profile = str(guard.get("profile", DEFAULT_POLICY.profile))
    if profile not in PROFILES:
        message = f"unknown guard profile: {profile}"
        raise ValueError(message)
    return GuardPolicy(
        name=str(guard.get("name", DEFAULT_POLICY.name)),
        profile=profile,
        allow_hosts=tuple(str(item).lower() for item in guard.get("allow_hosts", ())),
        deny_hosts=tuple(str(item).lower() for item in guard.get("deny_hosts", ())),
        allow_ports=tuple(int(item) for item in guard.get("allow_ports", (80, 443))),
        deny_loopback=bool(guard.get("deny_loopback", True)),
        deny_private=bool(guard.get("deny_private", True)),
        deny_link_local=bool(guard.get("deny_link_local", True)),
        deny_metadata=bool(guard.get("deny_metadata", True)),
        deny_reserved=bool(guard.get("deny_reserved", True)),
        follow_redirects=bool(guard.get("follow_redirects", False)),
        redirect_limit=int(guard.get("redirect_limit", 3)),
        pin_dns=bool(guard.get("pin_dns", False)),
        dns_records=records,
    )
