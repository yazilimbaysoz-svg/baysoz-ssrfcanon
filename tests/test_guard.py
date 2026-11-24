# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""DNS fixture and guard policy tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from pathlib import Path

import pytest

from baysoz_ssrfcanon.authority import analyze
from baysoz_ssrfcanon.dns import effective_info, normalize_host, rebind_targets, resolve
from baysoz_ssrfcanon.guard import effective_authority, evaluate
from baysoz_ssrfcanon.model import AddressClass, GuardPolicy
from baysoz_ssrfcanon.policy import DEFAULT_POLICY, load_policy

RECORDS = {
    "public.example.com": ("93.184.216.34",),
    "rebind.example.com": ("93.184.216.34", "127.0.0.1"),
    "internal.example.com": ("10.0.0.7",),
}


def test_dns_fixture_resolution() -> None:
    assert resolve("PUBLIC.EXAMPLE.COM.", RECORDS) == ("93.184.216.34",)
    assert resolve("example.com", RECORDS) == ()
    assert resolve("127.0.0.1", RECORDS) == ("127.0.0.1",)
    assert normalize_host("Example.COM.") == "example.com"


def test_effective_info_uses_first_answer() -> None:
    assert effective_info("internal.example.com", RECORDS).address_class == AddressClass.PRIVATE
    assert effective_info("public.example.com", RECORDS).address_class == AddressClass.PUBLIC
    assert rebind_targets("rebind.example.com", RECORDS) == ("127.0.0.1",)


def test_guard_denies_blocked_literal() -> None:
    decision = evaluate(analyze("http://127.0.0.1/", "python-313"), DEFAULT_POLICY)
    assert not decision.allowed
    assert "blocked-class:loopback" in decision.reasons


def test_guard_honors_disabled_flag() -> None:
    policy = GuardPolicy(name="permissive-loopback", deny_loopback=False)
    decision = evaluate(analyze("http://127.0.0.1/", "python-313"), policy)
    assert decision.allowed


def test_guard_host_and_port_rules() -> None:
    authority = analyze("https://example.com:8443/", "python-313")
    assert not evaluate(authority, DEFAULT_POLICY).allowed
    policy = GuardPolicy(name="allow-any-host", allow_ports=(8443,))
    assert evaluate(authority, policy).allowed
    blocked = GuardPolicy(name="deny-list", deny_hosts=("example.com",))
    assert not evaluate(authority, blocked).allowed


def test_effective_authority_uses_dns_fixture() -> None:
    policy = GuardPolicy(name="dns", dns_records=RECORDS)
    authority = analyze("http://internal.example.com/", "python-313")
    resolved = effective_authority(authority, policy)
    assert resolved.info.address_class == AddressClass.PRIVATE
    assert not evaluate(authority, policy).allowed


def test_policy_loading(tmp_path: Path) -> None:
    config = tmp_path / "guard.toml"
    config.write_text(
        '[guard]\nname = "ci-guard"\nprofile = "whatwg"\nallow_hosts = ["trusted.test"]\n'
        'allow_ports = [80, 443]\npin_dns = true\n\n[dns]\n"a.test" = ["203.0.113.9"]\n',
        encoding="utf-8",
    )
    policy = load_policy(config)
    assert policy.name == "ci-guard"
    assert policy.profile == "whatwg"
    assert policy.allow_hosts == ("trusted.test",)
    assert policy.allow_ports == (80, 443)
    assert policy.pin_dns is True
    assert policy.dns_records == {"a.test": ("203.0.113.9",)}


def test_policy_rejects_unknown_profile(tmp_path: Path) -> None:
    config = tmp_path / "bad.toml"
    config.write_text('[guard]\nprofile = "unknown"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="unknown guard profile"):
        load_policy(config)
