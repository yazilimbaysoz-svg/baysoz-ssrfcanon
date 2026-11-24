# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Authority interpretation tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import pytest

from baysoz_ssrfcanon.authority import PROFILES, analyze
from baysoz_ssrfcanon.model import AddressClass


def test_all_profiles_available() -> None:
    assert PROFILES == ("python-313", "whatwg", "go-124", "libc-numeric")


@pytest.mark.parametrize("profile", PROFILES)
def test_loopback_literal_in_every_profile(profile: str) -> None:
    authority = analyze("http://127.0.0.1:8080/admin", profile)
    assert authority.info.address_class == AddressClass.LOOPBACK
    assert authority.port == 8080
    assert authority.info.is_literal


def test_numeric_forms_differ_by_profile() -> None:
    url = "http://0177.0.0.1/"
    assert analyze(url, "whatwg").info.address_class == AddressClass.LOOPBACK
    assert analyze(url, "libc-numeric").info.address_class == AddressClass.LOOPBACK
    assert analyze(url, "python-313").info.address_class == AddressClass.UNRESOLVED
    assert analyze(url, "go-124").info.address_class == AddressClass.UNRESOLVED


def test_decimal_integer_divergence() -> None:
    url = "http://2130706433/"
    assert analyze(url, "whatwg").host == "127.0.0.1"
    assert analyze(url, "python-313").host == "2130706433"
    assert analyze(url, "python-313").info.address_class == AddressClass.UNRESOLVED


def test_userinfo_is_stripped_at_last_at() -> None:
    authority = analyze("http://trusted.example.com@127.0.0.1/", "python-313")
    assert authority.host == "127.0.0.1"
    assert authority.info.address_class == AddressClass.LOOPBACK
    assert "userinfo-stripped-at-last-at" in authority.notes


def test_backslash_separator_confusion() -> None:
    url = "http://trusted.example.com\\@127.0.0.1/"
    whatwg = analyze(url, "whatwg")
    python = analyze(url, "python-313")
    assert whatwg.host == "trusted.example.com"
    assert "backslash-treated-as-separator" in whatwg.notes
    assert python.info.address_class == AddressClass.LOOPBACK


def test_percent_encoded_host() -> None:
    url = "http://%31%32%37.0.0.1/"
    assert analyze(url, "whatwg").info.address_class == AddressClass.LOOPBACK
    assert analyze(url, "python-313").info.address_class == AddressClass.UNRESOLVED
    assert "percent-decoded-host" in analyze(url, "whatwg").notes


def test_bracketed_ipv6_with_zone() -> None:
    url = "http://[fe80::1%25eth0]:8080/"
    whatwg = analyze(url, "whatwg")
    assert whatwg.host == "fe80::1"
    assert whatwg.port == 8080
    assert whatwg.info.address_class == AddressClass.LINK_LOCAL
    assert analyze(url, "python-313").info.address_class == AddressClass.INVALID


def test_invalid_url_has_invalid_authority() -> None:
    assert analyze("not-a-url", "whatwg").info.address_class == AddressClass.INVALID
    assert analyze("http://[::1", "whatwg").info.address_class == AddressClass.INVALID


def test_unknown_profile_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown profile"):
        analyze("https://example.com", "unknown")


def test_default_port_is_not_reported() -> None:
    assert analyze("https://example.com/", "python-313").port is None
