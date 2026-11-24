# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Corpus generator tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from baysoz_ssrfcanon.corpus import forge
from baysoz_ssrfcanon.model import AddressClass


def test_corpus_size_and_uniqueness() -> None:
    cases = forge()
    assert len(cases) == 14
    assert len({case.case_id for case in cases}) == 14
    assert len({case.url for case in cases}) == 14


def test_corpus_is_deterministic() -> None:
    assert forge("http://app.internal.test/path?q=1") == forge("http://app.internal.test/path?q=1")


def test_corpus_contains_high_value_techniques() -> None:
    techniques = {case.technique for case in forge()}
    assert {"octal-ipv4", "hex-ipv4", "decimal-ipv4", "mapped-ipv6", "metadata-ip"} <= techniques


def test_expected_classes() -> None:
    cases = {case.technique: case for case in forge()}
    assert cases["metadata-ip"].expected_class == AddressClass.METADATA
    assert cases["decimal-ipv4"].expected_class == AddressClass.LOOPBACK
    assert cases["trailing-dot"].expected_class == AddressClass.UNRESOLVED


def test_seed_path_and_query_are_preserved() -> None:
    cases = forge("https://trusted.test/deep/path?q=1#frag")
    assert all("/deep/path?q=1#frag" in case.url for case in cases)
