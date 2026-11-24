# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""SARIF report tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json

from baysoz_ssrfcanon.model import ATTRIBUTION, GuardPolicy
from baysoz_ssrfcanon.policy import DEFAULT_POLICY
from baysoz_ssrfcanon.sarif import build_sarif
from baysoz_ssrfcanon.verdict import scan_url


def test_sarif_structure() -> None:
    report = build_sarif(scan_url("http://0177.0.0.1/", DEFAULT_POLICY), DEFAULT_POLICY)
    assert report["version"] == "2.1.0"
    assert report["properties"]["attribution"] == ATTRIBUTION
    run = report["runs"][0]
    assert run["tool"]["driver"]["organization"] == ATTRIBUTION
    assert run["results"]
    assert {item["ruleId"] for item in run["results"]} == {"SSRF-CANON-001"}
    json.dumps(report)


def test_sarif_empty_report_is_valid() -> None:
    report = build_sarif((), DEFAULT_POLICY)
    assert report["runs"][0]["results"] == []
    assert report["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_fingerprints_are_stable() -> None:
    findings = scan_url("http://2130706433/", DEFAULT_POLICY)
    first = build_sarif(findings, DEFAULT_POLICY)
    second = build_sarif(findings, GuardPolicy(name="other"))
    assert first["runs"][0]["results"] == second["runs"][0]["results"]


def test_sarif_result_fields() -> None:
    finding = scan_url("http://127.0.0.1/", GuardPolicy(name="gap", deny_loopback=False))[0]
    result = build_sarif((finding,), DEFAULT_POLICY)["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "http://127.0.0.1/"
    )
    assert result["properties"]["addressClass"] == "loopback"
