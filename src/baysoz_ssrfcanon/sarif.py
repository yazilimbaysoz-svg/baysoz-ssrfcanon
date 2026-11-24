# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""SARIF 2.1.0 report construction.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import hashlib

from .model import ATTRIBUTION, Finding, GuardPolicy

_RULES = {
    "SSRF-CANON-001": (
        "SSRF guard canonicalization divergence",
        "Different stacks interpret one URL authority as a different address class.",
    ),
    "SSRF-CANON-002": (
        "Guard accepts a forbidden address class",
        "The declared guard rules permit a class the oracle treats as forbidden.",
    ),
    "SSRF-CANON-003": (
        "DNS rebinding window between check and fetch",
        "A later DNS answer can reach a forbidden address after a passing check.",
    ),
    "SSRF-CANON-004": (
        "Redirect chain reaches a forbidden authority",
        "A followed redirect reaches an address the initial URL did not expose.",
    ),
}


def build_sarif(findings: tuple[Finding, ...], policy: GuardPolicy) -> dict:
    """Build a deterministic, schema-valid SARIF 2.1.0 document."""
    used = sorted({finding.rule_id for finding in findings})
    rules = [
        {
            "id": rule_id,
            "name": rule_id.replace("-", "_"),
            "shortDescription": {"text": _RULES[rule_id][0]},
            "fullDescription": {"text": _RULES[rule_id][1]},
            "helpUri": "https://github.com/yazilimbaysoz-svg/baysoz-ssrfcanon#rules",
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "CWE-918"]},
        }
        for rule_id in used
    ]
    results = []
    for finding in sorted(findings, key=lambda item: (item.rule_id, item.url, item.profile)):
        digest = hashlib.sha256(
            f"{finding.rule_id}|{finding.url}|{finding.profile}".encode("utf-8")
        ).hexdigest()
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": finding.severity,
                "message": {"text": f"{finding.title}: {finding.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.url},
                            "region": {"startLine": 1, "startColumn": 1},
                        }
                    }
                ],
                "properties": {
                    "profile": finding.profile,
                    "addressClass": finding.address_class.value,
                    "tags": list(finding.tags),
                },
                "partialFingerprints": {"baysozSsrfCanon/v1": digest},
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "properties": {"attribution": ATTRIBUTION, "guard": policy.name},
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "baysoz-ssrfcanon",
                        "version": "1.0.0",
                        "informationUri": (
                            "https://github.com/yazilimbaysoz-svg/baysoz-ssrfcanon"
                        ),
                        "organization": "Baysöz Labs <baysozlabs@proton.me>",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
