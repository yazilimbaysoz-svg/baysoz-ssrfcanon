# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Human-readable renderers for the CLI.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from .authority import PROFILES, analyze
from .guard import effective_authority, evaluate
from .model import ATTRIBUTION, Finding, GuardPolicy


def render_findings(findings: tuple[Finding, ...]) -> str:
    if not findings:
        return f"No SSRF divergences found. — {ATTRIBUTION}"
    lines = [f"SSRF canonicalization findings — {ATTRIBUTION}", ""]
    for finding in findings:
        lines.append(
            f"[{finding.severity.upper():<7}] {finding.rule_id} "
            f"{finding.address_class.value} via {finding.profile}"
        )
        lines.append(f"    URL: {finding.url}")
        lines.append(f"    {finding.detail}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_explain(url: str, policy: GuardPolicy) -> str:
    lines = [f"Authority explanation for {url} — {ATTRIBUTION}", ""]
    lines.append(f"{'profile':<14} {'host':<30} {'port':<7} {'class':<12} guard")
    for profile in PROFILES:
        authority = effective_authority(analyze(url, profile), policy)
        decision = evaluate(analyze(url, profile), policy)
        lines.append(
            f"{profile:<14} {authority.host[:30]:<30} "
            f"{str(authority.port or '-'):<7} {authority.info.address_class.value:<12} "
            f"{'ALLOW' if decision.allowed else 'DENY'}"
        )
        notes = ", ".join(authority.notes) or "-"
        lines.append(f"    reason: {authority.info.reason}; notes: {notes}")
    return "\n".join(lines)
