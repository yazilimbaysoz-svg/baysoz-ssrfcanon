# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Command-line interface for the SSRF canonicalization oracle.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .corpus import forge
from .model import ATTRIBUTION, GuardPolicy
from .policy import DEFAULT_POLICY, load_policy
from .render import render_explain, render_findings
from .sarif import build_sarif
from .selftest import run_selftest
from .verdict import scan_chain, scan_url

_DESCRIPTION = (
    "Offline SSRF guard differential oracle: canonicalization, adversarial corpus, SARIF CI gate."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="baysoz-ssrfcanon",
        description=f"{_DESCRIPTION} By {ATTRIBUTION}.",
        epilog=f"Baysöz Labs — {ATTRIBUTION}",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"baysoz-ssrfcanon {__version__} — Baysöz Labs <baysozlabs@proton.me>",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser(
        "scan",
        help="scan URLs or an offline redirect chain",
        description=f"Scan URLs across all parser profiles. By {ATTRIBUTION}.",
        epilog=f"Baysöz Labs — {ATTRIBUTION}",
    )
    scan.add_argument("urls", nargs="*", metavar="URL")
    scan.add_argument("--chain", nargs="+", metavar="URL", help="offline redirect chain")
    scan.add_argument("--policy", metavar="TOML", help="guard policy file")
    scan.add_argument("--format", choices=("text", "sarif"), default="text")
    scan.add_argument("--output", metavar="PATH", help="write report to a file")

    forge_cmd = commands.add_parser(
        "forge",
        help="generate the adversarial canonicalization corpus",
        description=f"Forge bypass candidates offline. By {ATTRIBUTION}.",
        epilog=f"Baysöz Labs — {ATTRIBUTION}",
    )
    forge_cmd.add_argument("--seed", default="https://trusted.example.com/app")
    forge_cmd.add_argument("--format", choices=("text", "json"), default="text")

    explain = commands.add_parser(
        "explain",
        help="explain every profile's authority interpretation",
        description=f"Explain one URL across profiles. By {ATTRIBUTION}.",
        epilog=f"Baysöz Labs — {ATTRIBUTION}",
    )
    explain.add_argument("url", metavar="URL")
    explain.add_argument("--policy", metavar="TOML", help="guard policy file")

    commands.add_parser(
        "selftest",
        help="run embedded release invariants",
        description=f"Run embedded invariants. By {ATTRIBUTION}.",
        epilog=f"Baysöz Labs — {ATTRIBUTION}",
    )
    return parser


def _load(args: argparse.Namespace) -> GuardPolicy:
    if getattr(args, "policy", None):
        return load_policy(args.policy)
    return DEFAULT_POLICY


def _scan(args: argparse.Namespace, policy: GuardPolicy) -> int:
    if bool(args.urls) == bool(args.chain):
        print("provide URLs or --chain, not both", file=sys.stderr)
        return 2
    if args.chain:
        findings = scan_chain(tuple(args.chain), policy)
    else:
        findings = tuple(item for url in args.urls for item in scan_url(url, policy))
    if args.format == "sarif":
        report = json.dumps(build_sarif(findings, policy), indent=2, ensure_ascii=False)
    else:
        report = render_findings(findings)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    else:
        print(report)
    return 1 if findings else 0


def _forge(args: argparse.Namespace) -> int:
    cases = forge(args.seed)
    if args.format == "json":
        payload = {"attribution": ATTRIBUTION, "cases": [asdict(case) for case in cases]}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for case in cases:
            print(f"{case.case_id} {case.technique:<16} {case.url}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args, _load(args))
        if args.command == "forge":
            return _forge(args)
        if args.command == "explain":
            print(render_explain(args.url, _load(args)))
            return 0
        failures = run_selftest()
        for failure in failures:
            print(f"FAIL: {failure}")
        if failures:
            return 1
        print(f"UNANIMOUS PASS — all embedded invariants hold. {ATTRIBUTION}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc} — {ATTRIBUTION}", file=sys.stderr)
        return 2
