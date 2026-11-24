# baysoz-ssrfcanon

[![CI](https://github.com/yazilimbaysoz-svg/baysoz-ssrfcanon/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-ssrfcanon/actions/workflows/ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Baysöz Labs](https://img.shields.io/badge/maintained%20by-Bays%C3%B6z%20Labs-orange.svg)](mailto:baysozlabs@proton.me)

**Offline SSRF guard differential oracle: URL/IP canonicalization across parser profiles,
adversarial bypass corpus, and SARIF CI gates.**

Maintained by **Baysöz Labs — baysozlabs@proton.me**.
Baysöz Labs <baysozlabs@proton.me> owns and maintains this project.

## Why

A guard that checks `http://0177.0.0.1/` with Python's `ipaddress` sees a DNS name. A browser,
Node/WHATWG client or libc `inet_aton` sees `127.0.0.1`. That gap is CWE-918 in production, and
it keeps reappearing (octal forms, `0x7f000001`, `::ffff:127.0.0.1`, DNS rebinding, metadata
hostnames). `baysoz-ssrfcanon` detects the gap **without sending a single packet**.

## Install

```bash
uv venv
uv pip install -e .
uv pip install pytest
baysoz-ssrfcanon --version
```

Python 3.13+, zero runtime dependencies.

## Architecture

```
URL + TOML guard policy
  -> authority.analyze (python-313 / whatwg / go-124 / libc-numeric)
  -> ipcanon.parse + classify (metadata-aware, IPv4-mapped IPv6 aware)
  -> dns fixture (first answer = guard view, later answers = rebinding)
  -> guard.evaluate -> verdict.findings -> text or SARIF 2.1.0
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md).

## Commands

| Command | Purpose |
| --- | --- |
| `scan URL [URL...]` | Differential scan; exit 1 when findings exist (CI gate). |
| `scan --chain U1 U2 ...` | Offline redirect-chain escape analysis. |
| `scan --format sarif --output report.sarif` | Emit SARIF 2.1.0 for code scanning. |
| `forge [--seed URL] [--format json]` | Generate 14 deterministic bypass candidates. |
| `explain URL` | Show every profile's host, port, class and guard decision. |
| `selftest` | Run embedded invariants (used by the release tribunal). |

Rules: `SSRF-CANON-001` canonicalization divergence, `-002` guard classification gap,
`-003` DNS rebinding window, `-004` redirect escape. All carry CWE-918 tags.

## Real CLI output

```console
$ baysoz-ssrfcanon scan http://0177.0.0.1/
SSRF canonicalization findings — Baysöz Labs <baysozlabs@proton.me>

[ERROR  ] SSRF-CANON-001 loopback via whatwg
    URL: http://0177.0.0.1/
    guard=python-313 saw unresolved (no-dns-fixture-record); whatwg saw loopback (ipv4-loopback) for host 127.0.0.1

[ERROR  ] SSRF-CANON-001 loopback via libc-numeric
    URL: http://0177.0.0.1/
    guard=python-313 saw unresolved (no-dns-fixture-record); libc-numeric saw loopback (ipv4-loopback) for host 127.0.0.1
```

```console
$ baysoz-ssrfcanon explain http://2130706433/
Authority explanation for http://2130706433/ — Baysöz Labs <baysozlabs@proton.me>

profile        host                           port    class        guard
python-313     2130706433                     -       unresolved   ALLOW
    reason: no-dns-fixture-record; notes: -
whatwg         127.0.0.1                      -       loopback     DENY
    reason: ipv4-loopback; notes: numeric-form-normalized
go-124         2130706433                     -       unresolved   ALLOW
    reason: no-dns-fixture-record; notes: -
libc-numeric   127.0.0.1                      -       loopback     DENY
    reason: ipv4-loopback; notes: numeric-form-normalized
```

```console
$ baysoz-ssrfcanon forge
SSRF-01 octal-ipv4       https://0177.0.0.1/app
SSRF-02 hex-ipv4         https://0x7f000001/app
SSRF-03 decimal-ipv4     https://2130706433/app
SSRF-04 short-ipv4       https://127.1/app
SSRF-05 mapped-ipv6      https://[::ffff:127.0.0.1]/app
SSRF-06 ipv6-loopback    https://[::1]/app
```

## Guard policy (TOML)

```toml
[guard]
name = "ci-guard"
profile = "python-313"
allow_hosts = ["trusted.example.com"]
allow_ports = [80, 443]
deny_loopback = true
deny_private = true
deny_link_local = true
deny_metadata = true
deny_reserved = true
follow_redirects = true
redirect_limit = 3
pin_dns = true

[dns]
"public.example.com" = ["93.184.216.34"]
"rebind.example.com" = ["93.184.216.34", "127.0.0.1"]
```

Use with `baysoz-ssrfcanon scan --policy guard.toml --format sarif <urls>`.

## Quality gates

```bash
uv venv && uv pip install -e . && uv pip install pytest
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

## License

MIT — Copyright (c) 2026 **Baysöz Labs <baysozlabs@proton.me>**. See [LICENSE](LICENSE).
Security reports: **baysozlabs@proton.me**. No legal entity suffix is used by this project.
