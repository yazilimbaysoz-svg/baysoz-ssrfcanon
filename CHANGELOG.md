# Changelog — baysoz-ssrfcanon

Baysöz Labs <baysozlabs@proton.me>

## 1.0.0 — 2026-11-24

- Initial release by Baysöz Labs <baysozlabs@proton.me>.
- Four authority interpretation profiles: `python-313`, `whatwg`, `go-124`, `libc-numeric`.
- Metadata-aware IP classification including IPv4-mapped and IPv4-compatible IPv6.
- Offline DNS fixture analysis with rebinding-window detection.
- Redirect-chain escape detection and declarative TOML guard policies.
- Deterministic 14-case adversarial corpus (`forge`).
- SARIF 2.1.0 output with stable fingerprints and CWE-918 tags.
- CLI subcommands `scan`, `forge`, `explain`, `selftest`; attributed help and version.
- Zero runtime dependencies; Python 3.13+; `uv`-based quality gates.
