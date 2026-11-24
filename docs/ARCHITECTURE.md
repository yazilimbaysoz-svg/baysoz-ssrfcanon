# Architecture — baysoz-ssrfcanon

Baysöz Labs <baysozlabs@proton.me>

## Data flow

```
URL / redirect chain + TOML guard policy
        |
        v
  authority.analyze(url, profile)  ------> python-313 | whatwg | go-124 | libc-numeric
        |                                   (split, userinfo, percent, IDNA, brackets)
        v
  ipcanon.parse/classify  ----------------> canonical IP + AddressClass + reason
        |
        +--> dns.resolve(offline fixture) -> first answer (guard view) / later answers (rebind)
        |
        v
  guard.evaluate  -----------------------> GuardDecision(allowed, reasons)
        |
        v
  verdict.scan_url / scan_chain  --------> Finding(001..004, severity, tags)
        |
        +--> render.render_findings / render_explain      (human)
        +--> sarif.build_sarif                            (SARIF 2.1.0, CI)
```

## Module contract

| Module | Responsibility |
| --- | --- |
| `model.py` | Immutable value types, address taxonomy, severity map, attribution constant. |
| `ipcanon.py` | `inet_aton`/WHATWG extended IPv4, strict IPv4, IPv6 zones, metadata-aware classification. |
| `authority.py` | Four profile-specific authority interpretations; never performs I/O. |
| `dns.py` | Fixture-only resolution, first-answer view, rebinding candidate extraction. |
| `policy.py` | TOML guard loading and validation with stdlib `tomllib`. |
| `guard.py` | Applies allow/deny host, port and address-class rules to one authority. |
| `verdict.py` | Runs the differential and emits deterministic findings. |
| `corpus.py` | Generates 14 stable canonicalization bypass candidates from a seed. |
| `sarif.py` | SARIF 2.1.0 serialization with SHA-256 partial fingerprints. |
| `render.py` | Human-readable findings and per-profile explanation tables. |
| `selftest.py` | Embedded invariants used by the release tribunal and CI. |
| `cli.py` | `scan`, `forge`, `explain`, `selftest` subcommands; attribution in help/version. |

## Profile semantics (deliberately modeled, not guessed)

| Profile | Authority rules | Numeric IPv4 | IPv6 zone |
| --- | --- | --- | --- |
| `python-313` | `urllib.parse` netloc, last `@`, no percent decode, no backslash folding | strict dotted quad (`ipaddress`) | rejected |
| `whatwg` | special-scheme `\` → `/`, percent-decode, IDNA→ASCII, last `@` | extended: octal/hex/decimal/short | `%25zone` tolerated |
| `go-124` | `net/url`-style last `@` and host percent-decode | strict (`netip` parity) | zone tolerated |
| `libc-numeric` | raw host from URL split, no decode | `inet_aton` numeric forms | rejected |

## Determinism and safety

- No sockets, no subprocesses, no dynamic imports, no environment-dependent behavior.
- DNS answers come only from the supplied TOML fixture; absent records yield `unresolved`.
- Findings are ordered by rule/URL/profile; SARIF fingerprints are SHA-256 over those fields.
- Every address classification is pure and unit-tested, including mapped/compatible IPv6.
- The CLI exits 1 when findings exist so it can be used as a CI gate.

## Extension points

Add a profile by implementing one `analyze()` branch plus its invariant tests; add a guard rule
by adding a finding constructor in `verdict.py` and a SARIF rule descriptor. Both are covered by
the embedded self-test. Baysöz Labs <baysozlabs@proton.me>
