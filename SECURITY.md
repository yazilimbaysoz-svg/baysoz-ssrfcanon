# Security Policy — baysoz-ssrfcanon

Baysöz Labs <baysozlabs@proton.me>

## Scope

The tool is a **defensive, offline analysis library and CLI**. It parses strings and TOML only.
It does not open sockets, resolve DNS via the OS, execute downloaded content, or contact any
service. Adversarial URLs produced by `forge` are inert test data.

## Threat model

| Threat | Mitigation |
| --- | --- |
| Malicious URL causing parser crashes | Bounded string parsing, guarded exception paths, invalid authority class. |
| Rebinding between check and fetch | Offline fixture with multiple answers; `SSRF-CANON-003` when `pin_dns` is false. |
| Canonicalization bypass | Four profiles compared; `SSRF-CANON-001` on any blocked-class divergence. |
| Guard misconfiguration | `SSRF-CANON-002` when the policy permits a forbidden class. |
| Redirect escape | Offline chain simulation; `SSRF-CANON-004` when `follow_redirects` is enabled. |
| Supply-chain drift | Zero runtime dependencies; lockfile-free stdlib design; pinned CI actions. |
| Secret leakage | No telemetry, no logs of credentials beyond the URL under test. |

## Supported versions

Python 3.13+ only. Older interpreters are unsupported because the parser semantics and
`tomllib` availability are part of the contract.

## Responsible use

Point `forge` output only at systems you own or are explicitly authorized to test. The library
is safe to run in air-gapped CI: it never needs network access.

## Reporting vulnerabilities

Email **baysozlabs@proton.me** with a minimal reproducer, affected version, and expected
versus observed `AddressClass`. Please do not open public issues for unpatched bypasses.

— Baysöz Labs <baysozlabs@proton.me>
