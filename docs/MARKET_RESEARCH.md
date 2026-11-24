# Market Research — baysoz-ssrfcanon

Baysöz Labs <baysozlabs@proton.me> · research snapshot: 2026-11-24 · live `gh search repos` / `gh search issues`

## 1. Why this problem exists in 2026–2027

Server-side request forgery is no longer only a classic "fetch an internal URL" bug. Modern
incidents are **canonicalization failures**: the component that checks a URL is not the
component that dereferences it. Evidence mined from live GitHub during this build:

| Signal (live GitHub, 2026-11-24) | Observation |
| --- | --- |
| `swisskyrepo/SSRFmap` — 3,652 stars | Offensive SSRF fuzzing demand is large and durable. |
| `reddelexc/hackerone-reports` — 6,770 stars | Disclosed-report corpus is a top-10k security resource. |
| `nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters` — 12,364 stars | SSRF is a first-class bug-hunting discipline. |
| `assetnote/blind-ssrf-chains` — 997 stars | Post-exploitation chains matter after a bypass is found. |
| `pipelab-org/pipelock` — 1,022 stars | Agent/egress firewalls now explicitly scan SSRF and exfiltration. |
| `nisshchayarathi/gitverse-nextjs#2083` (open) | `validateSafeUrl` vulnerable to DNS rebinding SSRF bypass. |
| `Anton-dot911/opportunity-engine#7` (open) | "Pin DNS resolution and harden SSRF protection" — check/fetch split is real. |
| `Limppano-ODD/wa-gateway#88` (open) | `link-preview-js@3.0.14` DNS rebinding bypass / incomplete fix for CVE-2026-43897. |
| `node-ip` issues (open) | Octal (`017700000001`), null-route (`0`) and permissive IPv6 regex bypasses. |
| `private-ip` issues (open) | Dedicated SSRF bypass in a popular allow/deny IP library. |
| `apertus-writer` security audit (open) | IPv4-mapped IPv6 reaches cloud metadata through a web proxy guard. |
| `anthropics/claude-code#42765` (open) | RFC 8252 loopback `127.0.0.1` vs `localhost` redirect mismatch. |
| `openai/codex#30460` (open) | MCP OAuth callback override not treated as exact redirect URI. |

The recurring root causes are: numeric IPv4 aliases (`0x7f000001`, `2130706433`, `0177.0.0.1`),
IPv4-in-IPv6 embeddings (`::ffff:127.0.0.1`), percent-decoded hosts, userinfo/separator
confusion, trailing-dot DNS names, redirect chains, and DNS rebinding between validation and
connection. Each has been reported *again* in 2026 despite mature libraries. A tooling gap
persists: teams validate a guard with one parser and ship a client that uses another.

## 2. Portfolio gap analysis

The existing Baysöz Labs portfolio already covers adjacent surfaces:

- `baysoz-desyncforge` — HTTP/1.1 request-smuggling *framing* differentials.
- `baysoz-josegate` — JOSE/JWT algorithm confusion.
- `baysoz-reachoracle` — Python vulnerability reachability from SBOM/AST evidence.
- `baysoz-netpol-oracle`, `baysoz-routegate`, `baysoz-disruption-oracle` — Kubernetes control plane.
- `baysoz-gqlcostgate`, `bolaforge`, `baysoz-cspforge` — API/authorization/browser policy.
- `baysoz-mcpcontract`, `baysoz-actionlock`, `baysoz-otelgate` — supply chain and telemetry config.

None of them answers: *"does my SSRF guard agree with the runtime that will actually open the
socket?"* Building another scanner or fuzzer would be redundant. `baysoz-ssrfcanon` is an
**offline differential semantics oracle** for the URL authority → IP address decision, which is
the shared root cause behind all of the issues above.

## 3. Product decision

- **Name:** `baysoz-ssrfcanon` (Python 3.13+, zero runtime dependencies, `uv`-managed).
- **Core:** four faithfully modeled authority interpreters (`python-313`, `whatwg`, `go-124`,
  `libc-numeric`), one declarative TOML guard policy, deterministic DNS fixture with rebinding
  analysis, offline redirect-chain simulation, a 14-case adversarial corpus, and SARIF 2.1.0.
- **Why offline-first:** reproducible CI gates, no target traffic, no authorization pitfalls,
  no heavy services, no local models. Red teams use the corpus against systems they are
  authorized to test; CI uses the oracle against guard code and policy.
- **Why SARIF:** it drops into GitHub code scanning, ESLint-style CI summaries and existing
  Baysöz Labs gates without a new reporting pipeline.
- **Non-goals:** exploitation, payload delivery, live DNS/network access, stealth, persistence.

## 4. Success criteria

A URL whose guard interpretation differs from any modeled runtime interpretation must produce a
stable `SSRF-CANON-001` finding; a guard that permits a blocked class produces `-002`; TOCTOU
DNS fixtures produce `-003`; followed redirects into blocked space produce `-004`. All findings
carry CWE-918 tags and deterministic fingerprints. Zero runtime dependencies means the tool
works in air-gapped review environments.

— Baysöz Labs <baysozlabs@proton.me>
