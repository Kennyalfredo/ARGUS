# BEAR-AGENT

**Autonomous offensive security platform — from recon to report.**

Multi-agent system built on [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that orchestrates passive reconnaissance, active vulnerability hunting, cloud posture auditing, and client-ready reporting through 30+ coordinated AI agents — built for professional penetration testing and bug bounty operations.

All findings require human review before submission. Nothing is auto-submitted.

---

## What it does

| Mode | Trigger | What runs |
|------|---------|-----------|
| **Bug-bounty recon** | `/program-load <url>` | Ingest a HackerOne/Bugcrowd/Intigriti program, then hunt for leaked secrets, exposed buckets, subdomain takeovers, and sensitive endpoints — all passive |
| **Web-vuln hunting** | `/webvuln-surface` → `/hunt-*` | 16-class active testing (IDOR, XSS, SQLi, SSRF, SSTI, RCE, XXE, OAuth, JWT, smuggling, race conditions, file upload, open redirect, GraphQL, deserialization, mass-assignment) via Burp MCP with strict compliance gates and proof ceilings |
| **Cloud audit** | `/audit-cloud <slug> <profile>` | Authenticated AWS posture scan (Prowler, ScoutSuite, CloudFox, PMapper, IAM analysis) with automated false-positive triage |
| **Digital footprint** | `/domain <domain>` | External attack-surface assessment: DNS, web portals, IP reputation, breach exposure, employee OSINT |
| **Internal pentest** | `/coverage-checklist` | PTES/NIST-800-115/CIS/OWASP/ATT&CK control-by-status matrix |

Every mode flows into one of two reporting channels:
- **Bug-bounty markdown** → `/draft-report` (HackerOne/Bugcrowd format)
- **Client Typst deliverable** → `/informe` (compiled PDF, staged for delivery)

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │             ORCHESTRATOR                │
                    │  /program-load  /route  /stats          │
                    └──────────┬──────────────┬───────────────┘
                               │              │
              ┌────────────────┼──────────────┼────────────────┐
              │                │              │                │
     ┌────────▼──────┐ ┌──────▼───────┐ ┌────▼─────┐ ┌───────▼───────┐
     │ secret-hunter │ │bucket-hunter │ │ takeover │ │endpoint-hunter│
     │  trufflehog   │ │  s3scanner   │ │  hunter  │ │  gau+waymore  │
     │  noseyparker  │ │  cloud_enum  │ │ subfinder│ │  nuclei/httpx │
     │  gh-codesearch│ │              │ │   subzy  │ │               │
     └───────┬───────┘ └──────┬───────┘ └────┬─────┘ └───────┬───────┘
             │                │              │                │
             └────────────────┼──────────────┼────────────────┘
                              │              │
                    ┌─────────▼──────────────▼─────────┐
                    │      ownership-verifier           │
                    │  3-check chain: GH + Wayback + DNS│
                    │  positive-proof model for buckets │
                    └──────────────┬────────────────────┘
                                   │
                    ┌──────────────▼────────────────────┐
                    │        report-drafter              │
                    │  hard-gated on verdict == owned    │
                    │  severity caps · no-inflation rule │
                    └──────────────┬────────────────────┘
                                   │
                    ┌──────────────▼────────────────────┐
                    │     HUMAN REVIEW & SUBMIT         │
                    │     (nothing is auto-submitted)    │
                    └──────────────────────────────────┘

     ┌──────────────────────────────────────────────────────────────┐
     │                   ACTIVE WEB-VULN TIER                      │
     │  webvuln-surface → 16 class hunters via Burp MCP            │
     │                                                              │
     │  access-control (IDOR/BOLA/BFLA/mass-assignment)            │
     │  xss · sqli · ssrf · ssti · rce · xxe                      │
     │  oauth · jwt · smuggling · race · upload · redirect         │
     │  graphql · deserialization                                   │
     │                                                              │
     │  Strict compliance gate (§1) · Proof ceiling: confirm only  │
     └──────────────────────────────────────────────────────────────┘
```

---

## Agents

### Passive recon tier

| Agent | Purpose | Tools |
|-------|---------|-------|
| `program-scope-parser` | Ingest program scope from H1/BC/Intigriti | WebFetch, Bash |
| `program-scout` | Find high-yield programs across platforms | WebFetch, Bash |
| `secret-hunter` | Leaked credentials (trufflehog + noseyparker + GH codesearch) | Bash |
| `bucket-hunter` | Cloud storage enumeration (S3/GCS/Azure, listing-only) | Bash |
| `takeover-hunter` | Subdomain takeover candidates (subfinder + subzy) | Bash |
| `endpoint-hunter` | Sensitive endpoints (gau + waymore + httpx + nuclei) | Bash |
| `ownership-verifier` | 3-check ownership chain before any report is drafted | Bash |
| `footprint-hunter` | Digital-footprint OSINT (DNS, portals, reputation, breaches) | Bash |

### Active web-vuln tier

| Agent | Vulnerability class | Tools |
|-------|---------------------|-------|
| `access-control-hunter` | IDOR / BOLA / BFLA / mass-assignment | Burp MCP |
| `xss-hunter` | Reflected / stored / DOM / blind XSS | Burp + Playwright |
| `sqli-hunter` | Error-based / boolean-blind / time-blind / UNION SQLi | Burp MCP |
| `ssrf-hunter` | OOB callbacks, cloud metadata, protocol handlers | Burp MCP |
| `ssti-hunter` | Template injection across 6+ engines | Burp MCP |
| `rce-hunter` | OS command injection (time-delay, OOB, inline) | Burp MCP |
| `xxe-hunter` | XML external entity injection (OOB, file read, SSRF) | Burp MCP |
| `oauth-hunter` | OAuth 2.0/OIDC redirect bypass, token leakage, PKCE bypass | Burp MCP |
| `jwt-hunter` | Algorithm confusion, weak secrets, claim tampering | Burp MCP |
| `smuggling-hunter` | HTTP request smuggling (CL.TE, TE.CL, H2.CL, CL.0) | Burp MCP |
| `race-hunter` | Race conditions / TOCTOU (single-packet attack) | Burp MCP |
| `upload-hunter` | File upload bypass (extension, type, polyglot, path traversal) | Burp MCP |
| `redirect-hunter` | Open redirect (parameter, path, header-based) | Burp MCP |
| `graphql-hunter` | Introspection, auth bypass, batching, injection | Burp MCP |
| `deser-hunter` | Insecure deserialization (Java, PHP, .NET, Python, Ruby, Node) | Burp MCP |

### Infrastructure

| Agent | Purpose | Tools |
|-------|---------|-------|
| `webvuln-surface` | Build testable injection-point inventory | Burp + Playwright |
| `auth-context` | Credential custody for authenticated testing | Burp MCP |
| `cloud-auditor` | AWS posture (Prowler + ScoutSuite + CloudFox + PMapper) | Bash |
| `report-drafter` | Bug-bounty markdown (H1/BC format, gated on ownership) | Read, Write |
| `syscloud-reporter` | Typst client deliverable authoring engine | Read, Write, Bash |
| `huella-reporter` | Digital-footprint report assembly | Read, Write |
| `retro-analyzer` | Post-engagement retrospective → rules + lessons | Read, Write |

---

## Slash commands

```
# Program management
/program-load <url>          Ingest a bug-bounty program
/find-programs               Scout high-yield programs across H1/BC/Intigriti
/route <slug>                Engine-routing recommendation by target profile

# Passive recon
/hunt-secrets <slug>         Leaked credential hunt
/hunt-buckets <slug>         Cloud bucket enumeration
/hunt-takeovers <slug>       Subdomain takeover scan
/hunt-endpoints <slug>       Sensitive endpoint discovery

# Active web-vuln hunting
/auth-load <slug>            Store test-account credentials
/webvuln-surface <slug>      Build injection-point inventory
/hunt-access <slug>          IDOR / BOLA / BFLA / mass-assignment
/hunt-xss <slug>             Cross-site scripting
/hunt-sqli <slug>            SQL injection
/hunt-ssrf <slug>            Server-side request forgery
/hunt-ssti <slug>            Server-side template injection
/hunt-rce <slug>             OS command injection
/hunt-xxe <slug>             XML external entity injection
/hunt-oauth <slug>           OAuth 2.0/OIDC flaws
/hunt-jwt <slug>             JWT authentication bypass
/hunt-smuggling <slug>       HTTP request smuggling
/hunt-race <slug>            Race conditions / TOCTOU
/hunt-upload <slug>          File upload vulnerabilities
/hunt-redirect <slug>        Open redirects
/hunt-graphql <slug>         GraphQL security
/hunt-deser <slug>           Insecure deserialization

# Reporting & delivery
/verify-ownership <asset>    Ownership verification (3-check chain)
/draft-report <slug>         Bug-bounty markdown report
/informe <slug> <type>       Typst client deliverable (tecnico|ejecutivo|huella)
/domain <domain>             Digital-footprint assessment
/audit-cloud <slug> <prof>   AWS cloud posture audit

# Operations
/retro <slug>                Post-engagement retrospective
/outcome <slug> <id>         Record triager disposition
/dup-check <slug> <asset>    Duplicate-risk assessment
/stats                       Pipeline metrics & funnel
/coverage-checklist <slug>   Pentest coverage matrix
```

---

## Learning loop

ARGUS learns from every engagement through a structured feedback loop:

1. **Hunt** — subagents produce candidates
2. **Verify** — ownership-verifier applies the 3-check chain
3. **Draft** — report-drafter applies severity caps and inflation guards
4. **Submit** — human reviews and submits
5. **Outcome** — `/outcome` records the triager's verdict
6. **Retro** — `/retro` proposes new rules grounded in what actually happened
7. **Apply** — rules land in `memory/rules.json` with provenance and confidence tiers

Rules have three confidence levels:
- **low/medium** — self-judged from engagement analysis
- **high** — grounded in external truth (triager verdict or explicit operator policy)

Falsified rules are disabled with a reason, not deleted — they serve as cautionary records.

---

## Safety & compliance

Every active hunter embeds a strict compliance gate at Step 0:

- **Hard gate:** refuses if automated tools are banned, scanner ban is set, target is out of scope, or no safe-harbor exists
- **Always off:** DoS, brute force, destructive mutations, data exfiltration beyond proof, attacking real users
- **Proof ceiling:** confirm the vulnerability exists, then stop
  - IDOR: read ONE adjacent object (never enumerate)
  - XSS: `alert(document.domain)` in your own session only
  - SQLi: boolean-diff or time-delay (never dump tables)
  - SSRF: OOB callback proof (never extract credentials)
  - RCE: single `id`/`hostname` (never reverse shells)
  - XXE: OOB callback or `/etc/hostname` (never sensitive files)
  - OAuth: redirect to controlled domain (never steal tokens)
  - JWT: forge token for your own account only
  - Smuggling: timing + self-request differential only
  - Race: minimum concurrent requests to prove the break
- **No auto-submit:** every report requires human review before submission
- **Credentials off-repo:** auth tokens stored outside the repository with restricted permissions, never in git

---

## Getting started

### Prerequisites

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- For passive recon: `trufflehog`, `noseyparker`, `s3scanner`, `subfinder`, `subzy`, `gau`, `waymore`, `httpx`, `nuclei` (see `tools.md`)
- For active web-vuln: [Burp Suite](https://portswigger.net/burp) with the [Burp MCP extension](https://github.com/PortSwigger/burp-mcp)
- For cloud audits: `prowler`, `scoutsuite`, `cloudfox`, `pmapper`, `cloudsplaining`
- For client reports: [Typst](https://typst.app/)

### Setup

```bash
git clone https://github.com/Kennyalfredo/ARGUS.git
cd ARGUS
claude
```

Then start with:
```
/program-load https://hackerone.com/your-target
/route your-target
/hunt-secrets your-target
```

### Customization

- **Agents** live in `.claude/agents/` — each is a Markdown file with YAML frontmatter (name, tools, model) and a system prompt body
- **Commands** live in `.claude/commands/` — slash commands that orchestrate the agents
- **Skills** live in `.claude/skills/` — reusable instruction sets (compliance gates, offensive technique references)
- **Hooks** live in `.claude/hooks/` — pre/post tool-use gates (coverage tracking, safety checks)
- **Rules** accumulate in `memory/rules.json` — the agent's learned behavior from past engagements
- **Lessons** are summarized in `memory/lessons.md` — methodology insights in plain English

---

## Project structure

```
ARGUS/
├── .claude/
│   ├── agents/            30+ subagent definitions
│   ├── commands/          30+ slash commands
│   ├── skills/            Compliance gates, offensive technique references
│   ├── hooks/             Coverage gate hook
│   └── settings.json      Project settings
├── memory/
│   ├── rules.json         Learned rules with provenance + confidence tiers
│   └── lessons.md         Methodology lessons from past engagements
├── scripts/               Routing, stats, dedup, outcome tracking
├── tools.md               Binary inventory & versions
└── README.md
```

---

## License

This project is provided as-is for educational and authorized security testing purposes. Use responsibly and only against systems you have explicit permission to test.
