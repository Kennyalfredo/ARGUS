# pr-agent

**Autonomous offensive-security agent built on [Claude Code](https://docs.anthropic.com/en/docs/claude-code)**

20+ specialized subagents that chain together to run bug-bounty recon, web-application pentesting, cloud-configuration audits, and digital-footprint assessments — then package findings into submission-ready reports. All with a human in the loop: nothing is submitted automatically.

---

## What it does

| Mode | Trigger | What runs |
|------|---------|-----------|
| **Bug-bounty recon** | `/program-load <url>` | Ingest a HackerOne/Bugcrowd/Intigriti program, then hunt for leaked secrets, exposed buckets, subdomain takeovers, and sensitive endpoints — all passive |
| **Web-vuln hunting** | `/webvuln-surface` → `/hunt-*` | Active IDOR/BOLA, XSS, SQLi, SSRF testing via Burp MCP with strict compliance gates and proof ceilings |
| **Cloud audit** | `/audit-cloud <slug> <profile>` | Authenticated AWS posture scan (Prowler, ScoutSuite, CloudFox, PMapper, IAM analysis) with automated false-positive triage |
| **Digital footprint** | `/domain <domain>` | External attack-surface assessment: DNS, web portals, IP reputation, breach exposure, employee OSINT |

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

     ┌──────────────────────────────────────────────────────┐
     │              ACTIVE WEB-VULN TIER                    │
     │  webvuln-surface → access-control-hunter (IDOR)      │
     │                  → xss-hunter · sqli-hunter          │
     │                  → ssrf-hunter                       │
     │  All via Burp MCP · strict compliance gate (§1)      │
     │  Proof ceiling: confirm, don't exploit               │
     └──────────────────────────────────────────────────────┘
```

---

## Subagents

| Agent | Purpose | Tools |
|-------|---------|-------|
| `program-scope-parser` | Ingest program scope from H1/BC/Intigriti | WebFetch, Bash |
| `program-scout` | Find high-yield programs to target | WebFetch, Bash |
| `secret-hunter` | Leaked credentials (trufflehog + noseyparker + GH codesearch) | Bash |
| `bucket-hunter` | Cloud storage enumeration (S3/GCS/Azure, listing-only) | Bash |
| `takeover-hunter` | Subdomain takeover candidates (subfinder + subzy) | Bash |
| `endpoint-hunter` | Sensitive endpoints (gau + waymore + httpx + nuclei) | Bash |
| `ownership-verifier` | 3-check ownership chain before any report is drafted | Bash |
| `report-drafter` | Bug-bounty markdown (H1/BC format) | Read, Write |
| `access-control-hunter` | IDOR / BOLA / BFLA / mass-assignment | Burp MCP |
| `xss-hunter` | Reflected / stored / DOM XSS | Burp + Playwright |
| `sqli-hunter` | Boolean, time-based, error-based SQLi | Burp MCP |
| `ssrf-hunter` | OOB callbacks, metadata, protocol handlers | Burp MCP |
| `webvuln-surface` | Build testable injection-point inventory | Burp + Playwright |
| `auth-context` | Credential custody for authenticated testing | Burp MCP |
| `footprint-hunter` | Digital-footprint OSINT (DNS, portals, reputation) | Bash |
| `cloud-auditor` | AWS posture (Prowler + ScoutSuite + CloudFox + PMapper) | Bash |
| `retro-analyzer` | Post-engagement retrospective → rules + lessons | Read, Write |
| `typst-reporter` | Typst report authoring engine | Read, Write, Bash |
| `huella-reporter` | Spanish digital-footprint report assembly | Read, Write |

---

## Slash commands

```
/program-load <url>          Ingest a bug-bounty program
/find-programs               Scout high-yield programs
/route <slug>                Engine-routing recommendation

/hunt-secrets <slug>         Leaked credential hunt
/hunt-buckets <slug>         Cloud bucket enumeration
/hunt-takeovers <slug>       Subdomain takeover scan
/hunt-endpoints <slug>       Sensitive endpoint discovery

/auth-load <slug>            Store test-account credentials
/webvuln-surface <slug>      Build injection-point inventory
/hunt-access <slug>          IDOR/BOLA/BFLA hunting
/hunt-xss <slug>             Cross-site scripting
/hunt-sqli <slug>            SQL injection
/hunt-ssrf <slug>            Server-side request forgery

/verify-ownership <asset>    Ownership verification
/draft-report <slug>         Bug-bounty report
/informe <slug> <type>       Typst client deliverable
/domain <domain>             Digital-footprint assessment
/audit-cloud <slug> <prof>   AWS cloud audit

/retro <slug>                Post-engagement retrospective
/outcome <slug> <id>         Record triager disposition
/dup-check <slug> <asset>    Duplicate-risk assessment
/stats                       Pipeline metrics & funnel
/coverage-checklist <slug>   Internal-pentest checklist
```

---

## Learning loop

The agent learns from every engagement through a structured feedback loop:

1. **Hunt** → subagents produce candidates
2. **Verify** → ownership-verifier applies the 3-check chain
3. **Draft** → report-drafter applies severity caps and inflation guards
4. **Submit** → human reviews and submits
5. **Outcome** → `/outcome` records the triager's verdict
6. **Retro** → `/retro` proposes new rules grounded in what actually happened
7. **Apply** → rules land in `memory/rules.json` with provenance and confidence tiers

Rules have three confidence levels:
- **low/medium** — self-judged from engagement analysis
- **high** — grounded in external truth (triager verdict or explicit operator policy)

Falsified rules are disabled with a reason, not deleted — they serve as cautionary records.

The current rule base contains **60+ learned rules** across all subagents, distilled from 30+ engagements.

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
- **No auto-submit:** every report requires human review before submission
- **Credentials off-repo:** auth tokens stored at `/mnt/files/` with `chmod 0600`, never in git

---

## Getting started

### Prerequisites

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- For passive recon: `trufflehog`, `noseyparker`, `s3scanner`, `subfinder`, `subzy`, `gau`, `httpx`, `nuclei` (see `tools.md` for full inventory)
- For active web-vuln: [Burp Suite](https://portswigger.net/burp) with the [Burp MCP extension](https://github.com/PortSwigger/burp-mcp)
- For cloud audits: `prowler`, `scoutsuite`, `cloudfox`, `pmapper`, `cloudsplaining`

### Setup

```bash
git clone https://github.com/Kennyalfredo/pr-agent.git
cd pr-agent
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
- **Rules** accumulate in `memory/rules.json` — the agent's learned behavior from past engagements
- **Lessons** are summarized in `memory/lessons.md` — methodology insights in plain English
- Replace `YOUR_ORG` references with your organization name for branded report output

---

## Project structure

```
pr-agent/
├── .claude/
│   ├── agents/            19 subagent definitions
│   ├── commands/          15 slash commands
│   ├── skills/            Compliance gate (webvuln-compliance)
│   ├── hooks/             Coverage gate hook
│   └── settings.json      Project settings
├── memory/
│   ├── rules.json         60+ learned rules (anonymized)
│   └── lessons.md         Methodology lessons
├── scripts/               Routing, stats, dedup, outcome tracking
├── tools.md               Binary inventory & versions
└── README.md
```

---

## License

This project is provided as-is for educational and authorized security testing purposes. Use responsibly and only against systems you have explicit permission to test.
