# bb-agent — offensive-security agent (bug bounty · pentest · cloud)

Multi-subagent system for Claude Code. It began as a non-applicative bug-bounty
discovery pipeline (leaked credentials, exposed cloud assets, subdomain takeover)
across HackerOne / Bugcrowd / Intigriti programs, and has grown into a broader
offensive-security agent with **four engagement modes** (see below): bug-bounty
recon, external-footprint (Huella Digital), active web-vuln testing, and
**authenticated AWS cloud-configuration audits** — plus a documentation axis
(Eje 3) that packages findings into HackerOne markdown or YOUR_ORG Typst reports.

## Status

Built incrementally since 2026-05-11:
1. Tool environment + project scaffold
2. `/program-load` + `program-scope-parser` (HackerOne/Bugcrowd/Intigriti ingestion)
3. `bucket-hunter` + `ownership-verifier` (3-check ownership chain with 30-day cache)
4. `secret-hunter` (trufflehog org-sweep + GH code-search dork + noseyparker history)
5. `report-drafter` + audit trail (hard-gated on `verdict == owned`)
6. Learning loop v1: `retro-analyzer` + `/retro` + `memory/rules.json` (machine-readable rules per subagent with deterministic IDs, confidence tiers, and provenance)

## Four engagement modes

**1. Bug-bounty passive recon** (original) — ingest a program (`/program-load`), run the hunts, verify ownership, `/draft-report`. Passive-only; no light-active probing of program infra.

**2. Huella Digital** (`/domain <domain>`, added 2026-05-27) — client-work-project mode for an **external-attack-surface / digital-footprint** assessment of a single domain. Authorization = bare-domain-is-go. Synthesizes a `engagement_type:"huella_digital"` scope, runs the four hunts **plus `footprint-hunter`** (DNS surface w/ RFC1918 flagging, web-portal inventory + screenshots, IP reputation/RBL, emails/phones/social, **passive** breach listing), then **`huella-reporter`** assembles a Spanish **YOUR_ORG "Informe de Huella Digital"** at `out/<slug>/reports/huella-digital-<ts>.md` scored on a Relevancia×Complejidad severity matrix.

Mode-2 boundaries (encoded as scope-rule flags): **light-active** tier ON (httpx homepage probe + 1 screenshot/host + DNSBL) but **credential validation HARD-OFF** (leaked creds listed only, `Estado=DESCONOCIDA`, never login-tested — requires separate written authorization), **heavy-active OFF** (no CVE/exploit), and the **LinkedIn-automation ban** stays (employee data via manual paste → §1.4.3). Breach source is pluggable (HIBP default, dehashed/credshed wireable). See `tools.md` → "Huella Digital mode".

**3. Active web-vuln tier** (`feat/webvuln-tier`, added 2026-06-10) — **applicative** vulnerability hunting that sends real payloads (IDOR/BOLA/BFLA, XSS/SQLi/SSTI, SSRF/XXE, JWT/OAuth/GraphQL/race/biz-logic) via the **Burp MCP**, powered by the global `offensive-*` skills. This is the one tier that actively exploits, so it runs under a dedicated **strict per-program gate** — `.claude/skills/webvuln-compliance/SKILL.md` is the canonical contract every active hunter embeds at Step 0:

- **Hard gate (REFUSE + stop):** `automated_tools_allowed==false`, `explicit_scanner_ban==true`, target not under an in-scope wildcard, or no safe-harbor without an operator go.
- **Always off:** DoS, brute force, destructive mutations, data exfil beyond proof, attacking real users.
- **Proof ceiling ("confirm, don't exploit"):** read ONE adjacent IDOR object (never enumerate), `alert(document.domain)`-class XSS, boolean/time SQLi (no dumps), `{{7*7}}` SSTI, OOB-to-Collaborator SSRF/XXE — stop at the ceiling and report the honest lower impact. Mirrors the passive tier's *"detection is the report."*
- **Decoupled & no-auto-submit** like the rest: hunters → `ownership-verifier` (`in_scope_subdomain_override` auto-fires for in-scope wildcards) → `report-drafter`. `out/` (incl. evidence) is gitignored; live auth tokens live only at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` (`0600`, off-repo).

Pipeline: `/auth-load <slug>` (store + validate 1–2 test accounts) → `/webvuln-surface <slug>` (build the testable injection-point inventory from the gau corpus + Burp history + a light authenticated Playwright crawl — **no payloads**) → `/hunt-access <slug>` (IDOR/BOLA/BFLA/mass-assignment, Phase B) → `/verify-ownership` → `/draft-report`. Injection / SSRF-XXE / auth-API hunters land in Phases C–E. **Requires the Burp MCP connected in the `~/bb-agent` session.**

**4. Cloud configuration audit** (`/audit-cloud <slug> <aws-cli-profile>`, added 2026-07-06) — authenticated **AWS cloud-config pentest** for a contracted engagement (credential-gated client work, distinct from the bug-bounty modes). The operator provisions a **read-only** engagement role (e.g. SSO permission set with `SecurityAudit` + `IAMReadOnlyAccess`) and configures an AWS CLI profile; the command confirms identity + the read-only loadout, synthesizes a `engagement_type:"cloud_audit"` scope, and delegates to the **`cloud-auditor`** subagent.

`cloud-auditor` runs the read-only posture suite across all enabled regions — **Prowler** (CIS/PCI/NIST/SOC2, condition-aware), **ScoutSuite**, **CloudFox**, **Cloudsplaining**, **PMapper** (privesc→admin graph, region-restricted), the **IAM credential report**, **IAM Access Analyzer**, and **GuardDuty** — then applies a mandatory **false-positive triage** before writing `out/<slug>/cloud/<ts>/FINDINGS.md`. The triage is the point of the tier: scanners flag raw state, so every finding is verified (policy `Condition` awareness — trust Prowler over ScoutSuite for "public"; SG→live-instance attachment vs orphan SGs; cross-account ExternalId + vendor attribution; RDS `PubliclyAccessible` vs actual SG reachability). Verified in practice to kill ~44 S3 + ~71 SNS + ~43 SG false positives per account.

Mode-4 boundaries: **read-only, proof ceiling** ("confirm, don't exploit" — no writes, no privesc *execution*, no port scans, no `GetObject`, no secret-value reads, no cross-account `AssumeRole`). SSO STS tokens expire ~hourly → the tier pauses and requests a refresh, never proceeding on a dead token. **pacu** + **enumerate-iam** are installed but deliberately NOT wired (write/exploitation is out of scope for the read-only role; enumerate-iam is redundant when `SecurityAudit` can read policies). Deliverable = YOUR_ORG Typst via `/informe <slug> tecnico`. See `tools.md` → "Cloud pentest tooling" and the standing lesson in `memory/feedback_cloud_scanner_fp_triage.md`.

## Documentation axis (Eje 3)

Independent of *which* mode discovers the findings, two reporting channels package them for delivery (neither auto-submits):

- **Bug-bounty markdown** — `/draft-report <slug> [asset]` → `report-drafter` (HackerOne/Bugcrowd, hard-gated on `ownership == owned`).
- **YOUR_ORG Typst** — `/informe <slug> <tecnico|ejecutivo|huella>` → `typst-reporter` (client/owner deliverable authored in Typst with `@local/plantilla-report`, compiled clean, staged for typst.app). This is the channel for contracted pentest + cloud-audit + Huella deliverables.

## Directory layout

```
bb-agent/
├── README.md             — this file
├── tools.md              — binary inventory (full paths, versions, compliance rules)
├── .claude/
│   ├── agents/           — subagent definitions (.md files with frontmatter)
│   ├── commands/         — slash commands (e.g., /program-load, /tier3-hunt)
│   └── skills/           — reusable knowledge (e.g., tier3-rules)
├── memory/
│   ├── programs/         — per-program scope JSON (<slug>.json)
│   └── ownership-cache/  — ownership-verification cache (positive + negative)
└── out/                  — scan outputs, drafted reports
```

Note: bbot scan output goes to `/mnt/files/bb-agent/` (off-root partition),
NOT here. This dir is only for agent state + reports.

## Key architectural decisions

1. **Many small subagents, not one big one.** Each has restricted tools.
2. **Ownership verifier is mandatory before drafting.** Without it, squatter-owned buckets with brand-plausible names get drafted.
3. **One non-destructive validation call per finding source.** Tracked in state.
4. **No auto-submit.** Reports go to `out/<program>/reports/*.md`. Human submits.
5. **Per-program rule parsing.** Each program's restrictions become machine-readable
   flags that downstream subagents respect.

## Learning loop & metrics (added 2026-06-07)

The pipeline's biggest blind spot was that it learned only from its own pre-submission
self-judgment — `platform_outcome` was `null` on every submission, so triager verdicts
never fed back. The first four ingested dispositions (N/A, duplicate/low-impact ×2,
accepted-but-duplicate) corrected more rules than a month
of self-graded retros. Tooling that closes and measures that loop:

- **`/stats`** (`scripts/bb_stats.py`) — funnel, per-engine yield, disposition tally,
  ownership verdicts, and rule-base health (filter:discovery ratio, confidence tiers,
  ground-truth-validated count). Read-only.
- **`/outcome <slug> <report-id|asset>`** (`scripts/bb_outcome.py`) — records a triager
  verdict into the audit trail, then fires a focused single-finding retro. This is the
  **one sanctioned path to a `high`-confidence rule** — disposition-grounded, not
  self-judged.
- **`/dup-check <slug> <asset>`** (`scripts/bb_duprisk.py`) — pre-submission
  duplicate-likelihood tier (3 of the first 4 dispositions were duplicates). Advisory;
  never hard-blocks. Wired into the `/draft-report` hand-off.
- **`scripts/bb_rule_audit.py`** — standing rule-base hygiene: flags self-judged-`high`
  rules (must carry a `grounding` field), missing provenance, dup IDs, stale refs to
  disabled rules, and filter:discovery drift.
- **`/route <slug>`** (`scripts/bb_route.py`) — pre-hunt engine-routing plan. Reads the
  target profile (GH org, wildcard count, web assets, caps) + actual historical per-engine
  yield and recommends RUN / DEPRIORITIZE / SKIP per hunt. Advisory; attacks the
  clean-negative streak by not spending budget on engines that don't pay off on a given
  target class (e.g. secret-hunter SKIP when there's no GH org; takeover-hunter SKIP on
  narrow scope / scanner ban). The prior sharpens as `/outcome` records more dispositions.

Rule confidence convention: `low`/`medium` are self-judged; `high` requires a `grounding`
field (`platform_disposition:<id>` or `user_policy`). Falsified rules are disabled
(`enabled:false` + `disabled_reason`), not deleted.

## Running anything

To use the agent from Claude Code:

```bash
cd ~/bb-agent
claude
```

Then invoke slash commands like `/program-load <h1-url>` once they're built.

## Compliance rules (read tools.md for full list)

- No active mass scanning
- One validation call per source
- No bucket file downloads
- Verify ownership BEFORE drafting report
- 0-day age gate (≥30 days since publication)
