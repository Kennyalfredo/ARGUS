# Bug Bounty Agent — Tool Inventory

Generated 2026-05-11. Updated 2026-05-22 (Phase 2 — endpoint-hunter agent added). Updated 2026-05-27 (Huella Digital mode — footprint-hunter + huella-reporter agents, `/domain` command).
Single source of truth for which tool lives where. Subagents MUST use the full paths below — do not rely on PATH order.

## Subagent → tool map (quick reference)

| Subagent | Primary tools | Active probes? | Compliance gates |
|---|---|---|---|
| `program-scope-parser` | WebFetch + arkadiyt dump | passive only | n/a |
| `program-scout` | WebFetch (one-time dump) | passive only | n/a |
| `secret-hunter` | trufflehog (A,B) + gitleaks (B.5) + noseyparker (C) + `gh api` | passive only (GitHub-side, not against program) | `automated_tools_allowed`, `mass_scanning_allowed` |
| `bucket-hunter` | s3scanner + aws s3api recheck | passive only (AWS-side) | `bucket_listing_allowed`, `mass_scanning_allowed` |
| `takeover-hunter` | subfinder + amass + crt.sh + dnsx + subzy + curl (body recheck) + nuclei (gated) | passive enum + body recheck curl + gated nuclei | `automated_tools_allowed`, `explicit_scanner_ban`, `rate_limit_cap_rps` |
| `endpoint-hunter` (Phase 2) | gau + **waymore** (`-mode U`) + grep + httpx (gated) + curl body fetch + nuclei (gated) | passive enum + gated active live-probe | `automated_tools_allowed`, `explicit_scanner_ban`, `rate_limit_cap_rps` |
| `ownership-verifier` | gh api + gau + dig + **theHarvester (Phase 3, gh_account assets only)** | passive only | n/a |
| `report-drafter` | (no scanning — reads candidate JSONs + ownership cache) | n/a | path-leak filter |
| `retro-analyzer` | (no scanning — analyzes engagement artifacts) | n/a | n/a |
| `footprint-hunter` (Huella Digital) | bbot (passive) + subfinder/amass/crt.sh + dnsx + httpx (`-screenshot`) + gowitness + theHarvester (NO linkedin) + dig (DNSBL) + HIBP/breach (pluggable) | passive enum + **light-active** (httpx homepage probe + 1 screenshot/host + DNSBL) | `light_active_allowed`, `screenshots_allowed`, `credential_validation_allowed` (always false), `heavy_active_allowed` (false), `rate_limit_cap_rps` |
| `huella-reporter` (Huella Digital) | (no scanning — reads footprint + 4 hunt outputs + LinkedIn manual paste + ownership cache) | n/a | no-local-paths filter; vendor-cred attribution |

## Binary paths

| Tool | Full path | Version | Purpose |
|---|---|---|---|
| bbot | `~/.local/bin/bbot` | 2.8.4 | Multi-module recon orchestrator |
| trufflehog | `$GOPATH/bin/trufflehog` | 3.95.2 | Verified-secret scanner (use `--results=verified` on 3.95.x; older `--only-verified` flag was renamed). Used by `secret-hunter` Pass A (`--org=<X>`) + Pass B (`filesystem` on cloned repos). |
| gitleaks | `$GOPATH/bin/gitleaks` | latest | Second-pass secret scanner, different ruleset (RSA PEM, base64-encoded JWT-shaped, JDBC connection strings, custom regex patterns). **Phase 1 integration (2026-05-21):** used by `secret-hunter` Pass B.5 on cloned repos with `--no-git --redact --no-banner`. Filesystem-only; Pass C noseyparker covers git history. |
| noseyparker | `$GOPATH/bin/noseyparker` | 0.24.0 | Fast historical-commit secret scanner. Used by `secret-hunter` Pass C — single shared datastore across all Pass B clones, one `report --format json` call at the end. |
| subfinder | `$GOPATH/bin/subfinder` | v2.6.8 | Passive subdomain enumeration. Used by `takeover-hunter` Step 4.1 as the primary source (~50 indexed passive sources). |
| httpx | `$GOPATH/bin/httpx` | v1.9.0 | HTTP probing (ProjectDiscovery, NOT the python lib). **Phase 2 integration (2026-05-22):** used by `endpoint-hunter` Step 6 for live-probe of gau-derived sensitive-path candidates. GATED on `automated_tools_allowed=true` AND `explicit_scanner_ban != true`. Rate-limited via `-rate-limit ${rate_limit_cap_rps:-5}`. NOT used by takeover-hunter (curl body-recheck is the only allowed HTTP probe there). |
| nuclei | `$GOPATH/bin/nuclei` | v3.3.10 | Template-based vuln + takeover scanner with ~9000 templates. **Phase 1 integration (2026-05-21):** `takeover-hunter` Step 6.7 with `-t http/takeovers/`, GATED on `automated_tools_allowed=true` AND `explicit_scanner_ban != true`. **Phase 2 integration (2026-05-22):** `endpoint-hunter` Step 8 with `-t http/exposures/ -t http/misconfiguration/`, same gates. Templates restricted to those two directories — broader nuclei classes (weak-creds, vulnerability scanning) remain out of bb-agent's passive-recon scope. |
| dnsx | `$GOPATH/bin/dnsx` | latest | DNS resolution toolkit. Used by `takeover-hunter` Step 5 for CNAME extraction. **Quirk:** the May 2026 binary hangs on `-l <file>`; pipe via stdin instead. |
| katana | `$GOPATH/bin/katana` | latest | Modern web crawler. NOT used by endpoint-hunter Phase 2 (relies on gau-archived URLs + nuclei templates instead). May be added in a future phase if archived-URL coverage proves insufficient on programs with newer/less-indexed sites. |
| naabu | `$GOPATH/bin/naabu` | latest | Fast port scanner. NOT used — active by definition; doesn't fit passive recon. |
| pdtm | `$GOPATH/bin/pdtm` | latest | ProjectDiscovery tool manager |
| subzy | `$GOPATH/bin/subzy` | latest | Subdomain takeover scanner (uses can-i-take-over-xyz). Used by `takeover-hunter` Step 6 as the primary fingerprint engine. CLI: `subzy run --targets <file> --output <file>.json --vuln --hide_fails --concurrency 20 --timeout 15`. `--vuln` saves only VULNERABLE entries. **All subzy matches must pass the Step 6.5 body-recheck gate** (`rule-takeover_hunter-subzy_body_recheck_required-e91f7`) before reaching report-drafter. |
| amass | `~/.local/bin/amass` | older | OWASP subdomain enumeration. **Phase 1 integration (2026-05-21):** used by `takeover-hunter` Step 4.2 alongside subfinder + crt.sh. **Must run `amass enum -passive`** — active mode does ASN sweeps and DNS bruteforce which violate the passive-only rule. |
| s3scanner | `$GOPATH/bin/s3scanner` | dev | S3 bucket permission scanner. Used by `bucket-hunter` Pass A. **Always rechecked via `aws s3api list-objects-v2 --no-sign-request`** at Step 4.5 — `rule-bucket_hunter-s3scanner_acl_recheck_required-37651`. |
| cloud_enum | `/usr/local/bin/cloud_enum` | system | Multi-cloud (AWS/GCS/Azure) enumerator. Used by `bucket-hunter` Pass B as a fallback if Pass A returns zero hits — has not triggered in any engagement to date. |
| theHarvester-h | `~/.local/bin/theHarvester-h` | 4.10.1 | Email/employee OSINT. **Phase 3 integration (2026-05-22):** used by `ownership-verifier` Step 3.5 (Check A.5) when `asset_class == "gh_account"`. Run once per program (90-day employee-cache TTL at memory/employee-cache/<slug>.json). MANDATORY flags: `-b duckduckgo,crtsh,certspotter,dnsdumpster` (passive search engines + cert-transparency + DNS records). ⚠️ **Discovered during an early Huella run:** theHarvester 4.10.1 now rejects `google` and `bing` as "Invalid source" and ABORTS the entire run if either is passed — they were dropped from the provider set. **NEVER use `-b linkedin`, `-b linkedin_links`, or `-b companies`** — LinkedIn ToS prohibits scraping; researcher account suspension risk. The remaining providers cover the same employee-email signal. Output is cross-referenced against the GH account's public profile (name/email/company) to attribute the account to a real program employee — boosts Check A from negative to positive when matched. |
| gh | `~/.local/bin/gh` | 2.92.0 | GitHub CLI for API queries |
| gau | `$GOPATH/bin/gau` | 2.2.4 | Get All URLs (Wayback + CC + AlienVault + URLScan). Used by `ownership-verifier` Check B for asset reference history. **Phase 2 integration (2026-05-22):** primary discovery surface for `endpoint-hunter` Step 4 — queries Wayback + CommonCrawl + AlienVault OTX + URLScan in parallel for each in-scope seed domain. Fully passive (no requests against program infra). |
| waybackurls | `$GOPATH/bin/waybackurls` | latest | Wayback URL dumper. Redundant with `gau` (gau queries Wayback as one of its providers). Not used by any current agent. |
| waymore | `~/.local/bin/waymore` | 7.7 (pipx, Python 3.12) | "Find way more from the Wayback Machine" (@xnl-h4ck3r). Superset of `gau`: archived-URL discovery from Wayback + CommonCrawl + AlienVault OTX + URLScan **+ VirusTotal + Intelligence X** (the last two need API keys in `~/.config/waymore/config.yml`). Two modes: `-mode U` (URLs only — the `gau`-equivalent discovery surface) and `-mode R` (downloads the archived **response bodies**, e.g. old JS/config/`.env` snapshots — useful for finding secrets/endpoints removed from the live site). **endpoint-hunter Step 4 integration (2026-06-15):** runs `-mode U` as a complementary discovery source merged+deduped with gau (waymore's deeper Wayback pagination + extra providers widen coverage; gau stays for speed + the empty-result retry). **footprint-hunter §DNS surface integration (2026-06-15):** runs `-mode U` and extracts in-scope hostnames from the archived URLs to widen subdomain discovery beyond subfinder/amass/crt.sh. Both integrations are optional + `timeout`-guarded (skip on absent/stall). Fully passive (queries public archive aggregators only, never program infra). **KNOWN ISSUE: hangs on the Wayback CDX query in the current sandbox (gau works there) — re-validate in the live runtime; the timeout guard makes a stall harmless.** `-mode R` is OFF by default (heavier; overlaps secret-hunter scope) — enable only on explicit operator request. Honors a date window via `-from`/`-to` and filtering via config `FILTER_*`. Config lives at `~/.config/waymore/config.yml`. |
| assetfinder | `$GOPATH/bin/assetfinder` | latest | Lightweight subdomain finder |
| cariddi | `$GOPATH/bin/cariddi` | latest | Web crawl + secret extractor in one pass |
| gowitness | `~/.bbot/tools/gowitness` | bundled (Jul 2025) | Headless web screenshotter. **Huella Digital (2026-05-27):** used by `footprint-hunter` §Web portals as the fallback screenshot engine when `httpx -screenshot` is unstable. `gowitness scan file -f <hosts> --screenshot-path <dir>`. httpx v1.9.0 also has a native `-screenshot -system-chrome -srd <dir>` (preferred — one tool for probe+shot). Screenshots are a **light-active** touch (loads the public homepage) — gated on `screenshots_allowed`. |
| maigret | `~/.local/bin/maigret` | 0.6.1 | Username/handle hunter across ~3158 sites (pipx, Python 3.12.3). **Huella Digital (2026-05-29):** used by `footprint-hunter` §Social (Technique B) for brand-handle enumeration — finds social/web profiles NOT linked from the client site (incl. impersonation/squatting). Anonymous **public-URL existence checks only** (no auth, no API keys) → matches the "anonymous GET only" mandate. MANDATORY flags: `--top-sites 300 --timeout 8 --retries 1 --no-recursion --no-extracting --no-progressbar --no-color -J simple -fo <dir>`. Parse `report_<handle>_simple.json` → keep entries where `.status.status=="Claimed" AND .site.similarSearch != true` (drops search-query pseudo-hits like Google Scholar). ⚠️ **Handle-enum results are CANDIDATES, not confirmed** — maigret has false positives (e.g. geeksforgeeks); tag `confidence: "candidate"` and flag for manual visual confirmation in the report. **NEVER feed LinkedIn** (`--ignore-ids` / exclude any `linkedin` site) — LinkedIn stays on the manual-paste path (absolute scraping ban). Touches third-party platforms → gated on `social_enum_allowed`. |

## Important PATH notes

- `~/.local/bin/httpx-py` is the Python httpx library CLI (renamed from `httpx`). Don't use it for security work.
- Always invoke tools by full path in subagent scripts to avoid PATH-shadowing surprises.

## Auxiliary binaries also available

- `dig`, `curl`, `jq` — standard utilities. `curl` is used by `takeover-hunter` Step 6.5 for the live body-recheck gate (`curl -s --max-time 10 -L -k`); `jq` is used everywhere for JSON parsing.
- `git` — for cloning repos. Always shallow (`--depth=1`) for Pass B; full unshallow happens in Pass C for noseyparker history.
- `aws` — `~/.local/bin/aws` (aws-cli/1.37.2). Used by `bucket-hunter` Step 4.5 for the anonymous list-objects-v2 recheck that defangs s3scanner ACL false positives: `aws s3api list-objects-v2 --no-sign-request --bucket <n> --max-items 1`. Never call with credentials; `--no-sign-request` is mandatory for compliance with the "passive-only" hard rule.
- `~/.bbot/tools/` — bbot's bundled binaries (httpx 2022, trufflehog 3.90.8, massdns, ffuf, gowitness, jadx, nuclei, retirejs, smuggler, telerik). Older but usable if needed.

## Web services (not local binaries)

- **crt.sh** — Cert Transparency log direct query. **Phase 1 integration (2026-05-21):** used by `takeover-hunter` Step 4.3 alongside subfinder + amass for passive subdomain enumeration. Pattern: `curl -s --max-time 30 "https://crt.sh/?q=%25.<seed>&output=json"` → `jq -r '.[]?.name_value'` → dedupe. **Rate limit:** no auth, ~10 req/min — be patient on 503 / empty JSON, log and continue with subfinder+amass only.
- **Wayback Machine via `gau` binary** — `gau` is the local binary that fronts Wayback + CommonCrawl + URLScan + AlienVault OTX. Used by `ownership-verifier` Check B for asset reference history. Phase 2 endpoint-hunter will use it as a discovery surface for `/.env*`-class archived URLs.
- **Archive aggregation via `waymore`** — registered 2026-06-15 (see Binary paths). Complements `gau` in `endpoint-hunter` Step 4 with deeper Wayback pagination + VirusTotal/IntelX providers. Also fronts archive aggregators only (passive). When both run, merge+dedupe their URL output before the Step-5 sensitive-path grep. Add VT/IntelX API keys to `~/.config/waymore/config.yml` to light up those extra providers (Wayback + CC + OTX + URLScan work key-less).

## API key file

`~/.config/bbot/secrets.yml` — add your own API keys here (GitHub PAT, Postman, etc.).

⚠️ Rotate keys when done with each engagement.

## Slug-prefix convention

Programs from different platforms can share a brand name (`cloudflare` exists on multiple platforms). To prevent ownership-cache / submissions-log collisions across platforms, non-H1 programs are stored with a per-platform prefix in `memory/programs/<slug>.json`:

| Platform | Slug form | Example | URL pattern parsed |
|---|---|---|---|
| HackerOne | bare handle | `cloudflare` | `https://hackerone.com/<handle>` |
| Bugcrowd | `bc-<engagement-slug>` | `bc-t-mobile` | `https://bugcrowd.com/engagements/<engagement-slug>` |
| Intigriti | `int-<handle>` | `int-aikido` | `https://www.intigriti.com/programs/<company-handle>/<handle>/detail` |

The prefix is stripped only for the GitHub-org guess in `ownership-verifier` (the GH org is `t-mobile`, not `bc-t-mobile`). Everywhere else — ownership-cache filenames, submissions log, program JSON, candidate scan output paths — the prefixed slug is used verbatim.

When adding a new platform, register the prefix in `ownership-verifier.md` Step 1 (the prefix-strip list) and in this table.

## Output convention

All scan output goes under `/mnt/files/bb-agent/<program>/<scan-type>/<timestamp>/`.
Never write to `~/.bbot/scans/` (root partition is tight).

## Compliance hard rules (apply to ALL subagents)

1. **One non-destructive validation call per finding source.** Track in conversation state. Refuse second calls.
2. **No bucket file downloads.** ListBucket OK. GetObject NOT OK.
3. **No active mass scanning.** Programs that ban "massive automated scans" → restrict to passive modules only.
4. **Verify ownership BEFORE drafting report.** GitHub code search + Wayback + DNS chain. If `UNOWNED`, abort.
5. **0-day age gate.** Block CVE reports for vulns published <30 days ago unless program allows.

## Cloud pentest tooling (AWS-focused, added 2026-07-02)

Arsenal for **authenticated cloud-configuration pentests** (contracted engagements, credential-gated — NOT bug-bounty passive recon). This tier is authenticated by definition: it needs an in-scope AWS access-key/secret or an assumable role. Credentials live in an AWS CLI profile (see below), never in the repo or in chat.

| Tool | Full path | Version | Purpose |
|---|---|---|---|
| aws | `~/.local/bin/aws` | 1.37.2 | Identity (`sts get-caller-identity`), enumeration, data access, `iam simulate-principal-policy`. |
| prowler | `~/.local/bin/prowler` | **5.17.0 (pipx)** | ⭐ Configuration/posture audit — CIS/PCI/NIST/SOC2 checks (`prowler aws -p <profile>`). The core of "cloud-config" testing. NOTE: a shadowed pip 5.1.3 also exists; the pipx one wins on PATH — do not rely on the pip copy. |
| scout | `~/.local/bin/scout` | 5.14.0 (ScoutSuite, pipx) | Multi-cloud posture audit with a navigable HTML report (`scout aws --profile <profile>`). Visual complement to Prowler. |
| pacu | `~/.local/bin/pacu` | 1.6.0 | Offensive AWS framework: `iam__enum_permissions`, `iam__privesc_scan`, modular exploitation. Import keys with `import_keys`. |
| cloudfox | `/usr/bin/cloudfox` | Bishop Fox | "What can I do with these creds" — enumeration + attack-path surfacing (`cloudfox aws --profile <profile> all-checks`). |
| pmapper | `~/.local/bin/pmapper` | 1.1.5 (principalmapper, pipx) | IAM privilege-escalation **graph** — PassRole/AssumeRole chains Prowler can't see (`pmapper --profile <p> graph create` → `query`/`analysis`/`visualize`). ⚠️ **PATCHED for Python 3.12:** its `util/case_insensitive_dict.py` used `from collections import Mapping` (removed in py3.10) → changed to `from collections.abc import Mapping, MutableMapping`. **A `pipx reinstall`/`upgrade` of principalmapper WIPES this patch — re-apply it.** |
| cloudsplaining | `~/.local/bin/cloudsplaining` | 0.9.1 (pipx) | IAM policy least-privilege assessment (dangerous wildcards, privesc, resource-exposure). `cloudsplaining download --profile <p>` then `scan`. |
| s3scanner | `$GOPATH/bin/s3scanner` | dev | S3 bucket permission scanner (also used by bucket-hunter). |
| cloud_enum | `/usr/local/bin/cloud_enum` | system | Unauthenticated multi-cloud resource discovery (S3/GCS/Azure) — the external-recon entrypoint when no creds yet. |
| trufflehog | `$GOPATH/bin/trufflehog` | 3.95.2 | Leaked cloud creds in repos/filesystems (shared with secret-hunter). Also used in the cloud tier's secrets sweep against decoded EC2/EB user-data + Lambda env. |
| IAM Access Analyzer | `aws accessanalyzer` (CLI) | — | AWS-native, **authoritative** external/public-access findings (buckets/roles/keys shared outside the account/org). `list-analyzers` per region → `list-findings`. SecurityAudit-readable. **If NO account analyzer is enabled, that absence is itself a finding** (no continuous external-access monitoring). Non-redundant with Prowler/ScoutSuite — settles "is it really public/shared" without manual condition triage. |
| GuardDuty | `aws guardduty` (CLI) | — | Runtime threat-detection findings (the one non-config dimension). `list-detectors` per region → `get-findings` top-by-severity. SecurityAudit-readable; `get-detector` confirms the detector's status. |
| boto3 / policyuniverse | pip libs | 1.35.94 / 1.5.1 | Ad-hoc AWS scripting + IAM policy analysis primitives. Powers the FP-triage scripts (SG→live-instance correlation, SNS/S3 policy-condition classification, RDS PubliclyAccessible check).|

**Formalized cloud tier (2026-07-06):** the above is orchestrated by the **`cloud-auditor`** subagent via the **`/audit-cloud <slug> <profile>`** command (analogous to `/domain` → footprint-hunter). cloud-auditor runs the non-redundant set (Prowler + pmapper + cloudfox + credential report + Access Analyzer + GuardDuty; ScoutSuite/cloudsplaining kept for their HTML) and applies the mandatory false-positive triage from `feedback_cloud_scanner_fp_triage.md` before writing `out/<slug>/cloud/<ts>/FINDINGS.md`. Deliverable = `/informe <slug> tecnico` (Typst). **pacu** + **enumerate-iam** are installed but intentionally NOT wired in — pacu's value is write/exploitation (out of scope for the read-only role) and enumerate-iam is redundant when SecurityAudit lets us read policies directly.

**Credential handling (hard rules for this tier):**
- Store creds in an AWS CLI **named profile** (`~/.aws/credentials` under `[<engagement>]`), set up by the operator via `! aws configure --profile <engagement>` so secrets never transit the chat/transcript. Every tool takes `--profile <engagement>`.
- First call on any new creds is always `aws sts get-caller-identity` (read-only) to confirm the identity + account before anything else.
- Read-only/enumeration by default. Any write, privesc *execution*, persistence, or data exfil requires explicit per-action operator authorization (mirrors the pentest-playbook proof ceiling — confirm the path, don't detonate it). No snapshot-sharing to external accounts, no key minting, no policy edits without sign-off.
- Rotate/revoke the engagement keys when the engagement closes; delete the profile.
- Deliverable is a YOUR_ORG **Typst** report via Eje 3 (`/informe <slug> tecnico`), not loose markdown.

## Huella Digital mode (`/domain`, added 2026-05-27)

A second engagement mode for **client work-projects**, distinct from bug-bounty passive-recon. Triggered by `/domain <domain>`; synthesizes a `engagement_type:"huella_digital"` scope JSON, runs the four existing hunts PLUS `footprint-hunter`, then `huella-reporter` assembles a Spanish **YOUR_ORG "Informe de Huella Digital"** at `out/<slug>/reports/huella-digital-<ts>.md`. Authorization = bare-domain-is-go (the user supplying the domain is the authorization).

**Capability tiers (encoded as scope-rule flags, not hardcoded):**
- **Passive** (always): bbot passive presets, subfinder/amass/crt.sh, **waymore (`-mode U`, archive-derived hostnames → §DNS surface; optional, timeout-guarded)**, dnsx, gau, theHarvester (allowed providers only), DNSBL via dig, HIBP/breach lookup.
- **Light-active** (`light_active_allowed:true`, default ON for `/domain`): single httpx homepage probe per host + one web screenshot/host. These load only public homepages — distinct from the bug-bounty mode's passive-only constraint.
- **Social handle-enum** (`social_enum_allowed:true`, default ON for `/domain`): maigret brand-handle existence checks across ~300 third-party social/web platforms. This is the ONE tier that touches **third parties** (not client infra) — anonymous public-URL GETs only, no auth, no scraping. Distinct flag so an engagement can keep client-only by setting it `false` (then §Social falls back to footer-scrape of the client's own pages only).
- **Heavy-active** (`heavy_active_allowed:false`, OFF): no nuclei CVE/exploit, no fuzzing, no port sweeps.
- **Credential validation** (`credential_validation_allowed:false`, **HARD-OFF in this build**): leaked creds are LISTED only, `Estado=DESCONOCIDA`, NEVER login-tested. The reference report's "Válida/Inválida" column + login-PoC screenshots (Figuras 4–7) are deliberately NOT replicated. Validation requires separate written client authorization.

**Standing bans that still apply in this mode:**
- **LinkedIn automation is banned** (theHarvester `-b linkedin/linkedin_links/companies`, bbot LinkedIn scraping) — ToS / account-suspension. LinkedIn employee data enters via a **manual paste** the `/domain` command collects → `out/<slug>/footprint/linkedin-manual.json` → §1.4.3.
- **No bucket downloads, no auth bypass, no exploitation.**

**Breach source is pluggable.** Default HIBP (`/api/v3/breacheddomain/<apex>`, needs `HIBP_API_KEY` — returns breach names, no passwords). bbot `dehashed`/`credshed` modules can be wired via `~/.config/bbot/secrets.yml` to populate plaintext (still listed only, never validated). Unconfigured → breach section degrades to "no configurado".
