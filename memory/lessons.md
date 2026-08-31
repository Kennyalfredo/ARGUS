# bb-agent lessons journal

Distilled methodology lessons from past engagements. Company names, domains, and report IDs have been removed. The structured rules that enforce these lessons live in `memory/rules.json`.

---

## Ownership & attribution

- **Bucket name derivation ≠ ownership.** S3 bucket names are globally unique first-come-first-served. A bucket named after an in-scope host stem, referenced in a third-party repo, or containing brand-plausible content can still be a squatter. Ownership requires POSITIVE proof: verified CNAME chain, first-party repo reference, explicit scope listing, or uniquely-proprietary content. A triager closed a report with "I see no evidence [the program] owns this bucket" — the first ground-truth rule reversal.

- **Content overrides domain signals.** A bucket verified-listable with three domain-based "owned" signals (wildcard-stem DNS, in-scope derivation, 2-of-3 aggregation) held 55K objects of completely unrelated foreign-language content. Content inspection was the only check that exposed the squatter. Domain ownership ≠ bucket ownership.

- **s3scanner ACL flags are unreliable.** Across 25+ consecutive engagements, every s3scanner `all_users_read=ALLOWED` flag returned AccessDenied on `aws s3api list-objects-v2 --no-sign-request` recheck. The ACL recheck gate is permanent infrastructure.

- **Squatter first-key signals.** A listable bucket whose first object key is `.aws/config`, `.aws/credentials`, `id_rsa`, etc. is a squatter. Legitimate corporate infrastructure never stores AWS credentials at the root of a brand-named bucket.

- **Vendor repo credentials.** Tokens in a vendor's public repo often belong to the vendor's clients. Always verify the credential owner via deploy context, not the repo owner. Four distinct naming patterns confirmed: `integrate_{brand}_with_*`, `authenticate-with-{brand}`, personal trading bots, and bootcamp training repos.

## Secret hunting

- **trufflehog Verified=true ≠ impact.** Verified proves the issuer accepts the credential — not that it has security impact. Test-fixture, history-only, and old-in-popular-repo credentials are routinely orphaned service accounts with no access to program data. A triager confirmed: "the credential has no impact — the account was associated with a former employee."

- **Blockchain RPC keys are low-value by default.** Alchemy/Infura/QuickNode keys are frequently public-by-design (browser dApp project IDs), free-tier, or test fixtures. Even verified-live ones were program-assessed as "just for testing services." Default informational, cap at low, never auto-draft High.

- **No speculative impact inflation.** Strip "MAY also be available" / "could potentially" / "request interception" claims. Describe only observed capability. Triagers read speculative escalation as inflation and it biases the whole report down.

- **Employee dotfiles → infra disclosure.** When an employee's GitHub account is confirmed (company field match), check dotfiles repos for VPN configs, RDP targets, internal hostnames, corp email, and RFC1918 IPs.

- **In-scope source_code repos deserve priority scan slots.** Don't let dork-selected third-party repos consume the clone budget before program-declared repos get deep-scanned.

- **Oversized repos need shallow-clone fallback.** Repos exceeding the size cap with critical/high severity should get `--depth=1 --filter=blob:limit=10m` rather than zero coverage.

- **SCOPE_QUESTION routing.** Verified secrets in a program's GitHub org but outside named in-scope repos need human triage, not silent drop. The org-but-not-named boundary is a policy question.

- **Brand-stem code search can be degenerate.** Some brand names collide with popular SDKs or common English words, making bare-stem dork queries useless. Use domain-qualified queries instead.

- **Short brand stems get dropped.** 4-char stems hit the length-min filter. Override explicitly when the short stem IS the brand.

- **GitHub org ≠ GitHub user.** A famous company name on GitHub can be a User account (0 repos), not an Org. Cache the real org name to avoid repeat discovery round-trips.

- **gh_org_supplement catches wrong-org cases.** When Pass A resolves a small org (< 10 repos), probe stem+suffix variants (inc, labs, software, corp) to find the real engineering org.

## Subdomain takeovers

- **subzy fingerprints produce false positives on generic 404s.** Cargo Collective fingerprint fires on any bare nginx/Apache 404 regardless of hosting platform — confirmed across email delivery, ELB, PaaS, and CDN endpoints. Body recheck is mandatory: the live response body MUST contain the actual fingerprint string.

- **CNAME hub-skip eliminates structural noise.** CDN and email service CNAMEs (Cloudflare, CloudFront, Akamai, email delivery providers, enterprise SaaS) are always-live infrastructure, not takeover candidates. Hub-skip rules cut subzy input by 50-90% on typical engagements.

- **Sender-auth CNAMEs are not user-claimable.** Email delivery service sender-authentication CNAMEs are account-bound (API key + domain ownership verification). Even with a "dangling" DNS record, no exploitable takeover scenario exists.

- **Some platforms require demonstrated takeover, not detection.** One managed-program platform closed a detection-only report as "theoretical." Policy requires the researcher to claim the dangling service and serve a proof page. Detection-only findings should be held as leads on these platforms.

- **DNS hostname ≠ application identity.** A subdomain named after a software product may not actually run that software. Fingerprint the actual service before pivoting to CVE lookups.

## Endpoint hunting

- **Archive-derived leads have a hard confidence ceiling.** Wayback/CommonCrawl pattern matches suggest historical exposure but the application may have changed. All archive-only leads need live confirmation. Three high-confidence archive leads all cleared on live GET.

- **Long-exposure signals predict duplicates.** A service publicly reachable and archive-indexed for 3+ years on a prominent domain has near-certain prior-report probability. Annotate the duplicate risk (soft signal) but still draft if the finding is valid.

## Reporting & process

- **No local filesystem paths in reports.** Never include `memory/`, `out/`, `/home/`, `ownership-cache/` paths in submitted reports. They leak researcher tooling internals and give competing researchers operational intel.

- **Synthesized scope caps are placeholders, not ceilings.** For directed/owner-authorized engagements with synthesized scope, rate findings by actual impact. The conservative default cap should not mechanically suppress a genuine High.

- **CVE patch-date reasoning.** When the CVE fix release date is known and the app build date is later, the build is likely patched. Build recency does NOT imply unpatched — it implies the opposite.

- **Platform dispositions must feed the learning loop.** Self-judged medium-confidence rules accumulate bias. Triager verdicts (ground truth) are the only signal that reaches high confidence. The three early rejections all shared the same failure shape: a positive-looking signal treated as the finding itself.

- **The discriminator between valid and rejected findings:** real ownership + impact argued from evidence. Not a verification signal treated as the finding.

## Program scouting & policy

- **Explicit scanner bans need automated detection.** Some programs categorically ban automated scanners in policy text. The parser should detect and set the flag at ingestion — don't rely on operator review.

- **Rate limit caps from policy text.** Extract machine-readable rate caps (e.g., "max 5 requests/sec") at ingestion time so all agents enforce automatically.

- **All-unknown severity caps silently downgrade.** One platform's data dump doesn't carry per-target severity caps; all default to unknown, which silently caps every finding at medium.

## Structural patterns

- **Clean-negative engagements cluster.** Polished mega-orgs with mature security programs reliably return clean across all hunters. The pipeline's value concentrates on younger/smaller programs and contracted work where the attack surface is less hardened.

- **On-prem programs have near-zero cloud-bucket yield.** Programs with no cloud-provider DNS signals, operating on private IP ranges with on-prem naming conventions, are predictable clean-negatives for bucket hunting.

- **Coverage ≠ clean.** When WAF/CDN/rate-limiting blocks scanning, the honest posture is "blocked — not tested" rather than "clean." Distinguish genuine clean-negatives from coverage gaps.
