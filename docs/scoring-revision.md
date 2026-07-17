# Scoring Revision Plan

Goal: redo per-check severity assignment so the score reflects real impact,
and the SummaryBar counts match what the user sees on the page.

## Severity Levels

Each check gets one of four levels. They do **not** map 1:1 to status —
e.g. a `fail` on a low-impact check can still be level 1, and a `warn` on
a critical one can be level 3.

| Level | Meaning | Score weight |
|---|---|---|
| **0** | Informational only — surfaced as a note, not a warning | 0 (no score impact) |
| **1** | Minor — nice to have, narrow impact | low |
| **2** | Medium — meaningful security or operational risk | medium |
| **3** | Critical — real attack surface or user-facing security gap | high |

## Status × Severity → score points

For each check the score contribution is:

```
points_earned = statusToPoints(status) × level_weight
```

where `statusToPoints` is `pass=1`, `warn=0.5`, `fail=0`, `info=1` (neutral).
Level 0 checks always contribute 0.

---

## Security Headers (total weight: 15)

| Header | Level | Weight | Rationale |
|---|---|---|---|
| **Strict-Transport-Security** (HSTS) | 3 | 5 | Without HSTS the first hit to `http://` is interceptable (Wi-Fi MITM) before the 301 redirect lands. Baseline for any business site. |
| **Content-Security-Policy** (CSP) | 3 | 5 | Most powerful security header. Any XSS bug is instantly exploitable without it. |
| **X-Frame-Options** | 2 | 2 | Clickjacking protection. Deprecated in favor of `CSP: frame-ancestors` — when CSP has `frame-ancestors` set, the old header is redundant. *Cross-check pending: drop to level 1 when CSP covers it.* |
| **X-Content-Type-Options** | 1 | 1 | MIME-sniffing edge cases. Modern browsers default to strict behavior for critical types. |
| **Referrer-Policy** | 1 | 1 | Privacy (URL/query string leakage to third parties), not direct security. |
| **Permissions-Policy** | 0 | 1 | Niche — restricts native browser features. Real impact small for typical sites. Show as info, not warn. |
| **X-XSS-Protection** | 0 | 0 | Deprecated and harmful in old browsers — checker correctly warns when *present*. No score impact either way. |

### Open items
- [ ] CSP `frame-ancestors` cross-check → drop X-Frame-Options to level 1 when present
- [ ] Stronger CSP analysis (`unsafe-inline` / `unsafe-eval` should not be `pass`)
- [ ] Switch Permissions-Policy missing → `info` instead of `warn`

---

## DNS & Domain (total weight: 18)

Card aggregates 5 sub-checks. Card status = worst of internal statuses.

| Check | Level | Weight | Rationale |
|---|---|---|---|
| **DNSSEC** | 1 | 3 | HTTPS already covers the main MITM threats. DNSSEC adds protection for DNS responses themselves (matters for MX/email routing and legacy systems without ubiquitous HTTPS), but adoption is <10% even among top sites — Google, Facebook, Twitter do not use it. Nice-to-have, not a blocker. |
| **CAA** | 2 | 5 | Controls which CAs may issue certs for the domain. Biggest value is as a **cross-check with CT logs** — a cert from a CA not in the CAA list is a strong misissuance signal. With `iodef:mailto:...`, CAs can email alerts on issuance attempts. Real security control. |
| **NS** | 0 | 0 | Foundation: no NS → domain unresolvable → every other check fails anyway. **Validity check, not security**. Show as info in UI, no score impact. |
| **danglingDns** | 3 (NS) / 2 (MX) | 6 | Exploitable vulnerability. Dangling NS = attacker can register the abandoned nameserver domain and control your DNS. Dangling MX = email hijack. Checker already splits via status: NS→fail (0 points), MX→warn (0.5 × 6). Single weight. |
| **domainExpiry** | 2 | 4 | Operational risk: expired domain → attacker registers it → brand/email/identity loss. Not security per se (HTTPS doesn't help), but the impact looks like one. |
| **Total** |  | **18** | (was 19) |

### Open items
- [ ] **Revise expiry thresholds**: `<90d → info` (early nudge), `<30d → warn`, `<7d → fail`. Currently `<=60d → warn`, `<0d → fail`.
- [ ] CAA `iodef` parsing — surface as info if present (positive signal that owner monitors misissuance)
- [ ] DNSSEC chain-of-trust validation, not just DS presence (currently we only check DS records exist)

---

## Reputation (total weight: 17)

Card aggregates 3 sub-checks (Safe Browsing, URLhaus, DNSBL). Card status = worst.

| Check | Level | Weight | Rationale |
|---|---|---|---|
| **Google Safe Browsing** | 3 | 8 | **Direct user-facing impact**. Listing triggers the red "Deceptive site ahead" interstitial in Chrome/Firefox/Safari — ~70%+ of browser traffic effectively blocked. This is a live production-outage signal, not metadata. A `fail` here should noticeably drop the score. |
| **URLhaus** | 2 | 4 | abuse.ch's malware-hosting database. Doesn't block users directly, but a listing usually means the site is compromised (CMS/plugin) and now serves malware. Serious investigation trigger, not "site is down". |
| **Blacklist (DNSBL)** | 2 | 5 | Domain-based DNSBL (Spamhaus DBL, SURBL) → mail dropped by many receivers. IP-based is noisy for shared CDN edge IPs — UI already hides those, but the scoring path doesn't yet (see open items). |
| **Total** |  | **17** | (was 18) |

### Open items
- [ ] **Don't penalize IP-DNSBL when behind a CDN**. `checkBlacklist` currently sets `warn` if *any* provider is listed, including IP-DNSBL on a shared edge IP. When `infrastructure.cdnProvider != null`, only domain-based DNSBL hits should count toward the status.
- [ ] **No-mail downgrade for blacklist** (analog to SPF/DMARC): if the domain has no MX (or Null MX per RFC 7505), domain-based DNSBL is also irrelevant — surface as info, don't penalize.

---

## Email Security (total weight: 14)

Card aggregates 4 sub-checks. Big shift here — `mx` and `dkim` drop from 8 combined points to 0, because neither produces a reliable security signal on its own.

| Check | Level | Weight | Rationale |
|---|---|---|---|
| **SPF** | 2 | 7 | Foundation of anti-spoofing for any domain that accepts mail. Multi-sub-check scoring (validations[]) covers record presence, RFC 7208 lookup limit (≤10), and the catch-all qualifier (`-all`/`~all`/`?all`). No-mail downgrade: surface as info when MX missing or Null MX. |
| **DMARC** | 2 | 7 | Policy layer on top of SPF+DKIM. Tag-level scoring via validations[] already distinguishes `p=none` (warn) from `p=reject` (pass). After 2024 Gmail/Yahoo bulk-sender rules, DMARC is mandatory for any domain that sends >5000 emails/day. No-mail downgrade applies. |
| **DKIM** | 0 | 0 | **Not score-relevant**: the checker probes 14 popular selectors; `info` means "we didn't guess the selector", not "DKIM is missing". Penalizing would produce false negatives on any domain with a custom selector. Keep the UI display (found selectors + pubkeys) but no score impact. |
| **MX** | 0 | 0 | Presence fact, not a security signal. "Does the domain accept email?" is operational metadata. Missing MX already cascades into SPF/DMARC info-downgrade via the existing no-mail logic. |
| **Total** |  | **14** | (was 24) |

### Open items
- [ ] **Confirm DMARC `p=none` lands as warn** via the existing tag-level validations[] path.
- [ ] **Optional**: derive a soft DKIM expectation signal from DMARC's `adkim=s` tag (strict alignment ⇒ owner expects DKIM to be configured). Not a hard score input.

### Weight budget recalc

Headers + DNS + Reputation + Email = 15 + 18 + 17 + 14 = **64**.
Remaining budget: **36** points across SSL/TLS, CT logs, Redirects, security.txt, SEO.

---

## SSL/TLS (total weight: 18)

Big card — many sub-checks of very different severity. Aggregate-via-`status`
loses the granularity, so we score sub-checks individually inside the 18-point
budget and sum them up.

Sub-checks are derived at score time from existing `SslResult` fields
(`daysRemaining`, `chainStatus`, `ct.chromeStatus`, `ct.appleStatus`,
`edges.consistency`, `managedBy`) — no type changes required.

| Sub-check | Level | Weight | Rationale |
|---|---|---|---|
| **Expiry** | 3 / 2 / 0 | 6 | Derived from `daysRemaining` + `managedBy`. Expired or `≤7d` → 0 points (production-outage risk). `8–30d` self-managed → warn (0.5 × 6 = 3 points); same range when CDN-managed (Cloudflare/AWS/Meta etc.) → info (full points, owner has nothing to do). `31–90d` → info-level "early nudge" mirror of domain-expiry threshold. `>90d` → pass. |
| **Chain validity** | 3 | 5 | Derived from `chainStatus`. Mobile browsers in particular don't follow AIA Issuer hints — a broken chain breaks the site for a real chunk of users. |
| **Edges consistency** | 3 / 0 | 4 | Derived from `edges.consistency`. `inconsistent` (a sample fails sanMatch or chainOk) → fail (a real edge is serving an invalid cert). `rollout` → info (normal mid-rotation state, don't penalize). `consistent` / `unknown` → pass. |
| **CT compliance (Chrome)** | 2 | 2 | Derived from `ct.chromeStatus`. Insufficient SCTs from distinct operators → Chrome users see `NET::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED`. Real impact, but partial (Chrome only). |
| **CT compliance (Apple)** | 1 | 1 | Derived from `ct.appleStatus`. Apple's policy is stricter on paper but enforced less consistently in the wild. Most certs that pass Chrome also pass Apple. |
| **Total** |  | **18** | (was 15) |

### Scoring formula

```
sslPoints = sum(statusToPoints(subStatus_i) × subWeight_i)
            for i in {expiry, chain, edges, ctChrome, ctApple}
```

Same shape as `headers` already uses for `items[]`. Card-level status =
worst of sub-statuses (UI displays this).

### Open items
- [ ] Move expiry threshold of 30d → 7d for `fail`-grade (currently `<0d → fail`; the `<=7d` band as level 3 is new).
- [ ] Recompute sub-check statuses inside `scoreCalculator` (or surface them on `SslResult` for parity with `items[]`). Pick one and document it.
- [ ] When `managedBy != null` and the only issue is expiry: also drop the **card-level** status to info, not just the score impact, so the UI doesn't show a yellow warning for something the owner can't fix.

### Weight budget recalc

Headers + DNS + Reputation + Email + SSL = 15 + 18 + 17 + 14 + 18 = **82**.
Remaining: **18** points across CT logs, Redirects, security.txt, SEO.

---

## Certificate Transparency / CT logs (total weight: 8)

Currently **excluded** from scoring (see `scoreCalculator.ts` — `SEO and CT Logs are informational — excluded from scoring`). We're un-excluding CT logs: the **CAA-violation finding** is the single most valuable signal CT monitoring produces. No other check can flag "a CA issued a cert for your domain that you didn't authorize."

| Finding | Current severity | Notes |
|---|---|---|
| **CAA violation** (cert from CA not in CAA) | warn (single) / warn-or-info (multi-tenant SaaS) | Misissuance signal. CA bug, legacy cert, or attack. |
| **Unknown CA** (not in Mozilla trust list) | warn (single) / warn-or-info (multi-tenant) | Self-signed test, niche CA, or attacker. |
| **"Different CA than installed"** | info | Backup CA already authorized via CAA — informational only. |
| **Wildcards > 3** | warn | Often legit for SaaS. Too noisy. |
| **High cert count > 500** | warn | Normal for large orgs. Too noisy. |
| **Cert count 100–500** | info | Already informational. |

### Scoring

| Sub-aggregation | Level | Weight | Rationale |
|---|---|---|---|
| **CT logs card overall** | 2 | 8 | One weight, card-status drives the score (worst of findings). Level 2 not 3 because too many false positives at level 3 (multi-tenant SaaS, parent CAA not covering tenant subs). Real misissuance attempts caught here, but signal-to-noise warrants caution. |
| **Total** |  | **8** | (was 0 — excluded) |

### Open items
- [ ] **Wildcards > 3** → downgrade to `info` (legit SaaS pattern, not security signal)
- [ ] **High cert count > 500** → downgrade to `info` (normal for large orgs)
- [ ] **CAA violation for single-tenant** → bump to `fail` instead of `warn` (real exploitable misissuance signal; multi-tenant logic already handles SaaS noise via `info` path)
- [ ] Remove `ctLogs` from the "informational / excluded" comment in `scoreCalculator.ts`; add to WEIGHTS

---

## Redirects (total weight: 5)

| Sub-check | Level | Weight | Rationale |
|---|---|---|---|
| **HTTP → HTTPS redirect** | 3 | 4 | Fundamental web baseline. Without it, a user who types `http://example.com` may have traffic intercepted on hostile networks before HSTS kicks in. `fail` (200 on HTTP, no redirect) is real attack surface. |
| **www consistency** | 0 | 1 | SEO concern (duplicate content for search engines), not security. Currently emits `warn` — should be downgraded to `info` in the checker. Small weight kept as a soft nudge. |
| **Total** |  | **5** | (was 6) |

### Open items
- [ ] `www consistency` `warn` → `info` in [redirectChecker.ts:64](server/checkers/redirectChecker.ts#L64) — "both serve content" is SEO advice, not security.

---

## security.txt (total weight: 3, custom scoring)

RFC 9116 file telling security researchers how to disclose vulnerabilities — **a disclosure channel, not a defensive control**. Missing doesn't make the site vulnerable; it just signals maturity gap.

**Reward presence**: having a security.txt file at all (even with validation issues) is meaningfully better than nothing — researchers can still extract a Contact line manually. So a partially-broken file should earn more than no file at all.

### Custom scoring (not the standard `statusToPoints × weight`)

| State | Points | When |
|---|---|---|
| **File absent** | 0 | `available === false` — researchers have no defined channel |
| **File present, has warnings/errors** | 2 | `available === true && status !== 'pass'` — credit for the disclosure channel even if syntax isn't perfect |
| **File present, fully valid** | 3 | `available === true && status === 'pass'` — full credit |
| **Total** | **3** | |

This means the gradient is **0 → 2 → 3**, not `0 → 1.5 → 3`. Bigger jump for showing up at all, smaller jump for being perfect.

### Implementation note

`scoreCalculator.ts` already has custom-path branches (for `headers`, `spf`, `dmarc`, `redirects`). Add another for `securityTxt` that returns:
```
result.available === false        → 0
result.available && status==='pass' → 3
result.available                  → 2
```

---

## SEO — remove entirely

SEO is not security, has never contributed to the score, and the card adds noise to the report. Drop it everywhere:

- [ ] Delete `server/checkers/seoChecker.ts`
- [ ] Delete `src/components/SeoCard.svelte`
- [ ] Drop `SeoResult`, `SeoCheckItem` from `server/types.ts` and `src/lib/types.ts`
- [ ] Drop `seo` from `ScanChecks`, `DEFAULT_SCAN_CONFIG.checks`, and `DomainCheckResponse`
- [ ] Drop `seo` from `server/lib/scanPipeline.ts` (wave 1)
- [ ] Drop `seo` from `ScanSection` in `src/lib/scanStream.ts`
- [ ] Drop `seo` handling from `DomainCheckerPage.svelte` (`applySection`, `SECTION_TO_GROUP`, render)
- [ ] Drop `renderSeoCard` and the `if (data.seo)` block in `server/lib/reportRenderer.ts`
- [ ] Drop `seo` from `server/routes/domainCheck.ts` (`/http` endpoint, `/full` endpoint, finalize flat-keys, etc.)
- [ ] Drop seo-related remediations from `server/remediations.ts`
- [ ] Drop seo entries from `server/scoreCalculator.ts` informational-list comment

---

## Final weight budget

Headers 15 + DNS 18 + Reputation 17 + Email 14 + SSL 18 + CT 8 + Redirects 5 + security.txt 3 = **98**.

The remaining 2 points are intentional headroom — a perfect 100/100 should require all 8 cards green, including the optional ones (security.txt, CAA). Keep the score "achievable but not free."

---

## Implementation order

1. ✅ This doc — severity tables for all categories
2. Update `server/scoreCalculator.ts` weights to match (replace WEIGHTS dict, add CT logs sub-check derivation for SSL, add CT to scoring path)
3. Tweak checkers per open items (Permissions-Policy → info, www-consistency → info, CT log wildcard/cert-count → info, single-tenant CAA → fail)
4. SEO removal sweep (file deletes + type cleanup + routes/pipeline/UI)
5. Update `src/components/DomainCheckerPage.svelte` SummaryBar to count per-card (so counts match visible UI)
6. Mirror in `server/lib/reportRenderer.ts:renderSummaryBar`
7. Smoke test on representative domains: cloudflare.com (managed CDN), facebook.com (Meta), self-hosted single-server site, no-mail domain
- [ ] Email Security (SPF, DMARC, DKIM, MX)
- [ ] security.txt
- [ ] SSL/TLS (chain validity, expiry, CT compliance, edges consistency, managedBy)
- [ ] Certificate Transparency (CT logs)
- [ ] Redirects
- [ ] SEO (informational — likely level 0)

## Implementation order

1. Land severity table for all categories (this doc finished)
2. Update `server/scoreCalculator.ts` weights to match
3. Update `server/checkers/headersAnalyzer.ts` to emit `info` instead of `warn`
   where the new severity says it shouldn't penalize
4. Update `src/components/DomainCheckerPage.svelte` SummaryBar to count
   **per card** (worst of internal checks), so counts match the visible UI
5. Mirror in `server/lib/reportRenderer.ts:renderSummaryBar`
