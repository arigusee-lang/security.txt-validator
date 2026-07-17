import type { CheckStatus, CtLogEntry, CtLogsResult, CtFinding, CtDataSource, CtSourcePref, CtCheckOptions, CaaRecord } from "../types.js";
import { cacheGetMaybeStale, cacheSet } from "../lib/cache.js";
import { ssrfSafeTlsConnect } from "../lib/ipCheck.js";
import { fetchFromCrtShPg } from "./crtShPg.js";
import { parseIssuerO, pickBestName, finalizeCerts } from "./ctNormalize.js";
import { createLogger } from "../lib/logger.js";
import { incr } from "../lib/metrics.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const log = createLogger("ct");

export type { CtLogEntry, CtLogsResult, CtFinding, CtDataSource };

// Fresh window (24h) — within this we serve cached CT data silently.
const CT_LONG_TTL = 24 * 60 * 60 * 1000;
// Stale grace window (7 days) — past freshness but still returned on upstream
// failure with `stale: true`. crt.sh routinely 502s/times-out and CertSpotter
// rate-limits; this keeps the check producing data instead of a hard fail.
const CT_STALE_TTL = 7 * 24 * 60 * 60 * 1000;

interface CtCacheEntry {
  certs: CtLogEntry[];
  totalCerts: number;
  cachedAt: string;
  source: CtDataSource;
}

// Built-in fallback CA list
const BUILTIN_CAS = [
  "Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign", "GoDaddy",
  "Amazon", "Google Trust Services", "Microsoft", "Cloudflare", "ZeroSSL",
];

/**
 * CAA-domain → known CT-log issuer names. CAA records use the CA's own
 * "issuer domain name" (RFC 8659), CT logs use friendly issuer names — they
 * almost never share enough substring to match by normalisation alone
 * (e.g. "letsencrypt.org" vs "Let's Encrypt"; "pki.goog" vs "Google Trust
 * Services"). This mapping covers the top-15 public CAs (~99% of web TLS
 * issuance). For unknown CAA values we fall back to substring matching on
 * normalised names — which works for many regional/corporate CAs where the
 * domain name and brand share tokens.
 */
const CAA_DOMAIN_TO_CA_NAMES: Record<string, string[]> = {
  "letsencrypt.org":   ["Let's Encrypt", "Lets Encrypt"],
  "pki.goog":          ["Google Trust Services", "GTS"],
  "digicert.com":      ["DigiCert", "GeoTrust", "Thawte", "RapidSSL", "QuoVadis", "Cybertrust", "Symantec"],
  "sectigo.com":       ["Sectigo", "Comodo", "PositiveSSL", "ZeroSSL"],
  "globalsign.com":    ["GlobalSign"],
  "amazon.com":        ["Amazon", "Amazon Trust Services", "AWS"],
  "amazontrust.com":   ["Amazon", "Amazon Trust Services"],
  "godaddy.com":       ["GoDaddy", "Go Daddy", "Starfield"],
  "starfieldtech.com": ["Starfield", "GoDaddy"],
  "entrust.net":       ["Entrust"],
  "identrust.com":     ["IdenTrust"],
  "buypass.com":       ["Buypass"],
  "buypass.no":        ["Buypass"],
  "apple.com":         ["Apple Public CA", "Apple"],
  "microsoft.com":     ["Microsoft"],
  "certum.pl":         ["Certum", "Asseco"],
  "twca.com.tw":       ["TWCA", "TAIWAN-CA"],
  "trustwave.com":     ["Trustwave"],
  "ssl.com":           ["SSL.com", "SSL Corporation"],
};

/**
 * RFC 8659 CAA values can carry parameters: `issue "letsencrypt.org;account=12345"`.
 * We only care about the issuer-domain part. Returns lowercased, trimmed.
 */
function parseCaaIssuerDomain(rawValue: string): string {
  return rawValue.split(";")[0].trim().toLowerCase();
}

/**
 * Decide whether `certIssuer` (CT-log friendly name) is authorised by `caaRawValue`
 * (CAA record value). Uses the hard-coded mapping for top-15 public CAs and
 * falls back to normalised substring matching for the long tail.
 */
function caaIssuerMatches(certIssuer: string, caaRawValue: string): boolean {
  const caaDomain = parseCaaIssuerDomain(caaRawValue);
  if (!caaDomain) return false; // `0 issue ";"` explicitly forbids issuance — no match for any issuer

  const normIssuer = normalizeCAName(certIssuer);
  const knownNames = CAA_DOMAIN_TO_CA_NAMES[caaDomain];
  if (knownNames) {
    return knownNames.some(n => {
      const normN = normalizeCAName(n);
      return normIssuer === normN || normIssuer.includes(normN) || normN.includes(normIssuer);
    });
  }

  // Fallback: normalised substring match against the CAA domain itself.
  // Helps regional CAs where the domain and brand share tokens (e.g. e-tugra.com.tr ↔ E-Tugra).
  const normCaa = normalizeCAName(caaDomain);
  return normIssuer.includes(normCaa) || normCaa.includes(normIssuer);
}

// Mozilla CA list - loaded eagerly at module import
const MOZILLA_CAS: string[] = (() => {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const raw = readFileSync(join(__dirname, "..", "data", "mozilla-trusted-cas.json"), "utf8");
    const cas = JSON.parse(raw) as string[];
    log.info({ count: cas.length }, "Mozilla CA list loaded");
    return cas;
  } catch {
    log.warn("Mozilla CA list not found, using built-in fallback");
    return BUILTIN_CAS;
  }
})();

// Surface CertSpotter API key state at startup so misconfigured envs are visible.
// CertSpotter free tier is id-ascending and capped — without a key we can't
// reach recent certs for high-volume domains.
{
  const k = process.env.CERTSPOTTER_API_KEY;
  if (k && k.length > 0) {
    log.info({ keyLength: k.length }, "CertSpotter API key present — full pagination enabled");
  } else {
    log.warn("CertSpotter API key not set — falling back to crt.sh first (set CERTSPOTTER_API_KEY for richer/recent CT data)");
  }
}

export function loadMozillaCAs(): string[] {
  return MOZILLA_CAS;
}

export function normalizeCAName(name: string): string {
  return name
    .toLowerCase()
    .replace(/\b(inc|llc|ltd|co|corp|gmbh|s\.?a\.?|authority|root|intermediate|certification|certificate|services|trust)\b/gi, "")
    .replace(/[.,]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function isKnownCA(issuerName: string): boolean {
  const norm = normalizeCAName(issuerName);
  return MOZILLA_CAS.some(
    (ca) => norm.includes(normalizeCAName(ca)) || normalizeCAName(ca).includes(norm),
  );
}

async function fetchWithRetry<T>(fn: () => Promise<T>, retries: number, delays: number[]): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err: any) {
      lastError = err;
      // Don't retry timeouts. A timeout means the upstream is overloaded (crt.sh's
      // public Postgres is slow for mega-domains under load) — an immediate retry
      // just burns another full timeout before we fall back. Retry only transient
      // errors (connection resets, etc.); fail fast on timeout so the fallback
      // source kicks in quickly.
      const msg = String(err?.message ?? err);
      if (err?.name === "AbortError" || /timeout/i.test(msg)) break;
      if (attempt < retries) await new Promise((r) => setTimeout(r, delays[attempt] ?? 1000));
    }
  }
  throw lastError;
}

/**
 * Fallback TLS handshake to learn the installed cert issuer when /web has not
 * yet populated the shared webfetch cache by the time /external runs.
 *
 * Without this, the "cert from different CA than installed" detection silently
 * skips when there's a race between /web and /external — and that race is
 * common because CT fetching is slow and starts in parallel with /web.
 *
 * TODO: replace with Redis pub/sub or a request-scoped barrier so /external
 * can subscribe to the SSL issuer published by /web instead of duplicating the
 * TLS handshake here.
 */
async function fetchSslIssuer(domain: string, timeoutMs = 5000): Promise<string | null> {
  try {
    const socket = await ssrfSafeTlsConnect({
      host: domain,
      port: 443,
      servername: domain,
      timeout: timeoutMs,
      rejectUnauthorized: false,
    });
    const cert = socket.getPeerCertificate(false);
    socket.destroy();
    if (!cert) return null;
    const issuer = String(cert.issuer?.O || cert.issuer?.CN || "").trim();
    return issuer || null;
  } catch {
    return null;
  }
}

type FetchResult = { certs: CtLogEntry[]; total: number; lastId?: string | null; source: CtDataSource };

/**
 * Default order the CT sources are tried in. The crt.sh Postgres mirror is the
 * primary (fast, 200ms–2s, full archive); CertSpotter is the fallback (recent
 * window, paginated with a key). When the admin picks a preferred source it's
 * moved to the front and the other stays as fallback.
 *
 * The crt.sh HTTP frontend was dropped: it's strictly worse than the PG mirror
 * (same dataset, but slow and routinely 502s) with no compensating upside.
 */
const DEFAULT_CT_ORDER: CtSourcePref[] = ["crt.sh-pg", "certspotter"];

/**
 * Short, cache-key-safe tag for a preferred CT source. Different source
 * selections must not share a cache entry (they can return different data),
 * so callers include this in the CT cache key. Undefined → "def" (default chain).
 */
export function ctSourceTag(src?: CtSourcePref): string {
  switch (src) {
    case "crt.sh-pg": return "pg";
    case "certspotter": return "cs";
    default: return "def";
  }
}

/** Build the fetchers for each source, all normalised to {certs,total,lastId?,source}. */
function ctFetchers(
  domain: string,
  authenticated: boolean,
  startAfterId: string | undefined,
): Record<CtSourcePref, () => Promise<FetchResult>> {
  return {
    certspotter: async () => {
      const r = await fetchAllFromCertSpotter(domain, authenticated, startAfterId);
      return { certs: r.certs, total: r.total, lastId: r.lastId, source: "certspotter" };
    },
    "crt.sh-pg": async () => {
      const r = await fetchFromCrtShPg(domain, authenticated);
      return { certs: r.certs, total: r.total, source: "crt.sh-pg" };
    },
  };
}

async function fetchAllFromCertSpotter(domain: string, authenticated: boolean, startAfterId?: string): Promise<{ certs: CtLogEntry[]; total: number; lastId: string | null }> {
  const apiKey = process.env.CERTSPOTTER_API_KEY || "";
  const headers: Record<string, string> = { "User-Agent": "dn-sec/1.0", Accept: "application/json" };
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
  const subdomains = authenticated ? "true" : "false";
  // Collect raw rows only; the shared finalizeCerts dedups + sorts + caps so all
  // sources are processed identically.
  const allCerts: CtLogEntry[] = [];
  let after = startAfterId || ""; let pages = 0; let lastId: string | null = null;
  while (pages < 50) {
    const c = new AbortController(); const t = setTimeout(() => c.abort(), 15000);
    try {
      const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=${subdomains}&expand=dns_names&expand=issuer${after ? "&after=" + after : ""}`;
      const res = await fetch(url, { signal: c.signal, headers });
      if (!res.ok) {
        log.warn({ upstream: "certspotter", status: res.status, domain }, "upstream returned non-2xx");
        if (res.status === 429) throw new Error("CertSpotter rate limited (429)");
        throw new Error(`CertSpotter HTTP ${res.status}`);
      }
      const data: any[] = await res.json();
      if (!Array.isArray(data) || data.length === 0) break;
      for (const e of data) {
        const bestName = pickBestName(e.dns_names, domain);
        // Prefer friendly_name, then organization, then parse DN out of `name` —
        // any of these can be missing depending on the cert / API tier.
        const issuer = e.issuer?.friendly_name || e.issuer?.organization || parseIssuerO(e.issuer?.name) || "Unknown";
        allCerts.push({ id: String(e.id || ""), issuerName: issuer, commonName: bestName, notBefore: e.not_before || "", notAfter: e.not_after || "" });
      }
      lastId = String(data[data.length - 1].id);
      after = lastId; pages++;
      if (data.length < 100 || !apiKey) break;
    } catch (err) {
      if (pages > 0) { log.warn({ page: pages + 1, err: (err as any)?.message || err, collected: allCerts.length }, "CertSpotter pagination error, using certs collected so far"); break; }
      throw err;
    } finally { clearTimeout(t); }
  }
  return { certs: allCerts, total: allCerts.length, lastId };
}

/**
 * Multi-tenant heuristic: when ≥5 violations are all on multi-level
 * sub-tenant subdomains (≥2 levels deeper than the scanned domain),
 * the violations are likely tenant-owned subdomains with their own CAA.
 * Per RFC 8659 §3.1, parent CAA does not apply if a closer ancestor
 * publishes its own — this is the SaaS multi-tenant pattern.
 */
function isMultiTenantPattern(subdomains: string[], scanDomain: string): boolean {
  if (subdomains.length < 5) return false;
  const baseDepth = scanDomain.split(".").length;
  return subdomains.every(s => {
    if (s === scanDomain || !s.endsWith("." + scanDomain)) return false;
    return s.split(".").length >= baseDepth + 2;
  });
}

export function analyzeFindings(certs: CtLogEntry[], totalCerts: number, domain: string, opts?: { sslIssuer?: string | null; caaRecords?: CaaRecord[] }): CtFinding[] {
  const f: CtFinding[] = [];
  const caaIssuers = (opts?.caaRecords || []).filter(r => r.tag === "issue" || r.tag === "issuewild").map(r => r.value);
  const hasCaa = caaIssuers.length > 0;

  // Collect violations grouped by issuer rather than emitting per-cert findings.
  // For multi-tenant SaaS (e.g. okta.com) a single CA can produce 50+ certs that
  // are all the same finding — collapse them into one entry.
  const caaViolations = new Map<string, string[]>();   // issuer → CN list
  const unknownCaCerts = new Map<string, string[]>();  // issuer → CN list

  for (const cert of certs) {
    if (cert.issuerName === "Unknown") continue;
    if (hasCaa) {
      const allowed = caaIssuers.some(caa => caaIssuerMatches(cert.issuerName, caa));
      if (!allowed) {
        const list = caaViolations.get(cert.issuerName) ?? [];
        list.push(cert.commonName);
        caaViolations.set(cert.issuerName, list);
      }
    } else if (!isKnownCA(cert.issuerName)) {
      const list = unknownCaCerts.get(cert.issuerName) ?? [];
      list.push(cert.commonName);
      unknownCaCerts.set(cert.issuerName, list);
    }
  }

  for (const [issuer, subdomains] of caaViolations) {
    if (subdomains.length === 1) {
      // Single-tenant CAA violation → real misissuance signal; bump from warn
      // to fail so the score reflects the severity. Multi-tenant SaaS noise is
      // handled in the else-branch below (warn or info via multiTenant check).
      f.push({
        severity: "fail",
        title: `Cert issued by CA not in CAA: ${issuer}`,
        description: `Certificate for "${subdomains[0]}" issued by "${issuer}" which is not authorized in CAA records. This is a strong misissuance signal — investigate immediately.`,
        subdomain: subdomains[0],
      });
    } else {
      const multiTenant = isMultiTenantPattern(subdomains, domain);
      const sample = subdomains.slice(0, 3).join(", ") + (subdomains.length > 3 ? `, +${subdomains.length - 3} more` : "");
      f.push({
        severity: multiTenant ? "info" : "warn",
        title: `${subdomains.length} certs from CA not in parent CAA: ${issuer}`,
        description: multiTenant
          ? `${subdomains.length} certificates from "${issuer}" on multi-level sub-tenant subdomains (${sample}). Per RFC 8659 §3.1, parent-domain CAA does not apply when a subdomain publishes its own — likely tenant-owned, common SaaS pattern.`
          : `${subdomains.length} certificates from "${issuer}" not authorized by parent CAA records (${sample}).`,
        subdomain: subdomains[0],
      });
    }
  }

  for (const [issuer, subdomains] of unknownCaCerts) {
    if (subdomains.length === 1) {
      f.push({
        severity: "warn",
        title: `Unknown CA: ${issuer}`,
        description: `Certificate for "${subdomains[0]}" issued by "${issuer}" - not in Mozilla Trusted CA list.`,
        subdomain: subdomains[0],
      });
    } else {
      const multiTenant = isMultiTenantPattern(subdomains, domain);
      const sample = subdomains.slice(0, 3).join(", ") + (subdomains.length > 3 ? `, +${subdomains.length - 3} more` : "");
      f.push({
        severity: multiTenant ? "info" : "warn",
        title: `${subdomains.length} certs from unknown CA: ${issuer}`,
        description: multiTenant
          ? `${subdomains.length} certificates from "${issuer}" on multi-level sub-tenant subdomains (${sample}). Likely tenant-owned subdomains using a non-public-trust CA.`
          : `${subdomains.length} certificates from "${issuer}" — not in Mozilla Trusted CA list (${sample}).`,
        subdomain: subdomains[0],
      });
    }
  }

  // "Different CA than installed" detection is only meaningful when the domain
  // publishes CAA records — otherwise any CA may legitimately issue certs and
  // multi-CA setups (Cloudflare Universal SSL, AWS, etc.) produce constant
  // false positives. With CAA, certs *not* in the allowed list are already
  // flagged above via caaViolations; here we only surface backup-CA usage
  // among the *allowed* set as info, since that's just legitimate redundancy.
  if (opts?.sslIssuer && hasCaa) {
    const normalizedSsl = normalizeCAName(opts.sslIssuer);
    const now = Date.now();
    const RECENT_THRESHOLD_MS = 60 * 86400_000;

    // Only consider certs whose issuer is allowed by CAA — others are already
    // flagged as a CAA violation; piling on a "different from installed"
    // finding for the same cert would be duplicative.
    const foreignByIssuer = new Map<string, CtLogEntry[]>();
    for (const cert of certs) {
      if (cert.commonName !== domain && cert.commonName !== `*.${domain}`) continue;
      const normalizedCt = normalizeCAName(cert.issuerName);
      if (normalizedCt === normalizedSsl || normalizedCt.includes(normalizedSsl) || normalizedSsl.includes(normalizedCt)) continue;
      const isAllowedByCaa = caaIssuers.some(caa => caaIssuerMatches(cert.issuerName, caa));
      if (!isAllowedByCaa) continue;
      const list = foreignByIssuer.get(cert.issuerName) ?? [];
      list.push(cert);
      foreignByIssuer.set(cert.issuerName, list);
    }

    for (const [issuer, list] of foreignByIssuer) {
      const valid = list.filter(c => {
        const t = new Date(c.notAfter).getTime();
        return Number.isFinite(t) && t > now;
      });
      const recent = valid.filter(c => {
        const t = new Date(c.notBefore).getTime();
        return Number.isFinite(t) && (now - t) <= RECENT_THRESHOLD_MS;
      });

      // Allowed-by-CAA backup CAs aren't a security concern — surface as info,
      // never warn. Caller can still cross-check if rotation looks unexpected.
      let suffix: string;
      if (valid.length === 0) {
        suffix = "all expired — historical CA, no longer in use";
      } else if (recent.length > 0) {
        suffix = recent.length === valid.length
          ? "active backup or alternate CA"
          : `${recent.length} of ${valid.length} recently issued — active backup or alternate CA`;
      } else {
        suffix = "valid but older — possibly previous CA from rotation";
      }

      const datesSorted = [...list].map(c => c.notBefore).filter(Boolean).sort();
      const earliest = datesSorted[0]?.slice(0, 10);
      const latest = datesSorted[datesSorted.length - 1]?.slice(0, 10);
      const dateRange = earliest && latest && earliest !== latest ? ` (${earliest} — ${latest})` : earliest ? ` (${earliest})` : "";

      if (list.length === 1) {
        f.push({
          severity: "info",
          title: `Additional authorized CA in use: ${issuer}`,
          description: `CT log shows cert for "${list[0].commonName}" from "${issuer}" (allowed by CAA); installed cert is from "${opts.sslIssuer}" — ${suffix}.`,
          subdomain: list[0].commonName,
        });
      } else {
        f.push({
          severity: "info",
          title: `${list.length} certs from additional authorized CA: ${issuer}`,
          description: `${list.length} certs in CT for "${domain}"${dateRange} from "${issuer}" (allowed by CAA); installed cert is from "${opts.sslIssuer}" — ${suffix}.`,
          subdomain: list[0].commonName,
        });
      }
    }
  }
  // Wildcards and cert volume are operational metrics, not security signals —
  // many wildcards are a legit SaaS pattern, and high cert counts are normal
  // for large orgs. Surface as info only; don't penalize the score.
  const wc = new Set<string>(); for (const c of certs) if (c.commonName.startsWith("*.")) wc.add(c.commonName);
  if (wc.size > 0) f.push({ severity: "info", title: `${wc.size} wildcard cert${wc.size > 1 ? "s" : ""} found`, description: wc.size > 3 ? `${wc.size} unique wildcard certs — check that they're all expected.` : `Wildcards: ${[...wc].join(", ")}`, subdomain: [...wc][0] });
  if (totalCerts > 500) f.push({ severity: "info", title: `High cert count: ${totalCerts}`, description: "Above 500 certs — normal for large orgs / SaaS; verify all are legitimate." });
  else if (totalCerts > 100) f.push({ severity: "info", title: `${totalCerts} certs in CT logs`, description: "Above average but may be normal for large orgs." });
  return f;
}

export function computeStatus(findings: CtFinding[], hasCerts: boolean): CheckStatus {
  if (findings.some(f => f.severity === "fail")) return "fail";
  if (findings.some(f => f.severity === "warn")) return "warn";
  return hasCerts ? "pass" : "info";
}

export function splitCerts(certs: CtLogEntry[], findings: CtFinding[]): { flaggedCerts: CtLogEntry[]; recentCerts: CtLogEntry[] } {
  const sorted = [...certs].sort((a, b) => (b.notBefore || "").localeCompare(a.notBefore || ""));
  const flaggedNames = new Set(findings.map(f => f.subdomain).filter(Boolean));
  const flaggedIssuers = new Set(findings.filter(f => f.title.includes("CA")).map(f => { const m = f.description.match(/issued by "([^"]+)"/); return m?.[1]; }).filter(Boolean));
  const flaggedCerts = sorted.filter(c => flaggedNames.has(c.commonName) || flaggedIssuers.has(c.issuerName));
  const recentCerts = sorted.slice(0, 10);
  return { flaggedCerts, recentCerts };
}

export async function checkCtLogs(domain: string, opts?: CtCheckOptions): Promise<CtLogsResult> {
  const authenticated = opts?.authenticated ?? false;
  const startAfterId = opts?.startAfterId;
  // Preferred source; undefined = default order (crt.sh-pg → certspotter).
  const preferred: CtSourcePref | undefined = opts?.ctSource;

  // Try sources in order: preferred (if any) first, then the default order for the rest.
  // The chosen source gets 2 retries; each fallback gets 1.
  const order: CtSourcePref[] = preferred
    ? [preferred, ...DEFAULT_CT_ORDER.filter(s => s !== preferred)]
    : DEFAULT_CT_ORDER;
  const fetchers = ctFetchers(domain, authenticated, startAfterId);

  let result: FetchResult | null = null;
  let source: CtDataSource = "none";
  for (let i = 0; i < order.length; i++) {
    const src = order[i];
    const isPrimary = i === 0;
    try {
      if (!isPrimary) log.warn({ source: src, domain }, "falling back");
      result = await fetchWithRetry(fetchers[src], isPrimary ? 2 : 1, isPrimary ? [1000, 2000] : [1000]);
      source = result.source;
      break;
    } catch (e: any) {
      const reason = e?.name === "AbortError" ? "timeout (10s)" : e?.message || e;
      const last = i === order.length - 1;
      log.warn(
        { source: src, domain, reason, errName: e?.name || "Error" },
        last ? "all CT sources failed" : (isPrimary ? "primary source failed after retries" : "fallback source failed"),
      );
    }
  }
  // Race fallback: /external can outrun /web, leaving sslIssuer null and silently
  // skipping the cross-CA detection. Do a quick TLS handshake ourselves so the
  // check runs even when the webfetch cache hasn't been populated yet.
  // Future: replace with Redis pub/sub to share the issuer between endpoints.
  let effectiveSslIssuer = opts?.sslIssuer ?? null;
  const cachedAny = await cacheGetMaybeStale<CtCacheEntry>(`ct-long:${domain}:${authenticated ? "s1" : "s0"}`);
  const hasCerts = (result && result.certs.length > 0) || !!cachedAny;
  if (!effectiveSslIssuer && hasCerts) {
    effectiveSslIssuer = await fetchSslIssuer(domain, 5000);
    if (effectiveSslIssuer) log.info({ domain, sslIssuer: effectiveSslIssuer }, "sslIssuer fallback resolved");
  }

  if (result) {
    // Uniform post-processing for every source: collapse true duplicates
    // (precert + leaf), sort recent-first, cap. `total` is the unique cert count.
    // The recent-first sort also avoids the "head-of-id-window looks like recent"
    // bug when CertSpotter returns the earliest 100 entries on the free tier.
    const { certs, total } = finalizeCerts(result.certs);
    await cacheSet(
      `ct-long:${domain}:${authenticated ? "s1" : "s0"}`,
      { certs, totalCerts: total, cachedAt: new Date().toISOString(), source } as CtCacheEntry,
      CT_LONG_TTL,
      CT_STALE_TTL,
    );
    const findings = analyzeFindings(certs, total, domain, { sslIssuer: effectiveSslIssuer, caaRecords: opts?.caaRecords });
    const { flaggedCerts, recentCerts } = splitCerts(certs, findings);
    incr("ct_source", { source, result: "fresh" });
    return { status: computeStatus(findings, total > 0), totalCerts: total, recentCerts, flaggedCerts, findings, source, lastCertSpotterId: result.lastId ?? undefined };
  }
  if (cachedAny) {
    const { data: cached, ageMs, isStale } = cachedAny;
    const staleSeconds = Math.round(ageMs / 1000);
    log.warn({ domain, stale: isStale, ageSeconds: staleSeconds, source: cached.source }, "using cached CT data");
    incr("ct_source", { source: cached.source, result: isStale ? "stale" : "cache" });
    // Re-finalize so entries cached before the unified pipeline (or by another
    // code path) are deduped/sorted/capped the same way as fresh fetches.
    const { certs, total } = finalizeCerts(cached.certs);
    const findings = analyzeFindings(certs, total, domain, { sslIssuer: effectiveSslIssuer, caaRecords: opts?.caaRecords });
    const { flaggedCerts, recentCerts } = splitCerts(certs, findings);
    return {
      status: "info",
      totalCerts: total,
      recentCerts,
      flaggedCerts,
      findings,
      source: cached.source,
      fromCache: true,
      cachedAt: cached.cachedAt,
      ...(isStale ? { stale: true, staleSeconds } : {}),
    };
  }
  log.warn({ domain }, "all CT sources unavailable");
  incr("ct_source", { source: "none", result: "none" });
  return { status: "info", totalCerts: 0, recentCerts: [], flaggedCerts: [], findings: [], source: "none", error: "CT log sources temporarily unavailable" };
}
