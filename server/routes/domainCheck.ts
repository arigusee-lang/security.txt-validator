import { Router } from "express";
import crypto from "node:crypto";
import type Database from "better-sqlite3";
import { safeFetchWithHeaders } from "../lib/safeFetch.js";
import { ssrfSafeFetch, ssrfSafeTlsConnect, warmDns } from "../lib/ipCheck.js";
import { cacheGet, cacheGetWithAge, cacheSet } from "../lib/cache.js";
import type { Response } from "express";
import { analyzeHeaders } from "../checkers/headersAnalyzer.js";
import { checkSpf } from "../checkers/spfChecker.js";
import { checkDmarc } from "../checkers/dmarcChecker.js";
import { checkDkim } from "../checkers/dkimChecker.js";
import { checkDnssec } from "../checkers/dnssecChecker.js";
import { checkCaa } from "../checkers/caaChecker.js";
import { checkMx } from "../checkers/mxChecker.js";
import { checkNs } from "../checkers/nsChecker.js";
import { analyzeSsl, analyzeSslDeep, applyManagedCertPolicy } from "../checkers/sslChecker.js";
import { probeMultiEdge } from "../lib/tlsEdgeProbe.js";
import { checkDomainExpiry } from "../checkers/domainExpiryChecker.js";
import { checkBlacklist } from "../checkers/blacklistChecker.js";
import { checkInfrastructure } from "../checkers/infrastructureChecker.js";
import { checkCtLogs, ctSourceTag } from "../checkers/ctLogsChecker.js";
import { checkRedirects } from "../checkers/redirectChecker.js";
import { checkSafeBrowsing } from "../checkers/safeBrowsingChecker.js";
import { checkUrlhaus } from "../checkers/urlhausChecker.js";
import { checkDanglingDns } from "../checkers/danglingDnsChecker.js";
import { parse } from "../../src/lib/parser.js";
import { createLogger } from "../lib/logger.js";

const log = createLogger("domain-check");
import { validate } from "../../src/lib/validator.js";
import { calculateScore } from "../scoreCalculator.js";
import { getRemediation } from "../remediations.js";
import { computeDiff } from "../diffEngine.js";
import type { ScanConfig, DomainCheckResponse, CheckStatus, CtCheckOptions, CtSourcePref } from "../types.js";
import { DEFAULT_SCAN_CONFIG } from "../types.js";
import { runDomainScan, type ProgressEvent, type ScanSection } from "../lib/scanPipeline.js";

const DNS_TIMEOUT = 8000;
const HTTP_TIMEOUT = 15000;
const CACHE_TTL = 15 * 60 * 1000;

/**
 * Helper: run a checker with caching.
 * If `res` is provided and a cache hit occurs, sets the `X-Cache-Age-Ms` header
 * to the maximum (oldest) age across all hits in this response — i.e. the
 * staleness ceiling of the data the client is about to render.
 */
async function cached<T>(key: string, noCache: boolean, fn: () => Promise<T>, res?: Response): Promise<T> {
  if (!noCache) {
    const hit = await cacheGetWithAge<T>(key);
    if (hit) {
      if (res) {
        const prev = parseInt((res.getHeader("X-Cache-Age-Ms") as string) || "0", 10);
        if (hit.ageMs > prev) res.setHeader("X-Cache-Age-Ms", String(hit.ageMs));
      }
      return hit.data;
    }
  }
  const result = await fn();
  await cacheSet(key, result, CACHE_TTL);
  return result;
}

/** Parse ScanConfig from query string */
function parseScanConfig(query: Record<string, any>): ScanConfig {
  const config: ScanConfig = JSON.parse(JSON.stringify(DEFAULT_SCAN_CONFIG));
  // noCache from query
  if (query.noCache === "1") config.noCache = true;
  if (isCtSourcePref(query.ctSource)) config.ctSource = query.ctSource;

  // Parse individual check toggles from query: e.g., ?checks.ssl=0&checks.headers=0
  if (query.config) {
    try {
      const parsed = JSON.parse(query.config as string);
      if (parsed.checks) {
        for (const [key, val] of Object.entries(parsed.checks)) {
          if (key in config.checks) {
            (config.checks as Record<string, boolean>)[key] = !!val;
          }
        }
      }
      if (parsed.noCache !== undefined) config.noCache = !!parsed.noCache;
      if (isCtSourcePref(parsed.ctSource)) config.ctSource = parsed.ctSource;
    } catch {
      // Ignore invalid config JSON
    }
  }
  return config;
}

/** Narrow an untrusted value to a valid CtSourcePref. */
function isCtSourcePref(v: unknown): v is CtSourcePref {
  return v === "certspotter" || v === "crt.sh-pg";
}

/** Attach remediation info to findings with warn/fail status */
function attachRemediations(result: Record<string, any>): void {
  const remediationCategories: Record<string, { statusPath: string; checkIdMap: Record<string, string> }> = {
    ssl: {
      statusPath: "status",
      checkIdMap: { warn: "expiring", fail: "expired" },
    },
    headers: {
      statusPath: "items",
      checkIdMap: {},
    },
    spf: {
      statusPath: "status",
      checkIdMap: { fail: "missing", warn: "softfail" },
    },
    dmarc: {
      statusPath: "status",
      checkIdMap: { fail: "missing", warn: "policy_none" },
    },
    dkim: {
      statusPath: "status",
      checkIdMap: { warn: "not_found", fail: "not_found" },
    },
    dnssec: {
      statusPath: "status",
      checkIdMap: { fail: "not_enabled", warn: "not_enabled" },
    },
    caa: {
      statusPath: "status",
      checkIdMap: { fail: "missing", warn: "missing" },
    },
    blacklist: {
      statusPath: "status",
      checkIdMap: { fail: "listed", warn: "listed" },
    },
    danglingDns: {
      statusPath: "status",
      checkIdMap: { fail: "dangling_found", warn: "dangling_found" },
    },
    domainExpiry: {
      statusPath: "status",
      checkIdMap: { warn: "expiring", fail: "expired" },
    },
    redirects: {
      statusPath: "status",
      checkIdMap: { fail: "no_https", warn: "no_redirect" },
    },
    securityTxt: {
      statusPath: "status",
      checkIdMap: { fail: "not_found", warn: "invalid" },
    },
    safeBrowsing: {
      statusPath: "status",
      checkIdMap: { fail: "flagged", warn: "flagged" },
    },
    urlhaus: {
      statusPath: "status",
      checkIdMap: { fail: "listed", warn: "listed" },
    },
  };

  for (const [category, config] of Object.entries(remediationCategories)) {
    const section = result[category];
    if (!section) continue;

    // Special handling for headers — attach remediation to individual items
    if (category === "headers" && section.items && Array.isArray(section.items)) {
      for (const item of section.items) {
        if (item.status === "warn" || item.status === "fail") {
          const checkId = `missing_${item.name?.toLowerCase().replace(/-/g, "_")}`;
          const rem = getRemediation("headers", checkId);
          if (rem) item.remediation = rem;
        }
      }
      continue;
    }

    // For SPF — check validations for specific issues
    if (category === "spf" && section.validations && Array.isArray(section.validations)) {
      for (const v of section.validations) {
        if (v.status === "warn" || v.status === "fail") {
          const checkId = v.check?.includes("lookup") ? "too_many_lookups"
            : v.check?.includes("softfail") || v.detail?.includes("~all") ? "softfail"
            : v.check?.includes("none") || v.detail?.includes("?all") || v.detail?.includes("+all") ? "policy_none"
            : "missing";
          const rem = getRemediation("spf", checkId);
          if (rem) v.remediation = rem;
        }
      }
    }

    // For DMARC — check validations for specific issues
    if (category === "dmarc" && section.validations && Array.isArray(section.validations)) {
      for (const v of section.validations) {
        if (v.status === "warn" || v.status === "fail") {
          const checkId = v.check?.includes("policy") && v.detail?.includes("none") ? "policy_none"
            : v.check?.includes("rua") ? "no_rua"
            : "missing";
          const rem = getRemediation("dmarc", checkId);
          if (rem) v.remediation = rem;
        }
      }
    }

    // General: attach remediation to the category level
    const status = section.status as CheckStatus;
    if (status === "warn" || status === "fail") {
      const checkId = config.checkIdMap[status];
      if (checkId) {
        const rem = getRemediation(category, checkId);
        if (rem) section.remediation = rem;
      }
    }
  }
}

/** Save a single section of scan results incrementally into the DB */
function saveScanSection(
  db: Database.Database,
  scanId: string,
  userId: string,
  domain: string,
  sectionKey: string,
  sectionData: any,
): void {
  const existing = db.prepare("SELECT result_json FROM scans WHERE id = ?").get(scanId) as
    | { result_json: string | null }
    | undefined;
  if (!existing) {
    db.prepare(
      "INSERT INTO scans (id, user_id, domain, scan_type, status, result_json, created_at) VALUES (?, ?, ?, 'single', 'running', ?, datetime('now'))",
    ).run(scanId, userId, domain, JSON.stringify({ [sectionKey]: sectionData }));
  } else {
    const current = JSON.parse(existing.result_json || "{}");
    current[sectionKey] = sectionData;
    db.prepare("UPDATE scans SET result_json = ? WHERE id = ?").run(JSON.stringify(current), scanId);
  }
}

interface DomainCheckDeps {
  db: Database.Database | null;
}

export function createDomainCheckRoutes({ db }: DomainCheckDeps): Router {
  const router = Router();

  // Pre-warm DNS cache before any check runs (prevents cold-resolver timeouts after idle)
  router.use(async (req, _res, next) => {
    const domain = req.query.domain as string;
    if (domain) await warmDns(domain);
    next();
  });

  /** Individual check endpoints — each returns independently */

  router.get("/dns", async (req, res) => {
    const domain = req.query.domain as string;
    const config = parseScanConfig(req.query);
    const nc = config.noCache;
    const checks = config.checks;

    // Infrastructure (resolve + CDN) runs first — DNSBL needs the primary IP,
    // and /web's managed-cert detection will read this from cache too.
    const infrastructure = checks.blacklist
      ? await cached(`infra:${domain}`, nc, () => checkInfrastructure(domain, DNS_TIMEOUT), res).catch(() => null)
      : null;
    const infraIp = infrastructure?.ip ?? null;

    const tasks: Promise<any>[] = [];
    const labels: string[] = [];

    if (checks.spf) { tasks.push(cached(`spf:${domain}`, nc, () => checkSpf(domain, DNS_TIMEOUT), res)); labels.push("spf"); }
    if (checks.dmarc) { tasks.push(cached(`dmarc:${domain}`, nc, () => checkDmarc(domain, DNS_TIMEOUT), res)); labels.push("dmarc"); }
    if (checks.dkim) { tasks.push(cached(`dkim:${domain}`, nc, () => checkDkim(domain, DNS_TIMEOUT), res)); labels.push("dkim"); }
    if (checks.dnssec) { tasks.push(cached(`dnssec:${domain}`, nc, () => checkDnssec(domain, DNS_TIMEOUT), res)); labels.push("dnssec"); }
    if (checks.caa) { tasks.push(cached(`caa:${domain}`, nc, () => checkCaa(domain, DNS_TIMEOUT), res)); labels.push("caa"); }
    if (checks.mx) { tasks.push(cached(`mx:${domain}`, nc, () => checkMx(domain, DNS_TIMEOUT), res)); labels.push("mx"); }
    if (checks.ns) { tasks.push(cached(`ns:${domain}`, nc, () => checkNs(domain, DNS_TIMEOUT), res)); labels.push("ns"); }
    if (checks.blacklist) { tasks.push(cached(`bl:${domain}`, nc, () => checkBlacklist(domain, infraIp, DNS_TIMEOUT), res)); labels.push("blacklist"); }
    if (checks.danglingDns) { tasks.push(cached(`dng:${domain}`, nc, () => checkDanglingDns(domain, DNS_TIMEOUT), res)); labels.push("danglingDns"); }
    if (checks.domainExpiry) { tasks.push(cached(`exp:${domain}`, nc, () => checkDomainExpiry(domain, HTTP_TIMEOUT), res)); labels.push("domainExpiry"); }

    const results = await Promise.allSettled(tasks);
    const x = <T>(s: PromiseSettledResult<T>, f: T): T => s.status === "fulfilled" ? s.value : f;

    const defaults: Record<string, any> = {
      spf: { status: "fail", record: null, validations: [], mechanisms: [], dnsLookupCount: 0, error: "Check failed" },
      dmarc: { status: "fail", record: null, validations: [], tags: [], error: "Check failed" },
      dkim: { status: "info", foundCount: 0, totalChecked: 14, selectors: [] },
      dnssec: { status: "fail", enabled: false, error: "Check failed" },
      caa: { status: "fail", records: [], error: "Check failed" },
      mx: { status: "info", records: [] },
      ns: { status: "fail", nameservers: [], error: "Check failed" },
      blacklist: { status: "info", providers: [], error: "Check failed" },
      danglingDns: { status: "info", records: [], danglingCount: 0, error: "Check failed" },
      domainExpiry: { status: "info", expirationDate: null, daysRemaining: null, error: "Check failed" },
    };

    const response: Record<string, any> = {};
    if (infrastructure) response.infrastructure = infrastructure;
    labels.forEach((label, i) => {
      response[label] = x(results[i], defaults[label]);
    });

    // ── No-email downgrade ──
    // If the domain has no MX records (or a Null MX per RFC 7505), email auth
    // is much less critical. Downgrade SPF/DMARC fail/warn → info with a note.
    // Spoofing protection still matters, so we don't suppress them entirely.
    const mx = response.mx;
    const hasMail = mx ? (mx.records?.length > 0 && !mx.nullMx) : true;
    if (!hasMail) {
      const note = mx?.nullMx
        ? "Domain explicitly rejects email (Null MX, RFC 7505). Email authentication is not required."
        : "Domain has no MX records and likely does not accept email. SPF/DMARC are optional but still recommended to prevent spoofing.";
      if (response.spf && (response.spf.status === "fail" || response.spf.status === "warn")) {
        response.spf.status = "info";
        response.spf.notice = note;
      }
      if (response.dmarc && (response.dmarc.status === "fail" || response.dmarc.status === "warn")) {
        response.dmarc.status = "info";
        response.dmarc.notice = note;
      }
    }

    // Incremental save for authenticated users
    const scanId = req.query.scanId as string | undefined;
    if (req.user && scanId && db) {
      try { saveScanSection(db, scanId, req.user.id, domain, "dns", response); } catch (e) { log.error({ err: e, section: "dns" }, "saveScanSection error"); }
    }

    res.json(response);
  });

  router.get("/web", async (req, res) => {
    const domain = req.query.domain as string;
    const config = parseScanConfig(req.query);
    const nc = config.noCache;
    const checks = config.checks;
    const response: Record<string, any> = {};

    // Shared infrastructure (cache key `infra:` — populated by /dns too, so
    // we usually hit cache here). Needed for multi-edge probe (use real IPs)
    // and CDN-managed cert detection (cdnProvider hint).
    const infrastructure = checks.ssl
      ? await cached(`infra:${domain}`, nc, () => checkInfrastructure(domain, DNS_TIMEOUT), res).catch(() => null)
      : null;
    const ipsForProbe = infrastructure?.ips ?? [];

    // Primary fetch (security.txt + headers + primary TLS cert) and
    // multi-edge probe run in parallel.
    const [fr, edgesResult] = await Promise.all([
      (checks.securityTxt || checks.headers || checks.ssl)
        ? cached(`webfetch:${domain}`, nc, () => safeFetchWithHeaders(domain, HTTP_TIMEOUT), res)
        : Promise.resolve(null),
      checks.ssl && ipsForProbe.length > 0
        ? cached(`edges:${domain}`, nc, () => probeMultiEdge(domain, ipsForProbe, HTTP_TIMEOUT), res).catch(() => null)
        : Promise.resolve(null),
    ]);

    // Build security.txt
    if (checks.securityTxt) {
      if (fr && fr.success) {
        const parsed = parse(fr.content, { withPgp: true });
        const vr = validate(parsed.lines, {
          contentType: fr.contentType, fetchedFrom: fr.fetchedFrom, redirectChain: fr.redirectChain,
          wellKnownFound: fr.wellKnownFound, fallbackUsed: fr.fallbackUsed, usedHttps: true,
        }, parsed.pgp);
        response.securityTxt = {
          status: vr.status === "valid" ? "pass" : vr.status === "valid-with-warnings" ? "warn" : "fail",
          available: true, validationStatus: vr.status, errorCount: vr.errorCount, warningCount: vr.warningCount,
          findings: vr.findings.map((f: any) => ({ severity: f.severity, title: f.title, explanation: f.explanation })),
          fetchedFrom: fr.fetchedFrom,
        };
      } else {
        const errMsg = fr ? (fr as any).message || "Could not fetch security.txt" : "Could not fetch security.txt";
        response.securityTxt = { status: "fail", available: false, validationStatus: null, errorCount: 0, warningCount: 0, findings: [], fetchedFrom: null, error: errMsg };
      }
    }

    // Build headers (from the same fetch response)
    if (checks.headers) {
      const rawHeaders = (fr as any)?.responseHeaders || null;
      response.headers = rawHeaders && Object.keys(rawHeaders).length > 0 ? await analyzeHeaders(rawHeaders) : { status: "info" as const, items: [] };
    }

    // Build SSL (from the same TLS connection)
    if (checks.ssl) {
      const tlsCert = (fr as any)?.tlsCert || null;
      const chainCerts = (fr as any)?.chainCerts;
      const rawLeafCert = (fr as any)?.rawLeafCert;
      if (tlsCert) {
        response.ssl = analyzeSslDeep(tlsCert, chainCerts, rawLeafCert);
      } else {
        response.ssl = analyzeSsl(null);
      }
      if (edgesResult) {
        response.ssl.edges = edgesResult;
      }
      // We have cdnProvider from shared infrastructure cache, so short-alias
      // issuer patterns (WE1 / E1) match here just like in /full + batch.
      applyManagedCertPolicy(response.ssl, infrastructure?.cdnProvider ?? undefined);
    }

    const scanId = req.query.scanId as string | undefined;
    if (req.user && scanId && db) {
      try { saveScanSection(db, scanId, req.user.id, domain, "web", response); } catch (e) { log.error({ err: e, section: "web" }, "saveScanSection error"); }
    }

    res.json(response);
  });

  router.get("/expiry", async (req, res) => {
    const domain = req.query.domain as string;
    const config = parseScanConfig(req.query);
    if (!config.checks.domainExpiry) { res.json(null); return; }
    const expiryResult = await cached(`exp:${domain}`, config.noCache, () => checkDomainExpiry(domain, HTTP_TIMEOUT));

    // Incremental save for authenticated users
    const scanId = req.query.scanId as string | undefined;
    if (req.user && scanId && db && expiryResult) {
      try { saveScanSection(db, scanId, req.user.id, domain, "expiry", expiryResult); } catch (e) { log.error({ err: e, section: "expiry" }, "saveScanSection error"); }
    }

    res.json(expiryResult);
  });

  router.get("/ct", async (req, res) => {
    const domain = req.query.domain as string;
    const config = parseScanConfig(req.query);
    
    if (!config.checks.ctLogs) { res.json(null); return; }
    // Subdomain CT lookup is a premium-tier feature. The flag is part of the
    // cache key so anonymous results never bleed into a premium request and
    // vice-versa.
    const wantSubdomains = req.user?.plan === "premium_plus";
    const ctOpts: CtCheckOptions = {
      authenticated: wantSubdomains,
      ctSource: config.ctSource,
    };
    const ctResult = await cached(`ct:${domain}:${ctSourceTag(config.ctSource)}:${wantSubdomains ? "s1" : "s0"}`, config.noCache, () => checkCtLogs(domain, ctOpts));

    const scanId = req.query.scanId as string | undefined;
    if (req.user && scanId && db && ctResult) {
      try { saveScanSection(db, scanId, req.user.id, domain, "ct", ctResult); } catch (e) { log.error({ err: e, section: "ct" }, "saveScanSection error"); }
    }

    res.json(ctResult);
  });

  router.get("/redirects", async (req, res) => {
    const domain = req.query.domain as string;
    const config = parseScanConfig(req.query);
    if (!config.checks.redirects) { res.json(null); return; }
    const redirectsResult = await cached(`redir:${domain}`, config.noCache, () => checkRedirects(domain, HTTP_TIMEOUT));

    const scanId = req.query.scanId as string | undefined;
    if (req.user && scanId && db && redirectsResult) {
      try { saveScanSection(db, scanId, req.user.id, domain, "redirects", redirectsResult); } catch (e) { log.error({ err: e, section: "redirects" }, "saveScanSection error"); }
    }

    res.json(redirectsResult);
  });

  router.get("/reputation", async (req, res) => {
    const domain = req.query.domain as string;
    const config = parseScanConfig(req.query);
    const nc = config.noCache;
    const checks = config.checks;

    const tasks: Promise<any>[] = [];
    const labels: string[] = [];

    if (checks.reputation) {
      tasks.push(cached(`sb:${domain}`, nc, () => checkSafeBrowsing(domain, DNS_TIMEOUT)));
      labels.push("safeBrowsing");
      tasks.push(cached(`uh:${domain}`, nc, () => checkUrlhaus(domain, DNS_TIMEOUT)));
      labels.push("urlhaus");
    }

    const results = await Promise.allSettled(tasks);
    const x = <T>(s: PromiseSettledResult<T>, f: T): T => s.status === "fulfilled" ? s.value : f;

    const response: Record<string, any> = {};
    if (labels.includes("safeBrowsing")) {
      response.safeBrowsing = x(results[labels.indexOf("safeBrowsing")], { status: "info", safe: null, threats: [], error: "Check failed" });
    }
    if (labels.includes("urlhaus")) {
      response.urlhaus = x(results[labels.indexOf("urlhaus")], { status: "info", listed: false, urlCount: 0, error: "Check failed" });
    }

    // Incremental save for authenticated users
    const scanId = req.query.scanId as string | undefined;
    if (req.user && scanId && db) {
      try { saveScanSection(db, scanId, req.user.id, domain, "reputation", response); } catch (e) { log.error({ err: e, section: "reputation" }, "saveScanSection error"); }
    }

    res.json(response);
  });

  /**
   * GET /http — Redirects + SEO checks (both make HTTP requests to the target domain)
   */
  router.get("/http", async (req, res) => {
    const domain = req.query.domain as string;
    const config = parseScanConfig(req.query);
    const nc = config.noCache;
    const checks = config.checks;
    const response: Record<string, any> = {};

    const tasks: Array<{ label: string; promise: Promise<any>; fallback: any }> = [];
    if (checks.redirects) tasks.push({ label: "redirects", promise: cached(`redir:${domain}`, nc, () => checkRedirects(domain, HTTP_TIMEOUT), res), fallback: { status: "info", httpsRedirect: false, wwwBehavior: null, items: [], error: "Check failed" } });

    const results = await Promise.allSettled(tasks.map(t => t.promise));
    tasks.forEach((t, i) => {
      response[t.label] = results[i].status === "fulfilled" ? (results[i] as PromiseFulfilledResult<any>).value : t.fallback;
    });

    const scanId = req.query.scanId as string | undefined;
    if (req.user && scanId && db) {
      try { saveScanSection(db, scanId, req.user.id, domain, "http", response); } catch (e) { log.error({ err: e, section: "http" }, "saveScanSection error"); }
    }

    res.json(response);
  });

  /**
   * GET /external — CT logs + reputation checks (all external API calls)
   */
  router.get("/external", async (req, res) => {
    const domain = req.query.domain as string;
    const config = parseScanConfig(req.query);
    const nc = config.noCache;
    const checks = config.checks;
    const response: Record<string, any> = {};

    const tasks: Array<{ label: string; promise: Promise<any>; fallback: any }> = [];

    if (checks.ctLogs) {
      // Try to get CAA and SSL data from cache for CT analysis
      // If not cached yet (race with /dns), do a quick CAA lookup
      let caaRecords = (await cacheGet<any>(`caa:${domain}`))?.records;
      if (!caaRecords) {
        try { const caaResult = await checkCaa(domain, DNS_TIMEOUT); caaRecords = caaResult.records; } catch { /* best effort */ }
      }
      const cachedSsl = await cacheGet<any>(`webfetch:${domain}`);
      const wantSubdomains = req.user?.plan === "premium_plus";
      const ctOpts: CtCheckOptions = {
        authenticated: wantSubdomains,
        ctSource: config.ctSource,
        caaRecords,
        sslIssuer: cachedSsl?.tlsCert?.issuer ?? null,
      };
      tasks.push({ label: "ct", promise: cached(`ct:${domain}:${ctSourceTag(config.ctSource)}:${wantSubdomains ? "s1" : "s0"}`, nc, () => checkCtLogs(domain, ctOpts), res), fallback: { status: "info", totalCerts: 0, recentCerts: [], findings: [], source: "none", error: "Check failed" } });
    }
    if (checks.reputation) {
      tasks.push({ label: "safeBrowsing", promise: cached(`sb:${domain}`, nc, () => checkSafeBrowsing(domain, DNS_TIMEOUT), res), fallback: { status: "info", safe: null, threats: [], error: "Check failed" } });
      tasks.push({ label: "urlhaus", promise: cached(`uh:${domain}`, nc, () => checkUrlhaus(domain, DNS_TIMEOUT), res), fallback: { status: "info", listed: false, urlCount: 0, error: "Check failed" } });
    }

    const results = await Promise.allSettled(tasks.map(t => t.promise));
    tasks.forEach((t, i) => {
      response[t.label] = results[i].status === "fulfilled" ? (results[i] as PromiseFulfilledResult<any>).value : t.fallback;
    });

    const scanId = req.query.scanId as string | undefined;
    if (req.user && scanId && db) {
      try { saveScanSection(db, scanId, req.user.id, domain, "external", response); } catch (e) { log.error({ err: e, section: "external" }, "saveScanSection error"); }
    }

    res.json(response);
  });

  /**
   * GET /full — Aggregated endpoint that runs all enabled checks, computes score,
   * attaches remediation, auto-saves for authenticated users, and computes diff.
   */
  /**
   * GET /stream — Server-Sent Events: wave-based pipeline emits each check
   * via `event: section` as soon as it completes. The frontend renders
   * incrementally without waiting for slow checks (CT logs, WHOIS) to block
   * the fast ones (SPF, headers, primary cert).
   *
   * Replaces the old "4 parallel endpoints with cache-read race fallbacks"
   * (/dns, /web, /http, /external). Those endpoints stay for the batch
   * scanner and any legacy clients.
   */
  router.get("/stream", async (req, res) => {
    const domain = req.query.domain as string;
    if (!domain) {
      res.status(400).json({ error: "invalid_request", message: "domain is required" });
      return;
    }

    const config = parseScanConfig(req.query);
    const scanId = req.query.scanId as string | undefined;

    // SSE headers — flush immediately so the client gets the connection-open
    // before the first check completes.
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no"); // disable nginx buffering
    res.flushHeaders?.();

    const aborter = new AbortController();
    let clientGone = false;
    req.on("close", () => {
      clientGone = true;
      aborter.abort();
    });

    // Accumulate sections so we can persist a snapshot at the end.
    const sections: Record<string, any> = {};

    const sendEvent = (event: ProgressEvent) => {
      if (clientGone) return;
      try {
        res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
      } catch {
        // best-effort — pipe may be broken if client disconnected mid-write
      }
      if (event.type === "section") {
        sections[event.section] = event.data;
      }
    };

    try {
      await runDomainScan(
        domain,
        {
          noCache: config.noCache,
          checks: config.checks,
          premiumPlus: req.user?.plan === "premium_plus",
          ctSource: config.ctSource,
        },
        sendEvent,
        aborter.signal,
      );
    } catch (err: any) {
      log.error({ err: err?.message || err, domain }, "scan pipeline error");
      if (!clientGone) {
        try {
          res.write(`event: error\ndata: ${JSON.stringify({ message: err?.message || "scan failed" })}\n\n`);
        } catch { /* ignore */ }
      }
    }

    // Persist accumulated sections as a flat result for authenticated users.
    // DomainCheckerPage.loadFromHistory detects flat format via r.spf/r.dmarc.
    if (!clientGone && req.user && scanId && db && Object.keys(sections).length > 0) {
      try {
        const json = JSON.stringify(sections);
        const existing = db.prepare("SELECT id FROM scans WHERE id = ?").get(scanId);
        if (existing) {
          db.prepare("UPDATE scans SET result_json = ? WHERE id = ?").run(json, scanId);
        } else {
          db.prepare(
            "INSERT INTO scans (id, user_id, domain, scan_type, status, result_json, created_at) VALUES (?, ?, ?, 'single', 'running', ?, datetime('now'))",
          ).run(scanId, req.user.id, domain, json);
        }
      } catch (e) {
        log.error({ err: e, scanId }, "stream persist failed");
      }
    }

    if (!clientGone) {
      try { res.end(); } catch { /* ignore */ }
    }
  });

  router.get("/full", async (req, res) => {
    const domain = req.query.domain as string;
    if (!domain) {
      res.status(400).json({ error: "invalid_request", message: "domain is required" });
      return;
    }

    const config = parseScanConfig(req.query);
    const nc = config.noCache || (!!req.user && req.query.noCache === "1");
    const checks = config.checks;
    const result: Record<string, any> = { domain, timestamp: new Date().toISOString() };

    try {
      // â”€â”€ Infrastructure (blacklist + multi-edge probe both depend on it) â”€â”€
      const infrastructure = checks.blacklist || checks.ssl
        ? await cached(`infra:${domain}`, nc, () => checkInfrastructure(domain, DNS_TIMEOUT)).catch(() => null)
        : null;
      const infraIp = infrastructure?.ip ?? null;
      if (infrastructure) result.infrastructure = infrastructure;

      // â”€â”€ DNS checks â”€â”€
      const dnsPromises: Array<{ label: string; promise: Promise<any>; fallback: any }> = [];
      if (checks.spf) dnsPromises.push({ label: "spf", promise: cached(`spf:${domain}`, nc, () => checkSpf(domain, DNS_TIMEOUT)), fallback: { status: "fail", record: null, validations: [], mechanisms: [], dnsLookupCount: 0, error: "Check failed" } });
      if (checks.dmarc) dnsPromises.push({ label: "dmarc", promise: cached(`dmarc:${domain}`, nc, () => checkDmarc(domain, DNS_TIMEOUT)), fallback: { status: "fail", record: null, validations: [], tags: [], error: "Check failed" } });
      if (checks.dkim) dnsPromises.push({ label: "dkim", promise: cached(`dkim:${domain}`, nc, () => checkDkim(domain, DNS_TIMEOUT)), fallback: { status: "info", foundCount: 0, totalChecked: 14, selectors: [] } });
      if (checks.dnssec) dnsPromises.push({ label: "dnssec", promise: cached(`dnssec:${domain}`, nc, () => checkDnssec(domain, DNS_TIMEOUT)), fallback: { status: "fail", enabled: false, error: "Check failed" } });
      if (checks.caa) dnsPromises.push({ label: "caa", promise: cached(`caa:${domain}`, nc, () => checkCaa(domain, DNS_TIMEOUT)), fallback: { status: "fail", records: [], error: "Check failed" } });
      if (checks.mx) dnsPromises.push({ label: "mx", promise: cached(`mx:${domain}`, nc, () => checkMx(domain, DNS_TIMEOUT)), fallback: { status: "info", records: [] } });
      if (checks.ns) dnsPromises.push({ label: "ns", promise: cached(`ns:${domain}`, nc, () => checkNs(domain, DNS_TIMEOUT)), fallback: { status: "fail", nameservers: [], error: "Check failed" } });
      if (checks.blacklist) dnsPromises.push({ label: "blacklist", promise: cached(`bl:${domain}`, nc, () => checkBlacklist(domain, infraIp, DNS_TIMEOUT)), fallback: { status: "info", providers: [], error: "Check failed" } });
      if (checks.danglingDns) dnsPromises.push({ label: "danglingDns", promise: cached(`dng:${domain}`, nc, () => checkDanglingDns(domain, DNS_TIMEOUT)), fallback: { status: "info", records: [], danglingCount: 0, error: "Check failed" } });

      // â”€â”€ Web checks â”€â”€
      const webPromises: Array<{ label: string; promise: Promise<any> }> = [];
      if (checks.securityTxt) webPromises.push({ label: "fetch", promise: cached(`fetch:${domain}`, nc, () => safeFetchWithHeaders(domain, HTTP_TIMEOUT)) });
      if (checks.headers) {
        webPromises.push({
          label: "headers",
          promise: cached(`hdrs:${domain}`, nc, async () => {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT);
            try {
              const headRes = await ssrfSafeFetch(`https://${domain}/`, {
                method: "HEAD", signal: controller.signal, redirect: "follow",
                headers: { "User-Agent": "security-txt-validator/1.0" },
              });
              clearTimeout(timer);
              const h: Record<string, string> = {};
              headRes.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
              return h;
            } catch { clearTimeout(timer); return null; }
          }),
        });
      }
      if (checks.ssl) {
        const ipsForProbe = infrastructure?.ips ?? [];
        if (ipsForProbe.length > 0) {
          webPromises.push({
            label: "edges",
            promise: cached(`edges:${domain}`, nc, () => probeMultiEdge(domain, ipsForProbe, HTTP_TIMEOUT)),
          });
        }
        webPromises.push({
          label: "tls",
          promise: cached(`tls:${domain}`, nc, async () => {
            return new Promise<any>(async (resolve) => {
              try {
                const socket = await ssrfSafeTlsConnect({ host: domain, port: 443, servername: domain, timeout: HTTP_TIMEOUT, rejectUnauthorized: false });
                // TLS connected
                let detailedCert: any, basicCert: any;
                try { detailedCert = socket.getPeerCertificate(true); basicCert = socket.getPeerCertificate(false);  } catch (e: any) { log.warn({ err: e?.message, section: "ssl" }, "getPeerCertificate error"); detailedCert = null; basicCert = null; }
                socket.destroy();
                const cert = detailedCert || basicCert;
                if (!cert || !cert.valid_from) { resolve(null); return; }
                const validFrom = new Date(cert.valid_from).toISOString();
                const validTo = new Date(cert.valid_to).toISOString();
                const daysRemaining = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
                const sans: string[] = cert.subjectaltname ? cert.subjectaltname.split(",").map((s: string) => s.trim().replace(/^DNS:/, "")) : [];
                let chainCerts: any[] | undefined;
                try { if (detailedCert) { chainCerts = []; let current = detailedCert; const seen = new Set<string>(); while (current && current.fingerprint256 && !seen.has(current.fingerprint256)) { seen.add(current.fingerprint256); chainCerts.push({ subject: String(current.subject?.CN || "Unknown"), issuer: String(current.issuer?.O || current.issuer?.CN || "Unknown"), validFrom: new Date(current.valid_from).toISOString(), validTo: new Date(current.valid_to).toISOString(), isSelfSigned: current.subject?.CN === current.issuer?.CN && current.subject?.O === current.issuer?.O, role: "leaf" }); current = current.issuerCertificate; } } } catch { chainCerts = undefined; }
                let rawLeafCert: Buffer | undefined;
                try { if (basicCert?.raw) rawLeafCert = basicCert.raw; } catch { rawLeafCert = undefined; }
                resolve({ issuer: String(cert.issuer?.O || cert.issuer?.CN || "Unknown"), subject: String(cert.subject?.CN || "Unknown"), validFrom, validTo, daysRemaining, sans, chainCerts, rawLeafCert });
              } catch { resolve(null); }
            });
          }),
        });
      }

      // â”€â”€ Other checks (non-CT) â”€â”€
      const otherPromises: Array<{ label: string; promise: Promise<any>; fallback: any }> = [];
      if (checks.domainExpiry) otherPromises.push({ label: "domainExpiry", promise: cached(`exp:${domain}`, nc, () => checkDomainExpiry(domain, HTTP_TIMEOUT)), fallback: { status: "info", expirationDate: null, daysRemaining: null, error: "Check failed" } });
      if (checks.redirects) otherPromises.push({ label: "redirects", promise: cached(`redir:${domain}`, nc, () => checkRedirects(domain, HTTP_TIMEOUT)), fallback: { status: "info", httpsRedirect: false, wwwBehavior: null, items: [], error: "Check failed" } });
      if (checks.reputation) {
        otherPromises.push({ label: "safeBrowsing", promise: cached(`sb:${domain}`, nc, () => checkSafeBrowsing(domain, DNS_TIMEOUT)), fallback: { status: "info", safe: null, threats: [], error: "Check failed" } });
        otherPromises.push({ label: "urlhaus", promise: cached(`uh:${domain}`, nc, () => checkUrlhaus(domain, DNS_TIMEOUT)), fallback: { status: "info", listed: false, urlCount: 0, error: "Check failed" } });
      }

      // Run all in parallel
      const allPromises = [
        ...dnsPromises.map((p) => p.promise),
        ...webPromises.map((p) => p.promise),
        ...otherPromises.map((p) => p.promise),
      ];
      const allResults = await Promise.allSettled(allPromises);

      let idx = 0;
      // DNS results
      for (const dp of dnsPromises) {
        const r = allResults[idx++];
        result[dp.label] = r.status === "fulfilled" ? r.value : dp.fallback;
      }
      // Web results
      const webMap: Record<string, any> = {};
      for (const wp of webPromises) {
        const r = allResults[idx++];
        webMap[wp.label] = r.status === "fulfilled" ? r.value : null;
      }
      // Other results
      for (const op of otherPromises) {
        const r = allResults[idx++];
        result[op.label] = r.status === "fulfilled" ? r.value : op.fallback;
      }

      // Build securityTxt from fetch result
      if (checks.securityTxt) {
        const fr = webMap.fetch;
        if (fr && fr.success) {
          const parsed = parse(fr.content, { withPgp: true });
          const vr = validate(parsed.lines, {
            contentType: fr.contentType, fetchedFrom: fr.fetchedFrom, redirectChain: fr.redirectChain,
            wellKnownFound: fr.wellKnownFound, fallbackUsed: fr.fallbackUsed, usedHttps: true,
          }, parsed.pgp);
          result.securityTxt = {
            status: vr.status === "valid" ? "pass" : vr.status === "valid-with-warnings" ? "warn" : "fail",
            available: true, validationStatus: vr.status, errorCount: vr.errorCount, warningCount: vr.warningCount,
            findings: vr.findings.map((f: any) => ({ severity: f.severity, title: f.title, explanation: f.explanation })),
            fetchedFrom: fr.fetchedFrom,
          };
        } else {
          const errMsg = fr ? (fr as any).message || "Could not fetch security.txt" : "Could not fetch security.txt";
          result.securityTxt = { status: "fail", available: false, validationStatus: null, errorCount: 0, warningCount: 0, findings: [], fetchedFrom: null, error: errMsg };
        }
      }

      // Build headers
      if (checks.headers) {
        const rawHeaders = webMap.headers;
        result.headers = rawHeaders ? await analyzeHeaders(rawHeaders) : { status: "info" as const, items: [] };
      }

      // Build SSL
      if (checks.ssl) {
        const cert = webMap.tls;
        if (cert) {
          const { chainCerts, rawLeafCert, ...certInfo } = cert;
          result.ssl = analyzeSslDeep(certInfo, chainCerts, rawLeafCert);
        } else {
          result.ssl = analyzeSsl(null);
        }
        if (webMap.edges) {
          result.ssl.edges = webMap.edges;
        }
        applyManagedCertPolicy(result.ssl, result.infrastructure?.cdnProvider);
      }

      // â”€â”€ CT Logs (second wave — needs SSL and CAA results) â”€â”€
      if (checks.ctLogs) {
        const wantSubdomains = req.user?.plan === "premium_plus";
        const fullCtOpts: CtCheckOptions = {
          authenticated: wantSubdomains,
          sslIssuer: result.ssl?.issuer ?? null,
          caaRecords: result.caa?.records ?? [],
          ctSource: config.ctSource,
        };
        try {
          result.ctLogs = await cached(`ct:${domain}:${ctSourceTag(config.ctSource)}:${wantSubdomains ? "s1" : "s0"}`, nc, () => checkCtLogs(domain, fullCtOpts));
        } catch {
          result.ctLogs = { status: "info", totalCerts: 0, recentCerts: [], findings: [], source: "none", error: "Check failed" };
        }
      }

      // â”€â”€ Calculate score â”€â”€
      const score = calculateScore(result);
      result.score = score;

      // â”€â”€ Attach remediation info to warn/fail findings â”€â”€
      attachRemediations(result);

      // â”€â”€ Auto-save for authenticated users â”€â”€
      let diff = null;
      if (req.user && db) {
        const scanId = crypto.randomUUID();
        const now = new Date().toISOString();

        // Find previous single-scan for same domain+user for diff.
        // Single scans diff only against single scans; batch and monitoring history is excluded.
        const previousScan = db.prepare(
          `SELECT id, result_json, created_at FROM scans
           WHERE user_id = ? AND domain = ? AND scan_type = 'single' AND status = 'completed'
           ORDER BY created_at DESC LIMIT 1`
        ).get(req.user.id, domain) as { id: string; result_json: string | null; created_at: string } | undefined;

        // Compute diff if previous scan exists
        if (previousScan?.result_json) {
          try {
            const previousResult = JSON.parse(previousScan.result_json) as DomainCheckResponse;
            diff = computeDiff(result as unknown as DomainCheckResponse, previousResult);
            diff.previousScanId = previousScan.id;
            diff.previousScanDate = previousScan.created_at;
          } catch {
            // Ignore diff errors
          }
        }

        // Save scan result
        try {
          db.prepare(
            `INSERT INTO scans (id, user_id, domain, scan_type, status, score, config_json, result_json, changes_json, created_at, completed_at)
             VALUES (?, ?, ?, 'single', 'completed', ?, ?, ?, ?, ?, ?)`
          ).run(
            scanId,
            req.user.id,
            domain,
            score.total,
            JSON.stringify(config),
            JSON.stringify(result),
            diff ? JSON.stringify(diff) : null,
            now,
            now,
          );
          result.scanId = scanId;
          result.saved = true;
        } catch (err) {
          log.error({ err }, "failed to save scan");
          result.saved = false;
        }
      }

      if (diff) {
        result.diff = diff;
      }

      res.json(result);
    } catch (err) {
      log.error({ err, route: "full" }, "scan error");
      res.status(500).json({ error: "internal", message: "Scan failed" });
    }
  });

  /**
   * POST /save — Save scan results collected by the frontend (progressive loading path).
   * Authenticated users only. Computes score, diff, and saves to history.
   */
  router.post("/save", async (req, res) => {
    if (!req.user || !db) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }

    const { domain, results } = req.body as { domain: string; results: Record<string, any> };
    if (!domain || !results) {
      res.status(400).json({ error: "invalid_request", message: "domain and results required" });
      return;
    }

    try {
      // Calculate score
      const score = calculateScore(results);

      // Find previous single-scan for diff (single ↔ single only).
      const previousScan = db.prepare(
        `SELECT id, result_json, created_at FROM scans
         WHERE user_id = ? AND domain = ? AND scan_type = 'single' AND status = 'completed'
         ORDER BY created_at DESC LIMIT 1`
      ).get(req.user.id, domain) as { id: string; result_json: string | null; created_at: string } | undefined;

      let diff = null;
      if (previousScan?.result_json) {
        try {
          const previousResult = JSON.parse(previousScan.result_json);
          diff = computeDiff(results as any, previousResult);
          diff.previousScanId = previousScan.id;
          diff.previousScanDate = previousScan.created_at;
        } catch { /* ignore diff errors */ }
      }

      // Save to DB
      const scanId = crypto.randomUUID();
      const now = new Date().toISOString();
      db.prepare(
        `INSERT INTO scans (id, user_id, domain, scan_type, status, score, result_json, changes_json, created_at, completed_at)
         VALUES (?, ?, ?, 'single', 'completed', ?, ?, ?, ?, ?)`
      ).run(scanId, req.user.id, domain, score.total, JSON.stringify(results), diff ? JSON.stringify(diff) : null, now, now);

      res.json({ scanId, score, diff, saved: true });
    } catch (err) {
      log.error({ err, route: "save" }, "scan error");
      res.status(500).json({ error: "internal" });
    }
  });

  /**
   * POST /finalize — Finalize an incremental scan: compute score, diff, update status.
   * Authenticated users only.
   */
  router.post("/finalize", async (req, res) => {
    if (!req.user || !db) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }

    const { scanId } = req.body as { scanId: string };
    if (!scanId) {
      res.status(400).json({ error: "invalid_request", message: "scanId is required" });
      return;
    }

    try {
      const scan = db.prepare("SELECT * FROM scans WHERE id = ? AND user_id = ?").get(scanId, req.user.id) as
        | { id: string; domain: string; result_json: string | null } | undefined;

      if (!scan) {
        res.status(404).json({ error: "not_found", message: "Scan not found" });
        return;
      }

      const resultJson = JSON.parse(scan.result_json || "{}");

      // Flatten the section-grouped result_json into a DomainCheckResponse-like shape for scoring
      // dns section contains: spf, dmarc, dkim, dnssec, caa, mx, ns, blacklist, danglingDns, domainExpiry
      // web section contains: securityTxt, headers, ssl
      // http section contains: redirects, seo
      // external section contains: ct, safeBrowsing, urlhaus
      const flat: Record<string, any> = {
        domain: scan.domain,
        timestamp: new Date().toISOString(),
      };

      if (resultJson.dns) {
        const { domainExpiry, ...dnsRest } = resultJson.dns;
        Object.assign(flat, dnsRest);
        if (domainExpiry) flat.domainExpiry = domainExpiry;
      }
      if (resultJson.web) {
        Object.assign(flat, resultJson.web);
      }
      // Legacy: old scans may have expiry as separate section
      if (resultJson.expiry) {
        flat.domainExpiry = resultJson.expiry;
      }
      // New grouped sections
      if (resultJson.http) {
        if (resultJson.http.redirects) flat.redirects = resultJson.http.redirects;
      }
      if (resultJson.external) {
        if (resultJson.external.ct) flat.ctLogs = resultJson.external.ct;
        if (resultJson.external.safeBrowsing) flat.safeBrowsing = resultJson.external.safeBrowsing;
        if (resultJson.external.urlhaus) flat.urlhaus = resultJson.external.urlhaus;
      }
      // Legacy: old scans may have these as separate sections
      if (resultJson.ct) flat.ctLogs = resultJson.ct;
      if (resultJson.redirects) flat.redirects = resultJson.redirects;
      if (resultJson.reputation) Object.assign(flat, resultJson.reputation);

      // Top-level flat format from the SSE pipeline — each check saved under
      // its own key (r.spf, r.ssl, r.ctLogs, ...). Copy any keys not already
      // populated by the section-grouped or legacy branches above.
      const FLAT_KEYS = [
        "spf", "dmarc", "dkim", "dnssec", "caa", "mx", "ns",
        "blacklist", "danglingDns", "infrastructure",
        "securityTxt", "headers", "ssl",
        "redirects",
        "safeBrowsing", "urlhaus", "ctLogs",
        "domainExpiry",
      ];
      for (const k of FLAT_KEYS) {
        if (resultJson[k] && !(k in flat)) flat[k] = resultJson[k];
      }

      // Calculate score
      const score = calculateScore(flat);

      // Attach remediations
      attachRemediations(flat);

      // Find previous single-scan for diff (single ↔ single only; exclude batch/monitoring history).
      const previousScan = db.prepare(
        `SELECT id, result_json, created_at FROM scans
         WHERE user_id = ? AND domain = ? AND scan_type = 'single' AND status = 'completed' AND id != ?
         ORDER BY created_at DESC LIMIT 1`
      ).get(req.user.id, scan.domain, scanId) as
        | { id: string; result_json: string | null; created_at: string } | undefined;

      let diff = null;
      if (previousScan?.result_json) {
        try {
          const previousResult = JSON.parse(previousScan.result_json);
          // Flatten previous result if it's in section format
          const prevFlat: Record<string, any> = {};
          if (previousResult.dns) { Object.assign(prevFlat, previousResult.dns); }
          else if (previousResult.spf) { Object.assign(prevFlat, previousResult); } // already flat
          if (previousResult.web) { Object.assign(prevFlat, previousResult.web); }
          else if (previousResult.headers) { Object.assign(prevFlat, previousResult); }
          if (previousResult.expiry) { prevFlat.domainExpiry = previousResult.expiry; }
          else if (previousResult.domainExpiry) { prevFlat.domainExpiry = previousResult.domainExpiry; }
          if (previousResult.ct) { prevFlat.ctLogs = previousResult.ct; }
          else if (previousResult.ctLogs) { prevFlat.ctLogs = previousResult.ctLogs; }
          if (previousResult.redirects) { prevFlat.redirects = previousResult.redirects; }
          if (previousResult.reputation) { Object.assign(prevFlat, previousResult.reputation); }
          else if (previousResult.safeBrowsing) { prevFlat.safeBrowsing = previousResult.safeBrowsing; prevFlat.urlhaus = previousResult.urlhaus; }

          diff = computeDiff(flat as any, prevFlat as any);
          diff.previousScanId = previousScan.id;
          diff.previousScanDate = previousScan.created_at;
        } catch { /* ignore diff errors */ }
      }

      const now = new Date().toISOString();
      db.prepare(
        `UPDATE scans SET status = 'completed', score = ?, result_json = ?, changes_json = ?, completed_at = ? WHERE id = ?`
      ).run(score.total, JSON.stringify(flat), diff ? JSON.stringify(diff) : null, now, scanId);

      res.json({ scanId, score, diff, saved: true });
    } catch (err) {
      log.error({ err, route: "finalize" }, "scan error");
      res.status(500).json({ error: "internal" });
    }
  });

  return router;
}

// Default export for backward compatibility (no db, anonymous-only)
export default createDomainCheckRoutes({ db: null });
