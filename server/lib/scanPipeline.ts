/**
 * Wave-based domain scan pipeline.
 *
 * Replaces the old "4 parallel endpoints with cache-read races" model with a
 * proper dependency-aware DAG. The pipeline emits each check via `onProgress`
 * as soon as it completes — the SSE endpoint forwards these as server-sent
 * events, so the UI can render incrementally with sub-second granularity.
 *
 * Waves:
 *  - Wave 0: infrastructure (resolve + CDN detect). Needed by blacklist,
 *    multi-edge TLS probe, and CDN-managed cert detection.
 *  - Wave 1: everything else with no cross-group dependency (DNS records,
 *    primary fetch + cert, redirects, safeBrowsing, urlhaus, edges probe).
 *  - Wave 2: CT logs (needs ssl.issuer + caa.records).
 */

import { cacheGetWithAge, cacheSet } from "./cache.js";
import { createLogger } from "./logger.js";
import { incr, observe } from "./metrics.js";
import { checkSpf } from "../checkers/spfChecker.js";
import { checkDmarc } from "../checkers/dmarcChecker.js";
import { checkDkim } from "../checkers/dkimChecker.js";
import { checkDnssec } from "../checkers/dnssecChecker.js";
import { checkCaa } from "../checkers/caaChecker.js";
import { checkMx } from "../checkers/mxChecker.js";
import { checkNs } from "../checkers/nsChecker.js";
import { checkBlacklist } from "../checkers/blacklistChecker.js";
import { checkInfrastructure } from "../checkers/infrastructureChecker.js";
import { checkDanglingDns } from "../checkers/danglingDnsChecker.js";
import { checkDomainExpiry } from "../checkers/domainExpiryChecker.js";
import { safeFetchWithHeaders } from "./safeFetch.js";
import { analyzeHeaders } from "../checkers/headersAnalyzer.js";
import { analyzeSsl, analyzeSslDeep, applyManagedCertPolicy } from "../checkers/sslChecker.js";
import { probeMultiEdge } from "./tlsEdgeProbe.js";
import { checkRedirects } from "../checkers/redirectChecker.js";
import { checkSafeBrowsing } from "../checkers/safeBrowsingChecker.js";
import { checkUrlhaus } from "../checkers/urlhausChecker.js";
import { checkCtLogs, ctSourceTag } from "../checkers/ctLogsChecker.js";
import { parse } from "../../src/lib/parser.js";
import { validate } from "../../src/lib/validator.js";
import type {
  ScanConfig,
  CtCheckOptions,
  CtSourcePref,
  SslResult,
  CaaResult,
  InfrastructureResult,
  SecurityTxtSection,
} from "../types.js";

const log = createLogger("scan-pipeline");

const DNS_TIMEOUT = 8000;
const HTTP_TIMEOUT = 15000;
const CACHE_TTL = 15 * 60 * 1000;

export type ScanSection =
  | "infrastructure"
  | "spf"
  | "dmarc"
  | "dkim"
  | "dnssec"
  | "caa"
  | "mx"
  | "ns"
  | "blacklist"
  | "danglingDns"
  | "domainExpiry"
  | "securityTxt"
  | "headers"
  | "ssl"
  | "redirects"
  | "safeBrowsing"
  | "urlhaus"
  | "ctLogs";

export type ProgressEvent =
  | { type: "section"; section: ScanSection; data: any; cacheAgeMs: number | null }
  | { type: "section-error"; section: ScanSection; message: string }
  | { type: "done" };

export type OnProgress = (event: ProgressEvent) => void;

export interface ScanOptions {
  noCache: boolean;
  checks: ScanConfig["checks"];
  premiumPlus?: boolean;
  ctSource?: CtSourcePref;
}

/** Run a cached check, returning data + age. Age is null on cache miss. */
async function cached<T>(
  key: string,
  noCache: boolean,
  fn: () => Promise<T>,
): Promise<{ data: T; cacheAgeMs: number | null }> {
  if (!noCache) {
    const hit = await cacheGetWithAge<T>(key);
    if (hit) return { data: hit.data, cacheAgeMs: hit.ageMs };
  }
  const result = await fn();
  await cacheSet(key, result, CACHE_TTL);
  return { data: result, cacheAgeMs: null };
}

/**
 * Await a check, emit `section` (with fallback on error) so the UI always
 * has something concrete to render.
 */
async function runAndEmit<T>(
  section: ScanSection,
  task: Promise<{ data: T; cacheAgeMs: number | null }>,
  onProgress: OnProgress,
  fallback: T,
): Promise<T> {
  try {
    const { data, cacheAgeMs } = await task;
    onProgress({ type: "section", section, data, cacheAgeMs });
    return data;
  } catch (err: any) {
    const message = err?.message || String(err);
    log.warn({ section, err: message }, "check failed");
    incr("check_error", { section });
    onProgress({ type: "section-error", section, message });
    onProgress({ type: "section", section, data: fallback, cacheAgeMs: null });
    return fallback;
  }
}

export async function runDomainScan(
  domain: string,
  opts: ScanOptions,
  onProgress: OnProgress,
  signal?: AbortSignal,
): Promise<void> {
  const { noCache, checks } = opts;
  const startedAt = Date.now();
  let outcome = "ok";
  try {

  // ─── Wave 0: infrastructure ──────────────────────────────────────────
  let infrastructure: InfrastructureResult | null = null;
  if (checks.blacklist || checks.ssl) {
    infrastructure = await runAndEmit<InfrastructureResult>(
      "infrastructure",
      cached(`infra:${domain}`, noCache, () => checkInfrastructure(domain, DNS_TIMEOUT)),
      onProgress,
      { ip: null, ips: [], resolverCount: 0, cdnProvider: null, cdnProviders: [], error: "Check failed" },
    );
  }
  if (signal?.aborted) { outcome = "aborted"; return; }

  // ─── Wave 1: parallel checks ─────────────────────────────────────────
  const wave1: Promise<any>[] = [];

  if (checks.spf) {
    wave1.push(
      runAndEmit(
        "spf",
        cached(`spf:${domain}`, noCache, () => checkSpf(domain, DNS_TIMEOUT)),
        onProgress,
        { status: "fail", record: null, validations: [], mechanisms: [], dnsLookupCount: 0, error: "Check failed" },
      ),
    );
  }

  if (checks.dmarc) {
    wave1.push(
      runAndEmit(
        "dmarc",
        cached(`dmarc:${domain}`, noCache, () => checkDmarc(domain, DNS_TIMEOUT)),
        onProgress,
        { status: "fail", record: null, validations: [], tags: [], error: "Check failed" },
      ),
    );
  }

  if (checks.dkim) {
    wave1.push(
      runAndEmit(
        "dkim",
        cached(`dkim:${domain}`, noCache, () => checkDkim(domain, DNS_TIMEOUT)),
        onProgress,
        { status: "info", foundCount: 0, totalChecked: 14, selectors: [] },
      ),
    );
  }

  if (checks.dnssec) {
    wave1.push(
      runAndEmit(
        "dnssec",
        cached(`dnssec:${domain}`, noCache, () => checkDnssec(domain, DNS_TIMEOUT)),
        onProgress,
        { status: "fail", enabled: false, error: "Check failed" },
      ),
    );
  }

  // CAA is also a Wave 2 input (CT logs). Share the promise so it runs once.
  let caaTask: Promise<CaaResult> | null = null;
  if (checks.caa || checks.ctLogs) {
    const task = runAndEmit(
      "caa",
      cached(`caa:${domain}`, noCache, () => checkCaa(domain, DNS_TIMEOUT)),
      onProgress,
      { status: "fail", records: [], error: "Check failed" },
    );
    caaTask = task;
    wave1.push(task);
  }

  if (checks.mx) {
    wave1.push(
      runAndEmit(
        "mx",
        cached(`mx:${domain}`, noCache, () => checkMx(domain, DNS_TIMEOUT)),
        onProgress,
        { status: "info", records: [] },
      ),
    );
  }

  if (checks.ns) {
    wave1.push(
      runAndEmit(
        "ns",
        cached(`ns:${domain}`, noCache, () => checkNs(domain, DNS_TIMEOUT)),
        onProgress,
        { status: "fail", nameservers: [], error: "Check failed" },
      ),
    );
  }

  if (checks.blacklist) {
    const primaryIp = infrastructure?.ip ?? null;
    wave1.push(
      runAndEmit(
        "blacklist",
        cached(`bl:${domain}`, noCache, () => checkBlacklist(domain, primaryIp, DNS_TIMEOUT)),
        onProgress,
        { status: "info", providers: [], error: "Check failed" },
      ),
    );
  }

  if (checks.danglingDns) {
    wave1.push(
      runAndEmit(
        "danglingDns",
        cached(`dng:${domain}`, noCache, () => checkDanglingDns(domain, DNS_TIMEOUT)),
        onProgress,
        { status: "info", records: [], danglingCount: 0, error: "Check failed" },
      ),
    );
  }

  if (checks.domainExpiry) {
    wave1.push(
      runAndEmit(
        "domainExpiry",
        cached(`exp:${domain}`, noCache, () => checkDomainExpiry(domain, HTTP_TIMEOUT)),
        onProgress,
        { status: "info", expirationDate: null, daysRemaining: null, error: "Check failed" },
      ),
    );
  }

  // Shared HTTP+TLS fetch for security.txt, headers, and primary cert.
  // One network round-trip serves three checks.
  let fetchTask: Promise<{ data: any; cacheAgeMs: number | null }> | null = null;
  if (checks.securityTxt || checks.headers || checks.ssl) {
    fetchTask = cached(`webfetch:${domain}`, noCache, () => safeFetchWithHeaders(domain, HTTP_TIMEOUT));
  }

  if (checks.securityTxt) {
    wave1.push(
      (async () => {
        try {
          const { data: fr, cacheAgeMs } = await fetchTask!;
          let securityTxt: SecurityTxtSection;
          if (fr && fr.success) {
            const parsed = parse(fr.content, { withPgp: true });
            const vr = validate(parsed.lines, {
              contentType: fr.contentType,
              fetchedFrom: fr.fetchedFrom,
              redirectChain: fr.redirectChain,
              wellKnownFound: fr.wellKnownFound,
              fallbackUsed: fr.fallbackUsed,
              usedHttps: true,
            }, parsed.pgp);
            securityTxt = {
              status: vr.status === "valid" ? "pass" : vr.status === "valid-with-warnings" ? "warn" : "fail",
              available: true,
              validationStatus: vr.status,
              errorCount: vr.errorCount,
              warningCount: vr.warningCount,
              findings: vr.findings.map((f: any) => ({ severity: f.severity, title: f.title, explanation: f.explanation })),
              fetchedFrom: fr.fetchedFrom,
            };
          } else {
            const errMsg = fr ? (fr as any).message || "Could not fetch security.txt" : "Could not fetch security.txt";
            securityTxt = { status: "fail", available: false, validationStatus: null, errorCount: 0, warningCount: 0, findings: [], fetchedFrom: null, error: errMsg };
          }
          onProgress({ type: "section", section: "securityTxt", data: securityTxt, cacheAgeMs });
        } catch (err: any) {
          incr("check_error", { section: "securityTxt" });
          onProgress({ type: "section-error", section: "securityTxt", message: err?.message || String(err) });
        }
      })(),
    );
  }

  if (checks.headers) {
    wave1.push(
      (async () => {
        try {
          const { data: fr, cacheAgeMs } = await fetchTask!;
          const rawHeaders = (fr as any)?.responseHeaders || null;
          const headers = rawHeaders && Object.keys(rawHeaders).length > 0
            ? await analyzeHeaders(rawHeaders)
            : { status: "info" as const, items: [] };
          onProgress({ type: "section", section: "headers", data: headers, cacheAgeMs });
        } catch (err: any) {
          incr("check_error", { section: "headers" });
          onProgress({ type: "section-error", section: "headers", message: err?.message || String(err) });
        }
      })(),
    );
  }

  // SSL is special: combine primary cert (from shared fetch) + multi-edge probe
  // (from infrastructure.ips) into one event so the UI only renders SSL once.
  let sslTask: Promise<SslResult | null> = Promise.resolve(null);
  if (checks.ssl) {
    const ipsForProbe = infrastructure?.ips ?? [];
    sslTask = (async () => {
      try {
        const { data: fr, cacheAgeMs } = await fetchTask!;
        const tlsCert = (fr as any)?.tlsCert || null;
        const chainCerts = (fr as any)?.chainCerts;
        const rawLeafCert = (fr as any)?.rawLeafCert;
        let ssl: SslResult;
        if (tlsCert) {
          ssl = analyzeSslDeep(tlsCert, chainCerts, rawLeafCert);
        } else {
          ssl = analyzeSsl(null);
        }
        if (ipsForProbe.length > 0) {
          try {
            const { data: edges } = await cached(
              `edges:${domain}`,
              noCache,
              () => probeMultiEdge(domain, ipsForProbe, HTTP_TIMEOUT),
            );
            ssl.edges = edges;
          } catch (err: any) {
            log.warn({ err: err?.message }, "edges probe failed");
          }
        }
        applyManagedCertPolicy(ssl, infrastructure?.cdnProvider);
        onProgress({ type: "section", section: "ssl", data: ssl, cacheAgeMs });
        return ssl;
      } catch (err: any) {
        incr("check_error", { section: "ssl" });
        onProgress({ type: "section-error", section: "ssl", message: err?.message || String(err) });
        return null;
      }
    })();
    wave1.push(sslTask);
  }

  if (checks.redirects) {
    wave1.push(
      runAndEmit(
        "redirects",
        cached(`redir:${domain}`, noCache, () => checkRedirects(domain, HTTP_TIMEOUT)),
        onProgress,
        { status: "info", httpsRedirect: false, wwwBehavior: null, items: [], error: "Check failed" },
      ),
    );
  }

  if (checks.reputation) {
    wave1.push(
      runAndEmit(
        "safeBrowsing",
        cached(`sb:${domain}`, noCache, () => checkSafeBrowsing(domain, DNS_TIMEOUT)),
        onProgress,
        { status: "info", safe: null, threats: [], error: "Check failed" },
      ),
    );
    wave1.push(
      runAndEmit(
        "urlhaus",
        cached(`uh:${domain}`, noCache, () => checkUrlhaus(domain, DNS_TIMEOUT)),
        onProgress,
        { status: "info", listed: false, urlCount: 0, error: "Check failed" },
      ),
    );
  }

  await Promise.allSettled(wave1);
  if (signal?.aborted) { outcome = "aborted"; return; }

  // ─── Wave 2: CT logs needs ssl.issuer + caa.records ──────────────────
  if (checks.ctLogs) {
    const ssl = await sslTask;
    const caa = caaTask ? await caaTask : null;
    const ctOpts: CtCheckOptions = {
      authenticated: !!opts.premiumPlus,
      sslIssuer: ssl?.issuer ?? null,
      caaRecords: caa?.records ?? [],
      ctSource: opts.ctSource,
    };
    const cacheKey = `ct:${domain}:${ctSourceTag(opts.ctSource)}:${opts.premiumPlus ? "s1" : "s0"}`;
    await runAndEmit(
      "ctLogs",
      cached(cacheKey, noCache, () => checkCtLogs(domain, ctOpts)),
      onProgress,
      { status: "info", totalCerts: 0, recentCerts: [], findings: [], source: "none", error: "Check failed" },
    );
  }

  onProgress({ type: "done" });
  } catch (err) {
    outcome = "error";
    throw err;
  } finally {
    incr("scan", { outcome });
    observe("scan_duration_ms", Date.now() - startedAt, { outcome });
  }
}
