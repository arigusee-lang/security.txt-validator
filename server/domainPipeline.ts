/**
 * Programmatic domain check pipeline — reusable by batch scanner and scheduler.
 * Mirrors the logic in server/routes/domainCheck.ts but returns a DomainCheckResponse
 * directly instead of sending HTTP responses.
 */
import { performance } from "node:perf_hooks";
import { createLogger } from "./lib/logger.js";
import { safeFetchWithHeaders } from "./lib/safeFetch.js";
import { ssrfSafeFetch, ssrfSafeTlsConnect } from "./lib/ipCheck.js";
import { cacheGet, cacheSet } from "./lib/cache.js";
import { analyzeHeaders } from "./checkers/headersAnalyzer.js";
import { checkSpf } from "./checkers/spfChecker.js";
import { checkDmarc } from "./checkers/dmarcChecker.js";
import { checkDkim } from "./checkers/dkimChecker.js";
import { checkDnssec } from "./checkers/dnssecChecker.js";
import { checkCaa } from "./checkers/caaChecker.js";
import { checkMx } from "./checkers/mxChecker.js";
import { checkNs } from "./checkers/nsChecker.js";
import { analyzeSsl, analyzeSslDeep, applyManagedCertPolicy } from "./checkers/sslChecker.js";
import type { ChainCertInfo } from "./checkers/sslChecker.types.js";
import { probeMultiEdge } from "./lib/tlsEdgeProbe.js";
import { checkDomainExpiry } from "./checkers/domainExpiryChecker.js";
import { checkBlacklist } from "./checkers/blacklistChecker.js";
import { checkInfrastructure } from "./checkers/infrastructureChecker.js";
import { checkCtLogs, ctSourceTag } from "./checkers/ctLogsChecker.js";
import { checkRedirects } from "./checkers/redirectChecker.js";
import { checkSafeBrowsing } from "./checkers/safeBrowsingChecker.js";
import { checkUrlhaus } from "./checkers/urlhausChecker.js";
import { checkDanglingDns } from "./checkers/danglingDnsChecker.js";
import { parse } from "../src/lib/parser.js";
import { validate } from "../src/lib/validator.js";
import type { DomainCheckResponse, ScanConfig, CtCheckOptions, SslResult } from "./types.js";

const DNS_TIMEOUT = 8000;
const HTTP_TIMEOUT = 15000;
const CACHE_TTL = 15 * 60 * 1000;

const log = createLogger("scan");

/** Helper: run a checker with caching */
async function cached<T>(key: string, noCache: boolean, fn: () => Promise<T>): Promise<T> {
  if (!noCache) {
    const hit = await cacheGet<T>(key);
    if (hit) return hit;
  }
  const result = await fn();
  await cacheSet(key, result, CACHE_TTL);
  return result;
}

function settled<T>(s: PromiseSettledResult<T>, fallback: T): T {
  return s.status === "fulfilled" ? s.value : fallback;
}

/** Record per-checker durations into a shared map so the scan-summary log can include them. */
function timed<T>(timings: Record<string, number>, name: string, fn: () => Promise<T>): Promise<T> {
  const start = performance.now();
  return fn().finally(() => {
    timings[name] = Math.round(performance.now() - start);
  });
}

/**
 * Runs the full domain check pipeline programmatically.
 * Returns a complete DomainCheckResponse — same data as the HTTP endpoints produce.
 */
export async function runDomainCheck(
  domain: string,
  config: ScanConfig,
): Promise<DomainCheckResponse> {
  const nc = config.noCache;
  const checks = config.checks;
  const scanStart = performance.now();
  const timings: Record<string, number> = {};

  // --- Infrastructure: resolve + CDN detect (runs first — blacklist DNSBL,
  //     multi-edge TLS probe, and CDN-managed cert detect all depend on it) ---
  const infrastructure = checks.blacklist || checks.ssl
    ? await timed(timings, "infrastructure", () =>
        cached(`infra:${domain}`, nc, () => checkInfrastructure(domain, DNS_TIMEOUT)),
      )
    : null;
  const infraIp = infrastructure?.ip ?? null;

  // --- DNS checks (parallel) ---
  const dnsPromises = await Promise.allSettled([
    checks.spf ? timed(timings, "spf", () => cached(`spf:${domain}`, nc, () => checkSpf(domain, DNS_TIMEOUT))) : Promise.resolve(null),
    checks.dmarc ? timed(timings, "dmarc", () => cached(`dmarc:${domain}`, nc, () => checkDmarc(domain, DNS_TIMEOUT))) : Promise.resolve(null),
    checks.dkim ? timed(timings, "dkim", () => cached(`dkim:${domain}`, nc, () => checkDkim(domain, DNS_TIMEOUT))) : Promise.resolve(null),
    checks.dnssec ? timed(timings, "dnssec", () => cached(`dnssec:${domain}`, nc, () => checkDnssec(domain, DNS_TIMEOUT))) : Promise.resolve(null),
    checks.caa ? timed(timings, "caa", () => cached(`caa:${domain}`, nc, () => checkCaa(domain, DNS_TIMEOUT))) : Promise.resolve(null),
    checks.mx ? timed(timings, "mx", () => cached(`mx:${domain}`, nc, () => checkMx(domain, DNS_TIMEOUT))) : Promise.resolve(null),
    checks.ns ? timed(timings, "ns", () => cached(`ns:${domain}`, nc, () => checkNs(domain, DNS_TIMEOUT))) : Promise.resolve(null),
    checks.blacklist ? timed(timings, "blacklist", () => cached(`bl:${domain}`, nc, () => checkBlacklist(domain, infraIp, DNS_TIMEOUT))) : Promise.resolve(null),
    checks.danglingDns ? timed(timings, "danglingDns", () => cached(`dng:${domain}`, nc, () => checkDanglingDns(domain, DNS_TIMEOUT))) : Promise.resolve(null),
  ]);

  const [spfR, dmarcR, dkimR, dnssecR, caaR, mxR, nsR, blacklistR, danglingDnsR] = dnsPromises;

  const spf = settled(spfR, null) ?? { status: "fail" as const, record: null, validations: [], mechanisms: [], dnsLookupCount: 0, error: "Check failed" };
  const dmarc = settled(dmarcR, null) ?? { status: "fail" as const, record: null, validations: [], tags: [], error: "Check failed" };
  const dkim = settled(dkimR, null) ?? { status: "info" as const, foundCount: 0, totalChecked: 14, selectors: [] };
  const dnssec = settled(dnssecR, null) ?? { status: "fail" as const, enabled: false, error: "Check failed" };
  const caa = settled(caaR, null) ?? { status: "fail" as const, records: [], error: "Check failed" };
  const mx = settled(mxR, null) ?? { status: "info" as const, records: [] };
  const ns = settled(nsR, null) ?? { status: "fail" as const, nameservers: [], error: "Check failed" };
  const blacklist = settled(blacklistR, null) ?? { status: "info" as const, providers: [], error: "Check failed" };
  const danglingDns = settled(danglingDnsR, null) ?? { status: "info" as const, records: [], danglingCount: 0, error: "Check failed" };

  // --- Web checks (parallel) ---
  const webPromises = await Promise.allSettled([
    checks.securityTxt
      ? timed(timings, "securityTxt", () => cached(`fetch:${domain}`, nc, () => safeFetchWithHeaders(domain, HTTP_TIMEOUT)))
      : Promise.resolve(null),
    checks.headers
      ? timed(timings, "headers", () => cached(`hdrs:${domain}`, nc, async () => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT);
          try {
            const headRes = await ssrfSafeFetch(`https://${domain}/`, {
              method: "HEAD",
              signal: controller.signal,
              redirect: "follow",
              headers: { "User-Agent": "security-txt-validator/1.0" },
            });
            clearTimeout(timer);
            const h: Record<string, string> = {};
            headRes.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
            return h;
          } catch {
            clearTimeout(timer);
            return null;
          }
        }))
      : Promise.resolve(null),
    checks.ssl
      ? timed(timings, "ssl", () => cached(`tls:${domain}`, nc, async () => {
          return new Promise<any>(async (resolve) => {
            try {
              const socket = await ssrfSafeTlsConnect(
                { host: domain, port: 443, servername: domain, timeout: HTTP_TIMEOUT, rejectUnauthorized: false },
              );

              // Get detailed cert (with issuerCertificate linked list) and basic cert (with raw Buffer)
              let detailedCert: any;
              let basicCert: any;
              try {
                detailedCert = socket.getPeerCertificate(true);
                basicCert = socket.getPeerCertificate(false);
              } catch {
                detailedCert = null;
                basicCert = null;
              }
              socket.destroy();

              const cert = detailedCert || basicCert;
              if (!cert || !cert.valid_from) { resolve(null); return; }

              const validFrom = new Date(cert.valid_from).toISOString();
              const validTo = new Date(cert.valid_to).toISOString();
              const daysRemaining = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
              const sans: string[] = cert.subjectaltname
                ? cert.subjectaltname.split(",").map((s: string) => s.trim().replace(/^DNS:/, ""))
                : [];

              // Walk issuerCertificate linked list → ChainCertInfo[] with cycle detection
              let chainCerts: ChainCertInfo[] | undefined;
              try {
                if (detailedCert) {
                  chainCerts = [];
                  let current = detailedCert;
                  const seen = new Set<string>();
                  while (current && current.fingerprint256 && !seen.has(current.fingerprint256)) {
                    seen.add(current.fingerprint256);
                    const subjectCN = String(current.subject?.CN || "Unknown");
                    const issuerStr = String(current.issuer?.O || current.issuer?.CN || "Unknown");
                    const isSelfSigned = (current.subject?.CN === current.issuer?.CN)
                      && (current.subject?.O === current.issuer?.O);
                    chainCerts.push({
                      subject: subjectCN,
                      issuer: issuerStr,
                      validFrom: new Date(current.valid_from).toISOString(),
                      validTo: new Date(current.valid_to).toISOString(),
                      isSelfSigned,
                      role: "leaf", // roles assigned by validateChain
                    });
                    current = current.issuerCertificate;
                  }
                }
              } catch {
                chainCerts = undefined;
              }

              // Extract raw Buffer for SCT parsing
              let rawLeafCert: Buffer | undefined;
              try {
                if (basicCert?.raw) {
                  rawLeafCert = basicCert.raw;
                }
              } catch {
                rawLeafCert = undefined;
              }

              resolve({
                issuer: String(cert.issuer?.O || cert.issuer?.CN || "Unknown"),
                subject: String(cert.subject?.CN || "Unknown"),
                validFrom, validTo, daysRemaining, sans,
                chainCerts,
                rawLeafCert,
              });
            } catch { resolve(null); }
          });
        }))
      : Promise.resolve(null),
    checks.ssl && (infrastructure?.ips.length ?? 0) > 0
      ? timed(timings, "edges", () => cached(`edges:${domain}`, nc, () => probeMultiEdge(domain, infrastructure!.ips, HTTP_TIMEOUT)))
      : Promise.resolve(null),
  ]);

  const [fetchResultR, headersResultR, tlsCertR, edgesR] = webPromises;

  // Build security.txt section
  let securityTxt: DomainCheckResponse["securityTxt"];
  const fr = settled(fetchResultR, null);
  if (fr && (fr as any).success) {
    const successFr = fr as any;
    const parsed = parse(successFr.content, { withPgp: true });
    const vr = validate(parsed.lines, {
      contentType: successFr.contentType,
      fetchedFrom: successFr.fetchedFrom,
      redirectChain: successFr.redirectChain,
      wellKnownFound: successFr.wellKnownFound,
      fallbackUsed: successFr.fallbackUsed,
      usedHttps: true,
    }, parsed.pgp);
    securityTxt = {
      status: vr.status === "valid" ? "pass" : vr.status === "valid-with-warnings" ? "warn" : "fail",
      available: true,
      validationStatus: vr.status,
      errorCount: vr.errorCount,
      warningCount: vr.warningCount,
      findings: vr.findings.map((f: any) => ({ severity: f.severity, title: f.title, explanation: f.explanation })),
      fetchedFrom: successFr.fetchedFrom,
    };
  } else {
    const errMsg = fr ? (fr as any).message || "Could not fetch security.txt" : "Could not fetch security.txt";
    securityTxt = {
      status: "fail", available: false, validationStatus: null,
      errorCount: 0, warningCount: 0, findings: [], fetchedFrom: null, error: errMsg,
    };
  }

  // Build headers
  const rawHeaders = settled(headersResultR, null) as Record<string, string> | null;
  const headers = rawHeaders ? await analyzeHeaders(rawHeaders, domain) : { status: "info" as const, items: [] };

  // Build SSL
  const tlsCertData = settled(tlsCertR, null) as any;
  let ssl: SslResult;
  if (tlsCertData) {
    const { chainCerts, rawLeafCert, ...certInfo } = tlsCertData;
    ssl = analyzeSslDeep(certInfo, chainCerts, rawLeafCert);
  } else {
    ssl = analyzeSsl(null);
  }
  const edgesResult = settled(edgesR, null) as SslResult["edges"] | null;
  if (edgesResult) {
    ssl.edges = edgesResult;
  }
  applyManagedCertPolicy(ssl, infrastructure?.cdnProvider);

  // --- Additional checks (parallel) ---
  // Build CtCheckOptions from SSL and CAA results (available from earlier waves)
  // Subdomain CT is a premium-tier feature; cache key must reflect the mode
  // so anonymous and premium-cached results don't poison each other.
  const wantSubdomains = !!config.authenticated;
  const ctOpts: CtCheckOptions = {
    authenticated: wantSubdomains,
    sslIssuer: ssl?.issuer ?? null,
    caaRecords: caa?.records ?? [],
    ctSource: config.ctSource,
  };

  const extraPromises = await Promise.allSettled([
    checks.domainExpiry ? timed(timings, "domainExpiry", () => cached(`exp:${domain}`, nc, () => checkDomainExpiry(domain, HTTP_TIMEOUT))) : Promise.resolve(null),
    checks.ctLogs ? timed(timings, "ctLogs", () => cached(`ct:${domain}:${ctSourceTag(config.ctSource)}:${wantSubdomains ? "s1" : "s0"}`, nc, () => checkCtLogs(domain, ctOpts))) : Promise.resolve(null),
    checks.redirects ? timed(timings, "redirects", () => cached(`redir:${domain}`, nc, () => checkRedirects(domain, HTTP_TIMEOUT))) : Promise.resolve(null),
    checks.reputation ? timed(timings, "safeBrowsing", () => cached(`sb:${domain}`, nc, () => checkSafeBrowsing(domain, DNS_TIMEOUT))) : Promise.resolve(null),
    checks.reputation ? timed(timings, "urlhaus", () => cached(`uh:${domain}`, nc, () => checkUrlhaus(domain, DNS_TIMEOUT))) : Promise.resolve(null),
  ]);

  const [domainExpiryR, ctLogsR, redirectsR, safeBrowsingR, urlhausR] = extraPromises;

  const domainExpiry = settled(domainExpiryR, null) ?? { status: "info" as const, expirationDate: null, daysRemaining: null, error: "Check failed" };
  const ctLogs = settled(ctLogsR, null) ?? { status: "info" as const, totalCerts: 0, recentCerts: [], error: "Check failed" };
  const redirects = settled(redirectsR, null) ?? { status: "info" as const, httpsRedirect: false, wwwBehavior: null, items: [], error: "Check failed" };
  const safeBrowsing = settled(safeBrowsingR, null) ?? { status: "info" as const, safe: null, threats: [], error: "Check failed" };
  const urlhaus = settled(urlhausR, null) ?? { status: "info" as const, listed: false, urlCount: 0, error: "Check failed" };

  const checkerResults: Record<string, { status?: string }> = {
    spf, dmarc, dkim, dnssec, caa, mx, ns, blacklist, danglingDns,
    securityTxt, headers, ssl,
    domainExpiry, ctLogs, redirects, safeBrowsing, urlhaus,
  };
  const summary = { pass: 0, warn: 0, fail: 0, info: 0 };
  const checkers: Record<string, { status: string; durationMs: number | null }> = {};
  for (const [name, r] of Object.entries(checkerResults)) {
    const status = r?.status ?? "info";
    if (status in summary) summary[status as keyof typeof summary]++;
    checkers[name] = { status, durationMs: timings[name] ?? null };
  }

  log.info(
    {
      domain,
      durationMs: Math.round(performance.now() - scanStart),
      authenticated: !!config.authenticated,
      noCache: nc,
      summary,
      checkers,
    },
    "scan completed",
  );

  return {
    domain,
    timestamp: new Date().toISOString(),
    securityTxt,
    headers,
    spf,
    dmarc,
    dkim,
    dnssec,
    caa,
    mx,
    ns,
    ssl,
    domainExpiry,
    infrastructure: infrastructure ?? undefined,
    blacklist,
    ctLogs,
    redirects,
    safeBrowsing,
    urlhaus,
    danglingDns,
  } as DomainCheckResponse;
}
