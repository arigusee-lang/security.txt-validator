/**
 * Client-side security score calculator.
 * Mirrors server/scoreCalculator.ts logic but runs in the browser.
 *
 * Keep weights and scoring formulas in sync with the server file —
 * docs/scoring-revision.md is the source of truth.
 */

const WEIGHTS: Record<string, number> = {
  ssl: 18,
  headers: 15,
  caa: 5,
  danglingDns: 6,
  domainExpiry: 4,
  dnssec: 3,
  safeBrowsing: 8,
  blacklist: 5,
  urlhaus: 4,
  spf: 7,
  dmarc: 7,
  dkim: 0,
  mx: 0,
  ctLogs: 8,
  redirects: 5,
  securityTxt: 3,
  ns: 0,
};

function statusToPoints(status: string): number {
  if (status === "pass") return 1;
  if (status === "warn") return 0.5;
  if (status === "fail") return 0;
  return 1; // info
}

const SSL_SUB = { expiry: 6, chain: 5, edges: 4, ctChrome: 2, ctApple: 1 };

function sslPoints(ssl: any): number {
  // expiry
  const days = ssl.daysRemaining;
  let expiry = 0;
  if (days != null && days >= 0) {
    if (days <= 7) expiry = 0;
    else if (days <= 30) expiry = ssl.managedBy ? SSL_SUB.expiry : SSL_SUB.expiry * 0.5;
    else if (days <= 90) expiry = SSL_SUB.expiry * 0.85;
    else expiry = SSL_SUB.expiry;
  }
  const chain = statusToPoints(ssl.chainStatus ?? "info") * SSL_SUB.chain;
  const edges = ssl.edges?.consistency === "inconsistent" ? 0 : SSL_SUB.edges;
  const ctChrome = ssl.ct?.chromeStatus === "fail" ? 0 : SSL_SUB.ctChrome;
  const ctApple = ssl.ct?.appleStatus === "fail" ? 0 : SSL_SUB.ctApple;
  return expiry + chain + edges + ctChrome + ctApple;
}

function securityTxtPoints(result: any): number {
  if (!result.available) return 0;
  if (result.status === "pass") return WEIGHTS.securityTxt; // 3
  return Math.round(WEIGHTS.securityTxt * 0.667 * 100) / 100; // 2
}

export interface ClientScoreResult {
  total: number;
  breakdown: Record<string, { earned: number; max: number }>;
}

/**
 * Calculate score from the check results available on the client.
 * Returns null if not enough data (dns + web minimum).
 */
export function calculateClientScore(
  dns: any,
  web: any,
  expiry: any,
  redirects: any,
  reputation: any,
  ct: any,
): ClientScoreResult | null {
  if (!dns || !web) return null;

  const flat: Record<string, any> = {};

  if (dns.spf) flat.spf = dns.spf;
  if (dns.dmarc) flat.dmarc = dns.dmarc;
  if (dns.dkim) flat.dkim = dns.dkim;
  if (dns.dnssec) flat.dnssec = dns.dnssec;
  if (dns.caa) flat.caa = dns.caa;
  if (dns.mx) flat.mx = dns.mx;
  if (dns.ns) flat.ns = dns.ns;
  if (dns.blacklist) flat.blacklist = dns.blacklist;
  if (dns.danglingDns) flat.danglingDns = dns.danglingDns;

  if (web.securityTxt) flat.securityTxt = web.securityTxt;
  if (web.headers) flat.headers = web.headers;
  if (web.ssl) flat.ssl = web.ssl;

  if (expiry) flat.domainExpiry = expiry;
  if (redirects) flat.redirects = redirects;
  if (ct) flat.ctLogs = ct;
  if (reputation?.safeBrowsing) flat.safeBrowsing = reputation.safeBrowsing;
  if (reputation?.urlhaus) flat.urlhaus = reputation.urlhaus;

  const breakdown: Record<string, { earned: number; max: number }> = {};
  let total = 0;

  for (const [category, weight] of Object.entries(WEIGHTS)) {
    const result = flat[category];
    if (!result) continue;
    if (weight === 0) {
      breakdown[category] = { earned: 0, max: 0 };
      continue;
    }

    let earned: number;

    if (category === "ssl") {
      earned = sslPoints(result);
    } else if (category === "securityTxt") {
      earned = securityTxtPoints(result);
    } else if (category === "headers" && result.items?.length) {
      const sum = result.items.reduce((acc: number, item: any) => acc + statusToPoints(item.status), 0);
      earned = (sum / result.items.length) * weight;
    } else if ((category === "spf" || category === "dmarc") && result.validations?.length) {
      const sum = result.validations.reduce((acc: number, v: any) => acc + statusToPoints(v.status), 0);
      earned = (sum / result.validations.length) * weight;
    } else if (category === "redirects" && result.items?.length) {
      const sum = result.items.reduce((acc: number, item: any) => acc + statusToPoints(item.status), 0);
      earned = (sum / result.items.length) * weight;
    } else {
      earned = statusToPoints(result.status) * weight;
    }

    breakdown[category] = { earned: Math.round(earned * 100) / 100, max: weight };
    total += earned;
  }

  return { total: Math.round(total), breakdown };
}
