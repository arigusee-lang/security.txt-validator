import type {
  CheckStatus,
  DomainCheckResponse,
  ScoreBreakdown,
  ScoreResponse,
  SslResult,
  SecurityTxtSection,
} from "./types.js";

/**
 * Category weights for security scoring (total = 98 — 2 points headroom so a
 * perfect 100/100 requires every card green, including optional ones like
 * security.txt and CAA).
 *
 * MX, NS, DKIM weight 0 — they're informational only (presence facts that
 * cascade into other checks; DKIM detection via selector probing is too
 * false-negative-prone to drive the score). Kept in the dict for breakdown
 * visibility.
 *
 * See docs/scoring-revision.md for the rationale behind each weight.
 */
export const WEIGHTS: Record<string, number> = {
  // Web security (33)
  ssl: 18,
  headers: 15,
  // DNS & domain (18)
  caa: 5,
  danglingDns: 6,
  domainExpiry: 4,
  dnssec: 3,
  // Reputation (17)
  safeBrowsing: 8,
  blacklist: 5,
  urlhaus: 4,
  // Email (14)
  spf: 7,
  dmarc: 7,
  dkim: 0,
  mx: 0,
  // Web / supporting (16)
  ctLogs: 8,
  redirects: 5,
  securityTxt: 3,
  // Validity facts (no security signal — 0 weight, kept for breakdown)
  ns: 0,
};

/** Maps a CheckStatus to a numeric score: pass=1, warn=0.5, fail=0. info treated as pass (neutral). */
export function statusToPoints(status: CheckStatus): number {
  if (status === "pass") return 1;
  if (status === "warn") return 0.5;
  if (status === "fail") return 0;
  // "info" — category is informational / not applicable, treat as full points
  return 1;
}

// ── SSL sub-check derivation ────────────────────────────────────────────────
// SSL splits its 18-point budget across 5 sub-checks of very different
// severity. Each is derived from existing SslResult fields at score time —
// no new shape required.

const SSL_SUB_WEIGHTS = { expiry: 6, chain: 5, edges: 4, ctChrome: 2, ctApple: 1 } as const;

function sslExpiryPoints(ssl: SslResult): number {
  const days = ssl.daysRemaining;
  if (days == null || days < 0) return 0;          // expired or unknown
  if (days <= 7) return 0;                          // critical
  if (days <= 30) {
    return ssl.managedBy ? SSL_SUB_WEIGHTS.expiry : SSL_SUB_WEIGHTS.expiry * 0.5;
  }
  if (days <= 90) return SSL_SUB_WEIGHTS.expiry * 0.85; // early-nudge soft band
  return SSL_SUB_WEIGHTS.expiry;
}

function sslChainPoints(ssl: SslResult): number {
  return statusToPoints(ssl.chainStatus ?? "info") * SSL_SUB_WEIGHTS.chain;
}

function sslEdgesPoints(ssl: SslResult): number {
  // `inconsistent` → some edge serves an invalid cert → 0. Everything else
  // (consistent / rollout / unknown / no edges data) → full points.
  return ssl.edges?.consistency === "inconsistent" ? 0 : SSL_SUB_WEIGHTS.edges;
}

function sslCtChromePoints(ssl: SslResult): number {
  return ssl.ct?.chromeStatus === "fail" ? 0 : SSL_SUB_WEIGHTS.ctChrome;
}

function sslCtApplePoints(ssl: SslResult): number {
  return ssl.ct?.appleStatus === "fail" ? 0 : SSL_SUB_WEIGHTS.ctApple;
}

function sslPoints(ssl: SslResult): number {
  return sslExpiryPoints(ssl) + sslChainPoints(ssl) + sslEdgesPoints(ssl) + sslCtChromePoints(ssl) + sslCtApplePoints(ssl);
}

// ── security.txt custom scoring ─────────────────────────────────────────────
// Reward presence: a file that exists with validation issues is meaningfully
// better than no file at all (researchers can still extract a Contact line).
//   absent → 0    present → 2    present + fully valid → 3

function securityTxtPoints(result: SecurityTxtSection): number {
  if (!result.available) return 0;
  if (result.status === "pass") return WEIGHTS.securityTxt;        // 3
  return Math.round(WEIGHTS.securityTxt * 0.667 * 100) / 100;       // 2 (of 3)
}

/**
 * Calculates the security score from a full DomainCheckResponse.
 *
 * Special scoring paths:
 *   - `ssl`: 5 sub-checks (expiry, chain, edges, ctChrome, ctApple) summed
 *   - `securityTxt`: presence-weighted (0 / 2 / 3 points)
 *   - `headers`/`spf`/`dmarc`/`redirects`: averaged over items[]/validations[]
 *   - default: `statusToPoints(result.status) × weight`
 */
export function calculateScore(
  checkResults: Partial<DomainCheckResponse>,
): ScoreResponse {
  const breakdown: ScoreBreakdown = {};
  let total = 0;

  for (const [category, weight] of Object.entries(WEIGHTS)) {
    const result = (checkResults as Record<string, any>)[category];

    if (!result) continue;
    if (weight === 0) {
      // Informational-only category — visible in breakdown but doesn't move the score.
      breakdown[category] = { earned: 0, max: 0 };
      continue;
    }

    let earned: number;

    if (category === "ssl") {
      earned = sslPoints(result as SslResult);
    } else if (category === "securityTxt") {
      earned = securityTxtPoints(result as SecurityTxtSection);
    } else if (category === "headers" && Array.isArray(result.items)) {
      const items = result.items as { status: CheckStatus }[];
      earned = items.length === 0
        ? weight
        : (items.reduce((acc, item) => acc + statusToPoints(item.status), 0) / items.length) * weight;
    } else if ((category === "spf" || category === "dmarc") && Array.isArray(result.validations)) {
      const v = result.validations as { status: CheckStatus }[];
      earned = v.length === 0
        ? statusToPoints(result.status) * weight
        : (v.reduce((acc, x) => acc + statusToPoints(x.status), 0) / v.length) * weight;
    } else if (category === "redirects" && Array.isArray(result.items)) {
      const items = result.items as { status: CheckStatus }[];
      earned = items.length === 0
        ? statusToPoints(result.status) * weight
        : (items.reduce((acc, item) => acc + statusToPoints(item.status), 0) / items.length) * weight;
    } else {
      earned = statusToPoints(result.status) * weight;
    }

    breakdown[category] = { earned: Math.round(earned * 100) / 100, max: weight };
    total += earned;
  }

  return { total: Math.round(total), breakdown };
}
