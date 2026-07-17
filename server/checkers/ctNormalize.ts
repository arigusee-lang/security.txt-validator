/**
 * Shared CT-entry normalization used by ALL three sources (CertSpotter, crt.sh
 * Postgres mirror, crt.sh HTTP).
 *
 * The sources return data in different shapes and with different built-in
 * dedup/limit behaviour. To keep downstream processing and display identical
 * regardless of source, every fetcher maps its rows to bare `CtLogEntry[]` and
 * then runs them through `finalizeCerts` here — one dedup rule, one sort, one
 * cap. Third parties may legitimately return different *data*, but our handling
 * of it is uniform.
 */

import type { CtLogEntry } from "../types.js";

/**
 * Max certs we keep for analysis/display, applied uniformly across sources.
 * Recent-first, so the cap drops the oldest rows, not the relevant ones. With
 * the recency window below this is just a safety backstop — most domains have
 * far fewer relevant certs.
 */
export const CT_MAX_CERTS = 500;

/**
 * Relevance window. This is a point-in-time security scan, so we keep certs that
 * can still authenticate as the domain (not expired) plus those that expired
 * recently (a just-expired misissuance is still worth surfacing). Anything older
 * is archival history — out of scope here; ongoing detection is the monitoring
 * service's job.
 *
 * This also makes the three sources converge: CertSpotter only returns a recent
 * window for non-monitored domains anyway, and crt.sh holds the full archive —
 * filtering to this window lines them up.
 */
export const CT_RECENT_WINDOW_DAYS = 30;

/**
 * Extract Organization (O=) from a certificate issuer DN.
 *
 * crt.sh (both HTTP and PG) returns the issuer as a full DN string
 * ("C=US, O=Let's Encrypt, CN=E8") — unreadable in the UI and bad for dedup
 * (same root, different intermediate CN ⇒ different DN). CertSpotter usually
 * gives a friendly_name, but its `name` fallback is also DN-shaped. We use the
 * O= field as the human-friendly issuer everywhere.
 *
 * Note: DN attributes can be RFC 4514 escaped (e.g. `O=Foo\, Inc.`) — we don't
 * handle that edge case; for the public-CA universe O= values rarely contain
 * commas.
 */
export function parseIssuerO(rawIssuer: string | undefined | null): string {
  if (!rawIssuer) return "Unknown";
  // Not DN-shaped (no "ATTR=" pattern) — assume it's already a friendly name.
  if (!/[A-Za-z]+=/.test(rawIssuer)) return rawIssuer;
  for (const part of rawIssuer.split(/,\s*/)) {
    if (/^o=/i.test(part)) {
      return part.substring(2).trim().replace(/^"|"$/g, "");
    }
  }
  return rawIssuer;
}

/** Pick the best name from a SAN list — prefer exact match, then wildcard, then any subdomain. */
export function pickBestName(names: string[] | undefined, domain: string): string {
  if (!names || names.length === 0) return domain;
  const exact = names.find((n) => n === domain);
  if (exact) return exact;
  const wc = names.find((n) => n === `*.${domain}`);
  if (wc) return wc;
  const sub = names.find((n) => n.endsWith(`.${domain}`));
  if (sub) return sub;
  return names[0];
}

/**
 * Collapse ONLY true duplicates — never hide a genuinely distinct certificate.
 *
 * A precertificate and its final certificate (RFC 6962) are the same logical
 * cert: identical name, issuer, and validity window (notBefore/notAfter), only
 * differing by the poison extension / SCT. crt.sh stores them as two separate
 * `certificate_id`s, so a PG fetch shows visual duplicates; CertSpotter and the
 * crt.sh HTTP API hide them. We unify on the full-validity key so that:
 *   - precert + leaf (identical on every displayed field) collapse to one row;
 *   - same-day RE-issuances (different notBefore time ⇒ different cert) are KEPT.
 *
 * The key uses full ISO timestamps, not a date prefix, precisely so a real
 * second cert issued the same day is not silently dropped. Within a single
 * source the timestamp format is consistent, so precert/leaf reliably match.
 */
export function dedupeCerts(certs: CtLogEntry[]): CtLogEntry[] {
  const seen = new Set<string>();
  const out: CtLogEntry[] = [];
  for (const c of certs) {
    const key = `${c.commonName}|${c.notBefore}|${c.notAfter}|${c.issuerName}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }
  return out;
}

/**
 * One pipeline for every source: dedup true duplicates → drop certs older than
 * the recency window → sort recent-first → cap. `total` is the unique relevant
 * cert count (pre-cap) so the UI reports a real, source-independent number;
 * `certs` is the capped slice used for analysis and display.
 */
export function finalizeCerts(certs: CtLogEntry[]): { certs: CtLogEntry[]; total: number } {
  const cutoff = Date.now() - CT_RECENT_WINDOW_DAYS * 24 * 60 * 60 * 1000;
  const relevant = dedupeCerts(certs).filter((c) => {
    const expiry = new Date(c.notAfter).getTime();
    // Keep if still valid or expired within the window. Unparseable notAfter is
    // kept rather than silently dropped — never hide a cert on a parse failure.
    return !Number.isFinite(expiry) || expiry >= cutoff;
  });
  relevant.sort((a, b) => (b.notBefore || "").localeCompare(a.notBefore || ""));
  return { certs: relevant.slice(0, CT_MAX_CERTS), total: relevant.length };
}
