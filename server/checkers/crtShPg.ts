/**
 * crt.sh Postgres data source — the PRIMARY CT source for scans.
 *
 * crt.sh exposes a public read-only Postgres at `crt.sh:5432`, db `certwatch`,
 * user `guest` (no password). It serves the same dataset as the web/JSON API
 * but typically responds in 200ms–2s where the HTTP frontend often takes
 * 5–60s or 502s under load — which is why the HTTP frontend was dropped and
 * this mirror is now primary, with CertSpotter as the fallback.
 *
 * CLI:
 *   npx tsx server/checkers/crtShPg.ts <domain> [--subdomains]
 */

import pg from "pg";
import { fileURLToPath } from "node:url";
import type { CtLogEntry } from "../types.js";
import { createLogger } from "../lib/logger.js";
import { parseIssuerO, CT_MAX_CERTS, CT_RECENT_WINDOW_DAYS } from "./ctNormalize.js";

const log = createLogger("ct-pg");

let pool: pg.Pool | null = null;

function getPool(): pg.Pool {
  if (pool) return pool;
  pool = new pg.Pool({
    host: "crt.sh",
    port: 5432,
    database: "certwatch",
    user: "guest",
    max: 4,
    connectionTimeoutMillis: 8000,
    idleTimeoutMillis: 30000,
    // crt.sh runs behind a pgbouncer that rejects `statement_timeout` as a
    // startup parameter, so we set the timeout client-side. `query_timeout`
    // sends a cancel-request to the server when the local timer fires.
    // 30s gives mega-domains (e.g. x.com ~7s typical) headroom for load spikes
    // before failing over to CertSpotter; timeouts aren't retried, so this is
    // the single worst-case wait on the primary, not a multiple of it.
    query_timeout: 30000,
  });
  pool.on("error", (err) => log.warn({ err: err.message }, "crt.sh pg pool error"));
  return pool;
}

/**
 * crt.sh deprecated direct queries on `certificate_identity`; the supported
 * path is the `certificate_and_identities` view with a full-text-search
 * pre-filter `plainto_tsquery('certwatch', $1) @@ identities(c.certificate)`
 * — that hits the FTS index instead of a seq scan and is what crt.sh's own
 * web UI uses. The `lower(...) LIKE ...` predicate then filters the small
 * candidate set to exact match (and `%.domain` for subdomain mode).
 *
 * DISTINCT ON collapses multiple SAN rows per cert; the CASE picks the
 * best matching identity (exact > wildcard > anything-else) so the chosen
 * `name_value` is the most relevant one to the searched domain.
 *
 * The `not_after >= now() - $4 days` predicate keeps the query inside the same
 * recency window the shared finalizeCerts enforces — so we fetch only relevant
 * certs (valid + recently expired) instead of the full archive. finalizeCerts
 * still applies the authoritative window; this is the server-side optimisation.
 */
const SQL = `
  SELECT cert_id, issuer_name, name_value, not_before, not_after
  FROM (
    SELECT DISTINCT ON (cai.CERTIFICATE_ID)
      cai.CERTIFICATE_ID AS cert_id,
      ca.NAME AS issuer_name,
      cai.NAME_VALUE AS name_value,
      x509_notBefore(cai.CERTIFICATE) AS not_before,
      x509_notAfter(cai.CERTIFICATE) AS not_after
    FROM certificate_and_identities cai
    LEFT JOIN ca ON ca.ID = cai.ISSUER_CA_ID
    WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
      AND x509_notAfter(cai.CERTIFICATE) >= now() - make_interval(days => $4::int)
      AND (
        lower(cai.NAME_VALUE) = lower($1)
        OR lower(cai.NAME_VALUE) LIKE lower($2)
      )
    ORDER BY cai.CERTIFICATE_ID,
      CASE
        WHEN lower(cai.NAME_VALUE) = lower($1) THEN 0
        WHEN lower(cai.NAME_VALUE) = lower('*.' || $1) THEN 1
        ELSE 2
      END
  ) sub
  ORDER BY not_before DESC NULLS LAST
  LIMIT $3
`;

interface PgRow {
  cert_id: string;
  issuer_name: string | null;
  name_value: string;
  not_before: Date | null;
  not_after: Date | null;
}

export async function fetchFromCrtShPg(
  domain: string,
  authenticated: boolean,
  // Fetch with headroom: SQL DISTINCT ON only collapses SAN rows, so precert +
  // leaf pairs still count against this limit. The caller's shared finalizeCerts
  // collapses those and caps the result to CT_MAX_CERTS.
  limit = CT_MAX_CERTS * 2,
): Promise<{ certs: CtLogEntry[]; total: number }> {
  // When authenticated, second predicate also matches subdomains via the
  // reverse-index. Without authentication we pass the bare domain twice;
  // the OR collapses to an exact match and the second branch becomes a no-op.
  const subdomainPattern = authenticated ? `%.${domain}` : domain;
  const t0 = Date.now();
  const res = await getPool().query<PgRow>(SQL, [domain, subdomainPattern, limit, CT_RECENT_WINDOW_DAYS]);
  const elapsed = Date.now() - t0;

  const certs: CtLogEntry[] = res.rows.map((r) => ({
    id: String(r.cert_id),
    issuerName: parseIssuerO(r.issuer_name),
    commonName: r.name_value,
    notBefore: r.not_before ? r.not_before.toISOString() : "",
    notAfter: r.not_after ? r.not_after.toISOString() : "",
  }));

  log.info({ domain, authenticated, rows: certs.length, ms: elapsed }, "crt.sh pg fetch");
  return { certs, total: certs.length };
}

/** Close the connection pool. Call on graceful shutdown. */
export async function closeCrtShPgPool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

// CLI: `npx tsx server/checkers/crtShPg.ts <domain> [--subdomains]`
if (process.argv[1] && process.argv[1] === fileURLToPath(import.meta.url)) {
  const domain = process.argv[2];
  if (!domain) {
    console.error("usage: tsx server/checkers/crtShPg.ts <domain> [--subdomains]");
    process.exit(1);
  }
  const subdomains = process.argv.includes("--subdomains");
  fetchFromCrtShPg(domain, subdomains)
    .then(async (r) => {
      console.log(JSON.stringify({
        domain,
        subdomains,
        total: r.total,
        sample: r.certs.slice(0, 10),
      }, null, 2));
      await closeCrtShPgPool();
      process.exit(0);
    })
    .catch(async (e) => {
      console.error("error:", e?.message || e);
      await closeCrtShPgPool().catch(() => {});
      process.exit(1);
    });
}
