import crypto from "node:crypto";
import type Database from "better-sqlite3";
import type { Worker, Job } from "bullmq";
import { ssrfSafeTlsConnect } from "./lib/ipCheck.js";
import { ssrfSafeFetch } from "./lib/ipCheck.js";
import { analyzeSsl } from "./checkers/sslChecker.js";
import { checkDomainExpiry } from "./checkers/domainExpiryChecker.js";
import { checkCtLogs } from "./checkers/ctLogsChecker.js";
import { checkBlacklist } from "./checkers/blacklistChecker.js";
import { checkInfrastructure } from "./checkers/infrastructureChecker.js";
import { checkCaa } from "./checkers/caaChecker.js";
import { checkDnssec } from "./checkers/dnssecChecker.js";
import { analyzeHeaders } from "./checkers/headersAnalyzer.js";
import { safeFetch } from "./lib/safeFetch.js";
import { parse } from "../src/lib/parser.js";
import type {
  MonitorType, MonitorJobData, DetectedChange, AlertSeverity,
  MonitorRow, MonitorStateRow, DomainCheckStateRow,
  SSL_THRESHOLDS, DOMAIN_THRESHOLDS, SECURITY_TXT_THRESHOLDS,
} from "./monitoringTypes.js";
import {
  SSL_THRESHOLDS as sslThresholds,
  DOMAIN_THRESHOLDS as domainThresholds,
  SECURITY_TXT_THRESHOLDS as secTxtThresholds,
  MONITOR_INTERVALS,
} from "./monitoringTypes.js";
import type { AlertDispatcher } from "./alertDispatcher.js";
import { QUEUE_NAME } from "./monitoringService.js";
import { createLogger } from "./lib/logger.js";
import { incr, observe } from "./lib/metrics.js";

const log = createLogger("monitoring-worker");

// ── Check wrapper functions (Task 6) ──

export async function checkSslForMonitor(domain: string): Promise<{ daysRemaining: number | null; validTo: string | null; issuer: string | null; chromeCtPass: boolean | null; appleCtPass: boolean | null }> {
  try {
    const socket = await ssrfSafeTlsConnect({ host: domain, port: 443, servername: domain, timeout: 15000, rejectUnauthorized: false });
    const detailedCert = socket.getPeerCertificate(true);
    const basicCert = socket.getPeerCertificate(false);
    socket.destroy();
    const cert = detailedCert || basicCert;
    if (!cert || !cert.valid_from) return { daysRemaining: null, validTo: null, issuer: null, chromeCtPass: null, appleCtPass: null };
    const validTo = new Date(cert.valid_to).toISOString();
    const validFrom = new Date(cert.valid_from).toISOString();
    const daysRemaining = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
    const issuer = String(cert.issuer?.O || cert.issuer?.CN || "Unknown");
    // CT policy check from raw cert
    let chromeCtPass: boolean | null = null;
    let appleCtPass: boolean | null = null;
    try {
      if (basicCert?.raw) {
        const { checkCtPolicy } = await import("./checkers/sslChecker.js");
        const lifetime = Math.floor((new Date(cert.valid_to).getTime() - new Date(cert.valid_from).getTime()) / 86400000);
        const ct = checkCtPolicy(basicCert.raw, lifetime);
        chromeCtPass = ct.chromeStatus === "pass";
        appleCtPass = ct.appleStatus === "pass";
      }
    } catch { /* CT check is best-effort */ }
    return { daysRemaining, validTo, issuer, chromeCtPass, appleCtPass };
  } catch {
    return { daysRemaining: null, validTo: null, issuer: null, chromeCtPass: null, appleCtPass: null };
  }
}

export async function checkDomainExpiryForMonitor(domain: string): Promise<{ daysRemaining: number | null; expirationDate: string | null }> {
  const result = await checkDomainExpiry(domain, 15000);
  return { daysRemaining: result.daysRemaining, expirationDate: result.expirationDate };
}

export async function checkCtLogsForMonitor(domain: string, db?: import("better-sqlite3").Database): Promise<{ recentCerts: unknown[]; findings: unknown[]; totalCerts: number; lastCertSpotterId?: string }> {
  let caaRecords: Array<{ tag: string; value: string }> | undefined;
  let sslIssuer: string | null = null;
  let startAfterId: string | undefined;
  if (db) {
    const caaState = db.prepare("SELECT result_json FROM domain_check_state WHERE domain = ? AND check_type = 'caa_dnssec'").get(domain) as { result_json: string } | undefined;
    if (caaState) { try { caaRecords = JSON.parse(caaState.result_json).caaRecords; } catch {} }
    const sslState = db.prepare("SELECT result_json FROM domain_check_state WHERE domain = ? AND check_type = 'ssl_expiry'").get(domain) as { result_json: string } | undefined;
    if (sslState) { try { sslIssuer = JSON.parse(sslState.result_json).issuer; } catch {} }
    const ctState = db.prepare("SELECT last_cursor FROM domain_check_state WHERE domain = ? AND check_type = 'ct_logs'").get(domain) as { last_cursor: string | null } | undefined;
    if (ctState?.last_cursor) { startAfterId = ctState.last_cursor; }
  }
  const result = await checkCtLogs(domain, { timeout: 30000, caaRecords: caaRecords as any, sslIssuer, startAfterId } as any);
  return { recentCerts: result.recentCerts, findings: result.findings, totalCerts: result.totalCerts, lastCertSpotterId: result.lastCertSpotterId };
}

export async function checkSecurityTxtExpiryForMonitor(domain: string): Promise<{ daysRemaining: number | null; expiresDate: string | null; available: boolean }> {
  const fetchResult = await safeFetch(domain);
  if (!fetchResult.success) return { daysRemaining: null, expiresDate: null, available: false };
  const parsed = parse(fetchResult.content, { withPgp: false });
  const expiresLine = parsed.lines.find(l => l.field?.toLowerCase() === "expires");
  if (!expiresLine?.value) return { daysRemaining: null, expiresDate: null, available: true };
  try {
    const expiresDate = new Date(expiresLine.value).toISOString();
    const daysRemaining = Math.floor((new Date(expiresLine.value).getTime() - Date.now()) / 86400000);
    return { daysRemaining, expiresDate, available: true };
  } catch {
    return { daysRemaining: null, expiresDate: null, available: true };
  }
}

export async function checkBlacklistForMonitor(domain: string): Promise<{ providers: Array<{ provider: string; listed: boolean; type: string }> }> {
  // After Phase A: blacklist no longer resolves the domain itself. Run
  // infrastructure first to get the primary IP for IP-DNSBL.
  const infra = await checkInfrastructure(domain, 10000);
  const result = await checkBlacklist(domain, infra.ip, 10000);
  return { providers: result.providers.map(p => ({ provider: p.provider, listed: p.listed, type: p.type })) };
}

export async function checkCaaDnssecForMonitor(domain: string): Promise<{ caaRecords: Array<{ tag: string; value: string }>; dnssecEnabled: boolean }> {
  const [caaResult, dnssecResult] = await Promise.all([checkCaa(domain, 10000), checkDnssec(domain, 10000)]);
  return {
    caaRecords: caaResult.records.map(r => ({ tag: r.tag, value: r.value })),
    dnssecEnabled: dnssecResult.enabled,
  };
}

export async function checkHeadersForMonitor(domain: string): Promise<{ items: Array<{ name: string; present: boolean; value: string }> }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    const res = await ssrfSafeFetch(`https://${domain}/`, {
      method: "HEAD", signal: controller.signal, redirect: "follow",
      headers: { "User-Agent": "security-txt-validator/1.0" },
    });
    clearTimeout(timer);
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
    const analyzed = analyzeHeaders(h);
    return { items: analyzed.items.map(i => ({ name: i.name, present: i.present, value: i.value })) };
  } catch {
    return { items: [] };
  }
}

const CHECKER_MAP: Record<MonitorType, (domain: string, db?: import("better-sqlite3").Database) => Promise<unknown>> = {
  ssl_expiry: (d) => checkSslForMonitor(d),
  domain_expiry: (d) => checkDomainExpiryForMonitor(d),
  ct_logs: (d, db) => checkCtLogsForMonitor(d, db),
  security_txt_expiry: (d) => checkSecurityTxtExpiryForMonitor(d),
  blacklist: (d) => checkBlacklistForMonitor(d),
  caa_dnssec: (d) => checkCaaDnssecForMonitor(d),
  headers: (d) => checkHeadersForMonitor(d),
};

// ── State comparison logic (Task 7) ──

// Recursively stringify with sorted object keys so the same data always
// produces the same hash regardless of insertion order. Arrays preserve
// their order — checkers are responsible for emitting deterministic arrays.
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const keys = Object.keys(value as object).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + stableStringify((value as Record<string, unknown>)[k])).join(",") + "}";
}

export function computeHash(result: unknown): string {
  return crypto.createHash("sha256").update(stableStringify(result)).digest("hex");
}

export function checkThresholds(
  daysRemaining: number | null,
  thresholds: Array<{ days: number; severity: AlertSeverity }>,
  firedThresholds: Record<string, boolean>,
): Array<{ threshold: number; severity: AlertSeverity }> {
  if (daysRemaining === null) return [];
  // Find the tightest (smallest) threshold that applies and hasn't fired yet
  const sorted = [...thresholds].sort((a, b) => a.days - b.days);
  for (const { days, severity } of sorted) {
    if (daysRemaining <= days && !firedThresholds[String(days)]) {
      // Fire only this one — the most urgent unfired threshold
      return [{ threshold: days, severity }];
    }
  }
  return [];
}

export function compareCtLogsState(
  prev: { recentCerts: any[]; findings: any[]; totalCerts: number } | null,
  curr: { recentCerts: any[]; findings: any[]; totalCerts: number },
): DetectedChange[] {
  if (!prev) return [];
  const changes: DetectedChange[] = [];
  const prevCertKeys = new Set(prev.recentCerts.map((c: any) => `${c.commonName}|${c.notBefore}|${c.issuerName}`));
  for (const cert of curr.recentCerts) {
    const key = `${(cert as any).commonName}|${(cert as any).notBefore}|${(cert as any).issuerName}`;
    if (!prevCertKeys.has(key)) {
      changes.push({
        severity: "info",
        title: `New certificate detected: ${(cert as any).commonName}`,
        description: `Issued by ${(cert as any).issuerName}, valid from ${(cert as any).notBefore}`,
        previousValue: null,
        currentValue: cert,
      });
    }
  }
  return changes;
}

export function compareBlacklistState(
  prev: { providers: Array<{ provider: string; listed: boolean; type: string }> } | null,
  curr: { providers: Array<{ provider: string; listed: boolean; type: string }> },
): DetectedChange[] {
  if (!prev) return [];
  const changes: DetectedChange[] = [];
  const prevMap = new Map(prev.providers.map(p => [p.provider, p]));
  for (const p of curr.providers) {
    // Skip IP-based providers — unreliable for CDN-fronted domains
    if (p.type === "ip") continue;
    const prevP = prevMap.get(p.provider);
    const wasListed = prevP?.listed ?? false;
    if (!wasListed && p.listed) {
      changes.push({
        severity: "critical",
        title: `Listed on ${p.provider}`,
        description: `Domain appeared on blacklist: ${p.provider}`,
        previousValue: false,
        currentValue: true,
      });
    } else if (wasListed && !p.listed) {
      changes.push({
        severity: "resolved",
        title: `Delisted from ${p.provider}`,
        description: `Domain removed from blacklist: ${p.provider}`,
        previousValue: true,
        currentValue: false,
      });
    }
  }
  return changes;
}

export function compareCaaDnssecState(
  prev: { caaRecords: Array<{ tag: string; value: string }>; dnssecEnabled: boolean } | null,
  curr: { caaRecords: Array<{ tag: string; value: string }>; dnssecEnabled: boolean },
): DetectedChange[] {
  if (!prev) return [];
  const changes: DetectedChange[] = [];

  // CAA changes
  const prevCaaSet = new Set(prev.caaRecords.map(r => `${r.tag}:${r.value}`));
  const currCaaSet = new Set(curr.caaRecords.map(r => `${r.tag}:${r.value}`));
  const caaChanged = prevCaaSet.size !== currCaaSet.size || [...prevCaaSet].some(k => !currCaaSet.has(k));

  if (caaChanged) {
    if (prev.caaRecords.length > 0 && curr.caaRecords.length === 0) {
      changes.push({ severity: "critical", title: "CAA records removed", description: "All CAA records have been removed from the domain", previousValue: prev.caaRecords, currentValue: curr.caaRecords });
    } else {
      changes.push({ severity: "warn", title: "CAA records changed", description: "CAA records have been modified", previousValue: prev.caaRecords, currentValue: curr.caaRecords });
    }
  }

  // DNSSEC changes
  if (prev.dnssecEnabled && !curr.dnssecEnabled) {
    changes.push({ severity: "critical", title: "DNSSEC disabled", description: "DNSSEC has been disabled for this domain", previousValue: true, currentValue: false });
  } else if (!prev.dnssecEnabled && curr.dnssecEnabled) {
    changes.push({ severity: "info", title: "DNSSEC enabled", description: "DNSSEC has been enabled for this domain", previousValue: false, currentValue: true });
  }

  return changes;
}

const CRITICAL_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy"];

export function compareHeadersState(
  prev: { items: Array<{ name: string; present: boolean; value: string }> } | null,
  curr: { items: Array<{ name: string; present: boolean; value: string }> },
): DetectedChange[] {
  if (!prev) return [];
  const changes: DetectedChange[] = [];
  const prevMap = new Map(prev.items.map(i => [i.name, i]));
  const currMap = new Map(curr.items.map(i => [i.name, i]));

  for (const [name, prevItem] of prevMap) {
    const currItem = currMap.get(name);
    if (prevItem.present && (!currItem || !currItem.present)) {
      const severity: AlertSeverity = CRITICAL_HEADERS.includes(name) ? "critical" : "warn";
      changes.push({ severity, title: `${name} header removed`, description: `Security header ${name} is no longer present`, previousValue: prevItem.value, currentValue: null });
    }
  }
  for (const [name, currItem] of currMap) {
    const prevItem = prevMap.get(name);
    if (currItem.present && (!prevItem || !prevItem.present)) {
      changes.push({ severity: "resolved", title: `${name} header added`, description: `Security header ${name} is now present`, previousValue: null, currentValue: currItem.value });
    }
  }
  return changes;
}

// ── Worker setup (Task 9) ──

export async function createMonitoringWorker(
  connection: import("ioredis").default,
  db: Database.Database,
  alertDispatcher: AlertDispatcher,
): Promise<import("bullmq").Worker> {
  const { Worker } = await import("bullmq");

  const worker = new Worker(QUEUE_NAME, async (job: Job) => {
    await processJob(job, db, alertDispatcher);
  }, {
    connection,
    concurrency: 3,
    limiter: { max: 10, duration: 60_000 },
  });

  worker.on("completed", (job) => {
    const data = job.data as MonitorJobData;
    const durationMs = job.processedOn && job.finishedOn ? job.finishedOn - job.processedOn : null;
    incr("monitor_job", { outcome: "completed", monitorType: data.monitorType });
    if (durationMs !== null) observe("monitor_job_duration_ms", durationMs, { monitorType: data.monitorType });
    log.info({ jobId: job.id, queue: QUEUE_NAME, domain: data.domain, monitorType: data.monitorType, durationMs }, "job completed");
  });

  worker.on("failed", (job, err) => {
    if (job) {
      const data = job.data as MonitorJobData;
      const durationMs = job.processedOn && job.finishedOn ? job.finishedOn - job.processedOn : null;
      incr("monitor_job", { outcome: "failed", monitorType: data.monitorType });
      log.error({ jobId: job.id, queue: QUEUE_NAME, domain: data.domain, monitorType: data.monitorType, durationMs, attempt: job.attemptsMade, err: err.message }, "job failed");
      // Update last_error on final failure
      if (job.attemptsMade >= (job.opts?.attempts ?? 3)) {
        db.prepare("UPDATE monitors SET last_error = ? WHERE id = ?").run(err.message, data.monitorId);
      }
    }
  });

  worker.on("stalled", (jobId) => {
    incr("monitor_job", { outcome: "stalled" });
    log.warn({ jobId, queue: QUEUE_NAME }, "job stalled");
  });

  worker.on("error", (err) => {
    log.error({ queue: QUEUE_NAME, err: err.message }, "worker error");
  });

  return worker;
}

async function processJob(job: Job, db: Database.Database, alertDispatcher: AlertDispatcher): Promise<void> {
  const data = job.data as MonitorJobData;
  const { monitorId, domainId, domain, monitorType, userId } = data;

  // Guard: skip if monitor was deleted
  const monitorExists = db.prepare("SELECT id FROM monitors WHERE id = ?").get(monitorId);
  if (!monitorExists) return;

  // Jitter: skip for initial jobs, apply for recurring
  const isInitial = (data as any).isInitial === true;
  if (!isInitial) {
    const jitterMs = Math.floor(Math.random() * 120_000);
    await new Promise(resolve => setTimeout(resolve, jitterMs));
  }

  // Freshness skip: check domain_check_state for result < 1 hour old
  const oneHourAgo = new Date(Date.now() - 3600_000).toISOString();
  let freshState = db.prepare(
    "SELECT result_json, result_hash, checked_at FROM domain_check_state WHERE domain = ? AND check_type = ? AND checked_at > ?"
  ).get(domain, monitorType, oneHourAgo) as DomainCheckStateRow | undefined;

  // For ct_logs: also check parent domain (vasya.com covers dev.vasya.com)
  if (!freshState && monitorType === "ct_logs") {
    const parts = domain.split(".");
    if (parts.length > 2) {
      const parent = parts.slice(1).join(".");
      freshState = db.prepare(
        "SELECT result_json, result_hash, checked_at FROM domain_check_state WHERE domain = ? AND check_type = ? AND checked_at > ?"
      ).get(parent, monitorType, oneHourAgo) as DomainCheckStateRow | undefined;
    }
  }

  let result: unknown;
  let resultHash: string;

  if (freshState) {
    result = JSON.parse(freshState.result_json);
    resultHash = freshState.result_hash;
  } else {
    // Run the checker
    const checker = CHECKER_MAP[monitorType as MonitorType];
    if (!checker) throw new Error(`Unknown monitor type: ${monitorType}`);
    result = await checker(domain, db);
    resultHash = computeHash(result);

    // Extract expiry date for expiry-type monitors
    let expiryDate: string | null = null;
    const r = result as any;
    if (monitorType === "ssl_expiry" && r.validTo) expiryDate = r.validTo;
    else if (monitorType === "domain_expiry" && r.expirationDate) expiryDate = r.expirationDate;
    else if (monitorType === "security_txt_expiry" && r.expiresDate) expiryDate = r.expiresDate;

    // Update domain_check_state (shared across users)
    // Extract cursor for incremental loading (CertSpotter last ID)
    let lastCursor: string | null = null;
    if (monitorType === "ct_logs" && (result as any).lastCertSpotterId) {
      lastCursor = (result as any).lastCertSpotterId;
    }

    db.prepare(`
      INSERT INTO domain_check_state (id, domain, check_type, result_json, result_hash, expiry_date, last_cursor, checked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(domain, check_type) DO UPDATE SET
        result_json = excluded.result_json,
        result_hash = excluded.result_hash,
        expiry_date = excluded.expiry_date,
        last_cursor = COALESCE(excluded.last_cursor, domain_check_state.last_cursor),
        checked_at = excluded.checked_at
    `).run(crypto.randomUUID(), domain, monitorType, JSON.stringify(result), resultHash, expiryDate, lastCursor);
  }

  // Only process state for the monitor that owns this job.
  // Each user has their own repeatable job, and the check result is shared
  // across users via domain_check_state — so per-user processing happens
  // when each user's own job fires (without racing other users' jobs).
  const monitor = db.prepare(
    "SELECT id, user_id, domain_id, enabled FROM monitors WHERE id = ?"
  ).get(monitorId) as { id: string; user_id: string; domain_id: string; enabled: number } | undefined;

  if (!monitor || !monitor.enabled) return;

  processMonitorState(monitor.id, monitor.user_id, monitor.domain_id, domain, monitorType as MonitorType, result, resultHash, db, alertDispatcher);
}

function processMonitorState(
  monitorId: string, userId: string, domainId: string, domain: string,
  monitorType: MonitorType, result: unknown, resultHash: string,
  db: Database.Database, alertDispatcher: AlertDispatcher,
): void {
  const prevState = db.prepare(
    "SELECT result_json, result_hash, thresholds_fired_json FROM monitor_state WHERE monitor_id = ?"
  ).get(monitorId) as MonitorStateRow | undefined;

  const changes: DetectedChange[] = [];
  let thresholdsFired: Record<string, boolean> = {};

  if (prevState) {
    thresholdsFired = prevState.thresholds_fired_json ? JSON.parse(prevState.thresholds_fired_json) : {};

    // Hash comparison — skip detailed diff if unchanged
    if (prevState.result_hash !== resultHash) {
      const prevResult = JSON.parse(prevState.result_json);

      // Type-specific comparison
      switch (monitorType) {
        case "ct_logs":
          changes.push(...compareCtLogsState(prevResult, result as any));
          break;
        case "blacklist":
          changes.push(...compareBlacklistState(prevResult, result as any));
          break;
        case "caa_dnssec":
          changes.push(...compareCaaDnssecState(prevResult, result as any));
          break;
        case "headers":
          changes.push(...compareHeadersState(prevResult, result as any));
          break;
      }
    }
  }

  // Threshold checks for expiry types
  const r = result as any;
  if (monitorType === "ssl_expiry" && r.daysRemaining !== null) {
    // Check for renewal (reset thresholds only if new cert has > 30 days)
    let renewed = false;
    if (prevState) {
      const prev = JSON.parse(prevState.result_json);
      if (prev.validTo && r.validTo && prev.validTo !== r.validTo) {
        const diffDays = Math.abs(new Date(r.validTo).getTime() - new Date(prev.validTo).getTime()) / 86400000;
        if (diffDays > 7 && r.daysRemaining > 30) {
          renewed = true;
          thresholdsFired = {}; // Real renewal with fresh cert
        }
        // Small diff or still expiring soon = load balancer rotation, keep thresholds
      }
    }
    const newThresholds = checkThresholds(r.daysRemaining, sslThresholds, thresholdsFired);
    for (const t of newThresholds) {
      thresholdsFired[String(t.threshold)] = true;
      changes.push({
        severity: t.severity,
        title: `SSL certificate expires in ${r.daysRemaining} days`,
        description: `SSL certificate for ${domain} expires on ${r.validTo ?? "unknown"}. Threshold: ${t.threshold} days.`,
        previousValue: null,
        currentValue: r.daysRemaining,
      });
    }

    // Issuer change detection
    if (prevState) {
      const prev = JSON.parse(prevState.result_json);
      if (prev.issuer && r.issuer && prev.issuer !== r.issuer) {
        changes.push({
          severity: "info",
          title: `SSL issuer changed: ${prev.issuer} → ${r.issuer}`,
          description: `Certificate issuer for ${domain} changed from "${prev.issuer}" to "${r.issuer}".`,
          previousValue: prev.issuer,
          currentValue: r.issuer,
        });
      }
      // Certificate renewed/replaced (validTo changed significantly — >7 days difference)
      if (prev.validTo && r.validTo && prev.validTo !== r.validTo) {
        const diffDays = Math.abs(new Date(r.validTo).getTime() - new Date(prev.validTo).getTime()) / 86400000;
        if (diffDays > 7) {
          changes.push({
            severity: "info",
            title: "SSL certificate renewed",
            description: `Certificate for ${domain} was replaced. New expiry: ${r.validTo}.`,
            previousValue: prev.validTo,
            currentValue: r.validTo,
          });
        }
        // Small difference (<= 7 days) = likely load balancer rotation, not renewal
      }
    }

    // CT Policy compliance change detection
    if (prevState) {
      const prev = JSON.parse(prevState.result_json);
      if (prev.chromeCtPass === true && r.chromeCtPass === false) {
        changes.push({
          severity: "critical",
          title: "Chrome CT policy compliance FAILED",
          description: `Certificate for ${domain} no longer meets Chrome's CT policy. Chrome may block access with NET::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED.`,
          previousValue: true,
          currentValue: false,
        });
      }
      if (prev.appleCtPass === true && r.appleCtPass === false) {
        changes.push({
          severity: "critical",
          title: "Apple CT policy compliance FAILED",
          description: `Certificate for ${domain} no longer meets Apple's CT policy. Safari may reject the connection.`,
          previousValue: true,
          currentValue: false,
        });
      }
    }
  }

  if (monitorType === "domain_expiry" && r.daysRemaining !== null) {
    if (prevState) {
      const prev = JSON.parse(prevState.result_json);
      if (prev.expirationDate && r.expirationDate && new Date(r.expirationDate).getTime() > new Date(prev.expirationDate).getTime() + 30 * 86400000) {
        thresholdsFired = {};
      }
    }
    const newThresholds = checkThresholds(r.daysRemaining, domainThresholds, thresholdsFired);
    for (const t of newThresholds) {
      thresholdsFired[String(t.threshold)] = true;
      changes.push({
        severity: t.severity,
        title: `Domain registration expires in ${r.daysRemaining} days`,
        description: `Domain ${domain} expires on ${r.expirationDate ?? "unknown"}. Threshold: ${t.threshold} days.`,
        previousValue: null,
        currentValue: r.daysRemaining,
      });
    }
  }

  if (monitorType === "security_txt_expiry") {
    if (r.daysRemaining !== null) {
      if (prevState) {
        const prev = JSON.parse(prevState.result_json);
        if (prev.expiresDate && r.expiresDate && new Date(r.expiresDate).getTime() > new Date(prev.expiresDate).getTime() + 30 * 86400000) {
          thresholdsFired = {};
        }
      }
      const newThresholds = checkThresholds(r.daysRemaining, secTxtThresholds, thresholdsFired);
      for (const t of newThresholds) {
        thresholdsFired[String(t.threshold)] = true;
        changes.push({
          severity: t.severity,
          title: `security.txt expires in ${r.daysRemaining} days`,
          description: `security.txt for ${domain} expires on ${r.expiresDate ?? "unknown"}. Threshold: ${t.threshold} days.`,
          previousValue: null,
          currentValue: r.daysRemaining,
        });
      }
    }
    // Check if security.txt became unavailable
    if (prevState) {
      const prev = JSON.parse(prevState.result_json);
      if (prev.available && !r.available) {
        changes.push({
          severity: "warn",
          title: "security.txt became unavailable",
          description: `security.txt for ${domain} is no longer accessible`,
          previousValue: true,
          currentValue: false,
        });
      }
    }
  }

  // Create alerts for detected changes
  for (const change of changes) {
    const alertId = crypto.randomUUID();
    db.prepare(`
      INSERT INTO monitor_alerts (id, monitor_id, domain_id, user_id, monitor_type, severity, title, description, previous_value, current_value, notified, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, datetime('now'))
    `).run(alertId, monitorId, domainId, userId, monitorType, change.severity, change.title, change.description,
      change.previousValue !== null ? JSON.stringify(change.previousValue) : null,
      change.currentValue !== null ? JSON.stringify(change.currentValue) : null);

    alertDispatcher.enqueue({
      alertId, userId, domainId, domain, monitorType,
      severity: change.severity, title: change.title, description: change.description,
      previousValue: change.previousValue, currentValue: change.currentValue,
    });
  }

  // Update monitor_state
  db.prepare(`
    INSERT INTO monitor_state (id, monitor_id, result_json, result_hash, checked_at, thresholds_fired_json)
    VALUES (?, ?, ?, ?, datetime('now'), ?)
    ON CONFLICT(monitor_id) DO UPDATE SET
      result_json = excluded.result_json,
      result_hash = excluded.result_hash,
      checked_at = excluded.checked_at,
      thresholds_fired_json = excluded.thresholds_fired_json
  `).run(crypto.randomUUID(), monitorId, JSON.stringify(result), resultHash,
    Object.keys(thresholdsFired).length > 0 ? JSON.stringify(thresholdsFired) : null);

  // Update monitors.last_run_at and next_run_at
  const intervalMs = MONITOR_INTERVALS[monitorType] ?? 86400000;
  const nextRunAt = new Date(Date.now() + intervalMs).toISOString();
  db.prepare("UPDATE monitors SET last_run_at = datetime('now'), next_run_at = ?, last_error = NULL WHERE id = ?").run(nextRunAt, monitorId);
}
