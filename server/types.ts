/** Response from the proxy fetch endpoint on success */
export interface ProxyFetchResponse {
  success: true;
  content: string;
  contentType: string;
  fetchedFrom: string;
  redirectChain: string[];
  wellKnownFound: boolean;
  fallbackUsed: boolean;
}

/** Error response from the proxy */
export interface ProxyFetchError {
  success: false;
  error:
    | "timeout"
    | "size_limit"
    | "dns_failure"
    | "http_error"
    | "ssrf_blocked"
    | "invalid_content_type"
    | "not_found"
    | "too_many_redirects"
    | "invalid_request"
    | "internal";
  message: string;
  httpStatus?: number;
}

export type ProxyResponse = ProxyFetchResponse | ProxyFetchError;

// ── Domain Security Checker types ──

/** Status outcome for a single check item */
export type CheckStatus = "pass" | "warn" | "fail" | "info";

/** TLS certificate details extracted from the HTTPS connection */
export interface TlsCertInfo {
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  sans: string[];
}

/** Extended response from safeFetchWithHeaders */
export interface SafeFetchWithHeadersResponse {
  success: true;
  content: string;
  contentType: string;
  fetchedFrom: string;
  redirectChain: string[];
  wellKnownFound: boolean;
  fallbackUsed: boolean;
  responseHeaders: Record<string, string>;
  tlsCert: TlsCertInfo | null;
  chainCerts?: any[];
  rawLeafCert?: Buffer;
}

// ── Headers ──

export interface HeaderCheckItem {
  name: string;
  present: boolean;
  value: string;
  status: CheckStatus;
  explanation: string;
  ref?: string;
}

export interface HeadersResult {
  status: CheckStatus;
  items: HeaderCheckItem[];
}

// ── SPF ──

export interface SpfMechanism {
  mechanism: string;
  description: string;
}

export interface SpfValidationItem {
  check: string;
  status: CheckStatus;
  detail: string;
  ref?: string;
}

export interface SpfResult {
  status: CheckStatus;
  record: string | null;
  validations: SpfValidationItem[];
  mechanisms: SpfMechanism[];
  dnsLookupCount: number;
  error?: string;
  notice?: string;
}

// ── DMARC ──

export interface DmarcTag {
  tag: string;
  value: string;
  description: string;
  /** Per-tag status — set when the tag value is invalid or carries a warning. Absent = ok. */
  status?: CheckStatus;
  /** Short human-readable explanation when `status` is warn/fail. */
  issue?: string;
}

export interface DmarcValidationItem {
  check: string;
  status: CheckStatus;
  detail: string;
  ref?: string;
}

export interface DmarcReportUri {
  /** Original URI as it appears in the record, e.g. "mailto:dmarc@example.com". */
  uri: string;
  /** Email address (after `mailto:` and before optional `!size`). Null for non-mailto URIs. */
  email: string | null;
  /** Email address domain. Null if URI couldn't be parsed. */
  domain: string | null;
  /** True if the URI's domain differs from the DMARC record's domain (and is not a sub-suffix). */
  external: boolean;
  /** For external URIs only: did the destination publish `<from>._report._dmarc.<dst>` v=DMARC1? Null if internal or check failed. */
  authorized: boolean | null;
}

export interface DmarcResult {
  status: CheckStatus;
  record: string | null;
  validations: DmarcValidationItem[];
  tags: DmarcTag[];
  error?: string;
  notice?: string;
  /** Parsed rua URIs with external-destination authorization status. */
  ruaUris?: DmarcReportUri[];
  /** Parsed ruf URIs with external-destination authorization status. */
  rufUris?: DmarcReportUri[];
}

// ── DKIM ──

export interface DkimSelectorResult {
  selector: string;
  service: string;
  found: boolean;
  record?: string;
}

export interface DkimResult {
  status: CheckStatus;
  foundCount: number;
  totalChecked: number;
  selectors: DkimSelectorResult[];
}

// ── DNSSEC ──

export interface DnssecResult {
  status: CheckStatus;
  enabled: boolean;
  error?: string;
}

// ── CAA ──

export interface CaaRecord {
  flags: number;
  tag: string;
  value: string;
}

export interface CaaResult {
  status: CheckStatus;
  records: CaaRecord[];
  error?: string;
}

// ── MX ──

export interface MxRecord {
  exchange: string;
  priority: number;
}

export interface MxResult {
  status: CheckStatus;
  records: MxRecord[];
  /** True if the domain accepts email — false if there are no MX records or a Null MX (RFC 7505). */
  hasMail?: boolean;
  /** RFC 7505 Null MX (single record `0 .`) — explicit "this domain does not accept mail". */
  nullMx?: boolean;
}

// ── NS ──

export interface NsResult {
  status: CheckStatus;
  nameservers: string[];
  error?: string;
}

// ── SSL ──

import type { ChainCertInfo, ChainIssue, CtPolicyResult } from "./checkers/sslChecker.types.js";

/**
 * One observed certificate from a single edge IP. The same `domain` can be
 * served from many IPs (CDN, anycast, multi-region LB) — each may carry a
 * different certificate during rotation.
 */
export interface TlsEdgeSample {
  ip: string;
  /** SHA-256 fingerprint of the leaf cert (hex, no separators). Same fingerprint = identical cert. */
  fingerprint: string;
  issuer: string;
  notAfter: string;        // ISO date
  daysRemaining: number;
  /** True if `domain` matches the cert's CN/SANs (hostname verification). */
  sanMatch: boolean;
  /** True if the chain verified up to a trusted root (libssl default trust store). */
  chainOk: boolean;
  /** Set when the per-IP TLS handshake failed; other fields are placeholder values. */
  error?: string;
}

export type TlsEdgesConsistency =
  | "consistent"      // 1 unique fingerprint, all samples OK
  | "rollout"         // 2+ fingerprints but all valid — normal mid-rotation state
  | "inconsistent"    // a sample failed sanMatch / chainOk → real problem on some edge
  | "unknown";        // < 2 samples returned, no comparison possible

export interface TlsEdgesResult {
  samples: TlsEdgeSample[];
  /** IPs we tried but couldn't get a sample from (timeout, refused, etc.). */
  failedIps: string[];
  /** Count of distinct leaf-cert fingerprints across successful samples. */
  distinctFingerprints: number;
  minDaysRemaining: number | null;
  maxDaysRemaining: number | null;
  allSanMatch: boolean;
  allChainOk: boolean;
  consistency: TlsEdgesConsistency;
}

export interface SslResult {
  status: CheckStatus;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  sans: string[];
  error?: string;

  // Deep check fields (optional for backward compatibility)
  chain?: ChainCertInfo[];
  chainStatus?: CheckStatus;
  chainIssues?: ChainIssue[];
  ct?: CtPolicyResult;
  /** Multi-IP edge probe — set when we sampled cert from each resolved IP separately. */
  edges?: TlsEdgesResult;
  /**
   * Name of the CDN/cloud provider that auto-rotates this cert (Cloudflare,
   * AWS ACM, Google Cloud, Fastly, Azure). Null when the cert is managed by
   * the domain owner directly (Let's Encrypt on origin, custom uploaded, etc.)
   * — those still need the standard expiry warnings.
   */
  managedBy?: string | null;
}

// ── Domain Expiry ──

export interface DomainExpiryResult {
  status: CheckStatus;
  expirationDate: string | null;
  daysRemaining: number | null;
  error?: string;
}

// ── Infrastructure ──

/**
 * What we observe about a domain's hosting / edge network. Distinct from
 * `BlacklistResult` (which is DNSBL only): infrastructure is the resolve+CDN
 * detection layer that other checks consume (multi-edge TLS probe, CDN-managed
 * cert detect, DNSBL ip-target).
 */
export interface InfrastructureResult {
  /** Primary IP — first IP from the multi-resolver probe. Null when resolve failed. */
  ip: string | null;
  /**
   * All unique A-record IPs observed across multiple public resolvers
   * (Google, Cloudflare, Quad9, OpenDNS). Larger sets indicate anycast / CDN
   * edges; a single IP typically means a single origin host.
   */
  ips: string[];
  /** Number of public resolvers that returned at least one IP. */
  resolverCount: number;
  /** CDN/cloud name matched against the primary IP's CIDR (or null). */
  cdnProvider: string | null;
  /** CDN providers detected across all observed IPs (usually 0 or 1). */
  cdnProviders: string[];
  /** Set when resolve failed for all paths (public resolvers + system fallback). */
  error?: string;
}

// ── Blacklist (DNSBL only after the Phase A refactor) ──

export interface DnsblProviderResult {
  provider: string;
  host: string;
  listed: boolean;
  type: "ip" | "domain";
}

export interface BlacklistResult {
  status: CheckStatus;
  providers: DnsblProviderResult[];
  error?: string;
}

// ── Security.txt section in domain check ──

export interface SecurityTxtSection {
  status: CheckStatus;
  available: boolean;
  validationStatus: "valid" | "invalid" | "valid-with-warnings" | null;
  errorCount: number;
  warningCount: number;
  findings: Array<{
    severity: "error" | "warning" | "info";
    title: string;
    explanation: string;
  }>;
  fetchedFrom: string | null;
  error?: string;
}

// ── Top-level API response ──

export interface DomainCheckResponse {
  domain: string;
  timestamp: string;
  securityTxt: SecurityTxtSection;
  headers: HeadersResult;
  spf: SpfResult;
  dmarc: DmarcResult;
  dkim: DkimResult;
  dnssec: DnssecResult;
  caa: CaaResult;
  mx: MxResult;
  ns: NsResult;
  ssl: SslResult;
  domainExpiry: DomainExpiryResult;
  /** Optional — only populated when blacklist or ssl checks ran. */
  infrastructure?: InfrastructureResult;
  blacklist: BlacklistResult;
  ctLogs: CtLogsResult;
  redirects: RedirectResult;
  safeBrowsing: SafeBrowsingResult;
  urlhaus: UrlhausResult;
  danglingDns: DanglingDnsResult;
}

// ── Certificate Transparency ──

export interface CtLogEntry {
  id?: string;
  issuerName: string;
  commonName: string;
  notBefore: string;
  notAfter: string;
}

export interface CtFinding {
  severity: "warn" | "fail" | "info";
  title: string;
  description: string;
  subdomain?: string;
}

export type CtDataSource = "crt.sh-pg" | "certspotter" | "none";

/**
 * Admin-selectable preferred CT data source. When set, the chosen source is
 * tried first and the other acts as fallback; when undefined, the default
 * order applies (crt.sh-pg → certspotter).
 */
export type CtSourcePref = "certspotter" | "crt.sh-pg";

export interface CtLogsResult {
  status: CheckStatus;
  totalCerts: number;
  recentCerts: CtLogEntry[];
  flaggedCerts?: CtLogEntry[];
  findings: CtFinding[];
  source: CtDataSource;
  fromCache?: boolean;
  cachedAt?: string;
  // True when both upstream sources failed and we returned a cached entry that
  // had passed its freshness window. `staleSeconds` is the age of that entry.
  stale?: boolean;
  staleSeconds?: number;
  lastCertSpotterId?: string;
  error?: string;
}

export interface CtCheckOptions {
  authenticated?: boolean;
  sslIssuer?: string | null;
  caaRecords?: CaaRecord[];
  /** Preferred CT source; undefined = default chain order. */
  ctSource?: CtSourcePref;
  timeout?: number;
  startAfterId?: string;
}

// ── Redirect / HTTPS ──

export interface RedirectCheckItem {
  check: string;
  status: CheckStatus;
  detail: string;
  ref?: string;
}

export interface RedirectResult {
  status: CheckStatus;
  httpsRedirect: boolean;
  wwwBehavior: string | null;
  items: RedirectCheckItem[];
  error?: string;
}


// ── Google Safe Browsing ──

export interface SafeBrowsingThreat {
  threatType: string;
  platformType: string;
}

export interface SafeBrowsingResult {
  status: CheckStatus;
  safe: boolean | null;
  threats: SafeBrowsingThreat[];
  error?: string;
}

// ── URLhaus ──

export interface UrlhausResult {
  status: CheckStatus;
  listed: boolean;
  urlCount: number;
  error?: string;
}

// ── Dangling DNS ──

export interface DanglingRecord {
  type: "MX" | "NS";
  hostname: string;
  resolves: boolean;
}

export interface DanglingDnsResult {
  status: CheckStatus;
  records: DanglingRecord[];
  danglingCount: number;
  error?: string;
}

// ── Phase 3: Accounts, Batch, Monitoring types ──

export interface UserRow {
  id: string;
  email: string;
  name: string | null;
  avatar_url: string | null;
  provider: "google" | "github";
  provider_id: string;
  plan: "free" | "premium" | "premium_plus";
  role: "user" | "admin";
  created_at: string;
  last_login_at: string | null;
}

export interface ScanRow {
  id: string;
  user_id: string | null;
  batch_id: string | null;
  domain: string;
  scan_type: "single" | "batch";
  status: "pending" | "running" | "completed" | "failed";
  score: number | null;
  config_json: string | null;
  result_json: string | null;
  changes_json: string | null;
  shared: number;
  share_id: string | null;
  share_expires: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface BatchScanRow {
  id: string;
  user_id: string;
  name: string | null;
  status: "pending" | "running" | "completed" | "failed";
  total_domains: number;
  completed_domains: number;
  config_json: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface BatchScanDomainRow {
  id: string;
  batch_id: string;
  domain: string;
  scan_id: string | null;
  status: "pending" | "running" | "completed" | "failed";
}

export interface WebhookRow {
  id: string;
  user_id: string;
  url: string;
  name: string | null;
  secret: string;
  events_json: string;
  enabled: number;
  failing: number;
  fail_count: number;
  created_at: string;
}

export interface WebhookDeliveryRow {
  id: string;
  webhook_id: string;
  event: string;
  payload_json: string;
  status: "pending" | "delivered" | "failed";
  response_code: number | null;
  error: string | null;
  attempts: number;
  created_at: string;
  delivered_at: string | null;
}

export interface NotificationLogRow {
  id: string;
  user_id: string;
  scan_id: string | null;
  type: "email" | "webhook";
  status: "pending" | "sent" | "failed";
  payload_json: string | null;
  error: string | null;
  created_at: string;
  sent_at: string | null;
}

export interface PlanAuditLogRow {
  id: string;
  admin_id: string;
  user_id: string;
  old_plan: string;
  new_plan: string;
  changed_at: string;
}

// ── Score ──

export interface ScoreBreakdown {
  [category: string]: { earned: number; max: number };
}

export interface ScoreResponse {
  total: number;
  breakdown: ScoreBreakdown;
}

// ── Remediation ──

export interface RemediationInfo {
  summary: string;
  steps: string[];
  effort: "low" | "medium" | "high";
  impact: "low" | "medium" | "high";
  ref: string;
}

// ── Scan Config ──

export interface ScanConfig {
  checks: {
    securityTxt: boolean;
    headers: boolean;
    spf: boolean;
    dmarc: boolean;
    dkim: boolean;
    dnssec: boolean;
    caa: boolean;
    mx: boolean;
    ns: boolean;
    ssl: boolean;
    domainExpiry: boolean;
    blacklist: boolean;
    ctLogs: boolean;
    redirects: boolean;
    reputation: boolean;
    danglingDns: boolean;
  };
  noCache: boolean;
  /** Preferred CT source; undefined = default chain order. */
  ctSource?: CtSourcePref;
  authenticated?: boolean;
}

export const DEFAULT_SCAN_CONFIG: ScanConfig = {
  checks: {
    securityTxt: true, headers: true, spf: true, dmarc: true,
    dkim: true, dnssec: true, caa: true, mx: true, ns: true,
    ssl: true, domainExpiry: true, blacklist: true, ctLogs: true,
    redirects: true, reputation: true, danglingDns: true,
  },
  noCache: false,
};

// ── Diff ──

export interface DiffChange {
  category: string;
  type: "status_changed" | "value_changed" | "appeared" | "disappeared";
  field?: string;
  severity: "critical" | "warn" | "resolved" | "info";
  previous: unknown;
  current: unknown;
  message: string;
}

export interface DiffResult {
  hasDiff: boolean;
  previousScanId: string | null;
  previousScanDate: string | null;
  scoreDelta: number;
  changes: DiffChange[];
  summary: {
    newIssues: number;
    resolvedIssues: number;
    valueChanges: number;
    totalChanges: number;
  };
}

// ── Extended API response ──

export interface DomainCheckResponseV3 extends DomainCheckResponse {
  score: ScoreResponse;
  diff?: DiffResult;
}

// ── API Error ──

export interface ApiError {
  error: string;
  message?: string;
}
