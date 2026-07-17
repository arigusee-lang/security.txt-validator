/** A single parsed line from the input */
export type ParsedLine =
  | { kind: "field"; lineNumber: number; raw: string; name: string; value: string }
  | { kind: "comment"; lineNumber: number; raw: string; text: string }
  | { kind: "blank"; lineNumber: number }
  | { kind: "invalid"; lineNumber: number; raw: string };

/** Severity levels for validation findings */
export type Severity = "error" | "warning" | "info";

/** A single validation finding */
export interface Finding {
  severity: Severity;
  lineNumber?: number;
  title: string;
  explanation: string;
  suggestedFix: string;
  ruleId: string;
  /** Optional link to relevant RFC section */
  rfcRef?: string;
}

/** Overall validation result */
export interface ValidationResult {
  status: "valid" | "invalid" | "valid-with-warnings";
  errorCount: number;
  warningCount: number;
  infoCount: number;
  findings: Finding[];
  parsedFields: ParsedLine[];
}

/** Metadata from URL-mode fetch */
export interface FetchMetadata {
  contentType: string;
  fetchedFrom: string;
  redirectChain: string[];
  wellKnownFound: boolean;
  fallbackUsed: boolean;
  usedHttps: boolean;
}

/** Known RFC 9116 field names */
export type KnownFieldName =
  | "Contact"
  | "Expires"
  | "Encryption"
  | "Acknowledgments"
  | "Canonical"
  | "Policy"
  | "Hiring"
  | "Preferred-Languages"
  | "CSAF";

/** Validation rule function signature */
export type ValidationRule = (lines: ParsedLine[], fetchMeta?: FetchMetadata) => Finding[];

/** PGP ClearSign wrapper info */
export interface PgpInfo {
  /** Whether the input was wrapped in a PGP ClearSign block */
  isSigned: boolean;
  /** The hash algorithm declared in the header (e.g. "SHA256") */
  hashAlgorithm?: string;
  /** Whether the PGP structure appears well-formed (has both header and signature) */
  wellFormed: boolean;
}

/** Result of parsing raw security.txt content */
export interface ParseResult {
  lines: ParsedLine[];
  pgp: PgpInfo;
}

// ── Domain Security Checker types (frontend) ──

export type CheckStatus = "pass" | "warn" | "fail" | "info";

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

export interface DnssecResult {
  status: CheckStatus;
  enabled: boolean;
  error?: string;
}

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

export interface NsResult {
  status: CheckStatus;
  nameservers: string[];
  error?: string;
}

// ── SSL Chain & CT types (duplicated from server for frontend) ──

export type CertRole = "leaf" | "intermediate" | "root";

export interface ChainCertInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  isSelfSigned: boolean;
  role: CertRole;
}

export interface ChainIssue {
  severity: CheckStatus;
  message: string;
}

export interface SctInfo {
  version: number;
  logId: string;
  timestamp: number;
  logName: string | null;
  operator: string | null;
}

export interface CtPolicyFinding {
  severity: CheckStatus;
  message: string;
}

export interface CtPolicyResult {
  scts: SctInfo[];
  chromeStatus: CheckStatus;
  appleStatus: CheckStatus;
  findings: CtPolicyFinding[];
}

/** One observed certificate from a single edge IP (multi-IP TLS probe). */
export interface TlsEdgeSample {
  ip: string;
  fingerprint: string;
  issuer: string;
  notAfter: string;
  daysRemaining: number;
  sanMatch: boolean;
  chainOk: boolean;
  error?: string;
}

export type TlsEdgesConsistency = "consistent" | "rollout" | "inconsistent" | "unknown";

export interface TlsEdgesResult {
  samples: TlsEdgeSample[];
  failedIps: string[];
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
  /** Name of the CDN/cloud provider that auto-rotates this cert, or null if self-managed. */
  managedBy?: string | null;
}

export interface DomainExpiryResult {
  status: CheckStatus;
  expirationDate: string | null;
  daysRemaining: number | null;
  error?: string;
}

export interface DnsblProviderResult {
  provider: string;
  host: string;
  listed: boolean;
  type: "ip" | "domain";
}

/** Infrastructure (resolve + CDN detect) — distinct from DNSBL. */
export interface InfrastructureResult {
  ip: string | null;
  ips: string[];
  resolverCount: number;
  cdnProvider: string | null;
  cdnProviders: string[];
  error?: string;
}

/** DNSBL only. Historical fields (ip, cdnProvider, ips, ...) moved to InfrastructureResult. */
export interface BlacklistResult {
  status: CheckStatus;
  providers: DnsblProviderResult[];
  error?: string;
}

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

export interface DomainCheckResult {
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

/** Admin-selectable preferred CT data source (undefined = default chain). */
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
  // Set when both upstream CT sources failed and we returned an entry past its
  // freshness window. `staleSeconds` is the age of that entry in seconds.
  stale?: boolean;
  staleSeconds?: number;
  error?: string;
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
