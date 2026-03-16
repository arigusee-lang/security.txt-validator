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
