import type { KnownFieldName } from './types';

/** Fields that may appear multiple times */
export const REPEATABLE_FIELDS: KnownFieldName[] = [
  "Contact",
  "Encryption",
  "Acknowledgments",
  "Canonical",
  "Policy",
  "Hiring",
];

/** Fields that must appear exactly once */
export const SINGULAR_FIELDS: KnownFieldName[] = ["Expires"];

/** RFC recommended field order for sorted output */
export const RECOMMENDED_ORDER: KnownFieldName[] = [
  "Contact",
  "Expires",
  "Encryption",
  "Acknowledgments",
  "Policy",
  "Hiring",
  "Canonical",
  "Preferred-Languages",
  "CSAF",
];

/** URI schemes accepted per field */
export const FIELD_URI_SCHEMES: Record<string, string[]> = {
  Contact: ["mailto:", "https://", "tel:"],
  Encryption: ["https://", "openpgp4fpr:"],
  Acknowledgments: ["https://"],
  Canonical: ["https://"],
  Policy: ["https://"],
  Hiring: ["https://"],
  CSAF: ["https://"],
};

/** All known RFC 9116 field names (lowercase for case-insensitive lookup) */
export const KNOWN_FIELD_NAMES: string[] = [
  "contact",
  "expires",
  "encryption",
  "acknowledgments",
  "canonical",
  "policy",
  "hiring",
  "preferred-languages",
  "csaf",
];
