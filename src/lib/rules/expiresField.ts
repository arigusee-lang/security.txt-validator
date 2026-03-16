import type { ParsedLine, Finding } from '../types';

/**
 * RFC 3339 date-time regex.
 * Matches: YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS+HH:MM (and variants with fractional seconds)
 */
const RFC3339_REGEX =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
const THREE_SIXTY_FIVE_DAYS_MS = 365 * 24 * 60 * 60 * 1000;

/**
 * Validates the Expires field for RFC 3339 format and temporal correctness.
 *
 * Rules:
 * - Value must be a valid RFC 3339 date-time string
 * - Date-time must not be in the past
 * - Warning if within 30 days of now
 * - Warning if more than 365 days in the future
 *
 * Skips if there are 0 or 2+ Expires fields (handled by requiredFields rule).
 */
export function checkExpiresField(lines: ParsedLine[]): Finding[] {
  const findings: Finding[] = [];

  const expiresFields = lines.filter(
    (line): line is Extract<ParsedLine, { kind: 'field' }> =>
      line.kind === 'field' && line.name.toLowerCase() === 'expires'
  );

  // Skip if 0 or 2+ Expires fields — those cases are handled by requiredFields
  if (expiresFields.length !== 1) {
    return findings;
  }

  const field = expiresFields[0];
  const value = field.value.trim();

  // Check RFC 3339 format with regex first
  if (!RFC3339_REGEX.test(value)) {
    findings.push({
      severity: 'error',
      lineNumber: field.lineNumber,
      title: 'Invalid Expires format',
      explanation:
        'The Expires field value is not a valid RFC 3339 date-time string.',
      suggestedFix:
        'Use RFC 3339 format, e.g. Expires: 2025-12-31T23:59:59z',
      ruleId: 'expires-invalid-format',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5',
    });
    return findings;
  }

  // Parse the date and verify it's a real date (regex alone doesn't catch e.g. month 13)
  const parsed = new Date(value);
  if (isNaN(parsed.getTime())) {
    findings.push({
      severity: 'error',
      lineNumber: field.lineNumber,
      title: 'Invalid Expires format',
      explanation:
        'The Expires field value is not a valid RFC 3339 date-time string.',
      suggestedFix:
        'Use RFC 3339 format, e.g. Expires: 2025-12-31T23:59:59z',
      ruleId: 'expires-invalid-format',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5',
    });
    return findings;
  }

  const now = new Date();
  const diffMs = parsed.getTime() - now.getTime();

  // Past
  if (diffMs < 0) {
    findings.push({
      severity: 'error',
      lineNumber: field.lineNumber,
      title: 'Expired security.txt',
      explanation: 'The file has expired.',
      suggestedFix:
        'Update the Expires field to a future date, e.g. one year from now.',
      ruleId: 'expires-past',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5',
    });
    return findings;
  }

  // Within 30 days
  if (diffMs <= THIRTY_DAYS_MS) {
    findings.push({
      severity: 'warning',
      lineNumber: field.lineNumber,
      title: 'Near expiry',
      explanation:
        'The Expires date is within 30 days of the current date.',
      suggestedFix:
        'Consider extending the Expires date to give yourself more time before it lapses.',
      ruleId: 'expires-near-expiry',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5',
    });
  }

  // More than 365 days in the future
  if (diffMs > THREE_SIXTY_FIVE_DAYS_MS) {
    findings.push({
      severity: 'warning',
      lineNumber: field.lineNumber,
      title: 'Expiry date too far in the future',
      explanation:
        'The Expires date is more than 365 days in the future.',
      suggestedFix:
        'RFC 9116 recommends setting the Expires date to less than one year ahead to avoid staleness.',
      ruleId: 'expires-too-far',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5',
    });
  }

  return findings;
}
