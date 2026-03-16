import type { ParsedLine, Finding } from '../types';

/**
 * Checks for missing or duplicate required fields per RFC 9116.
 *
 * Rules:
 * - At least one Contact field is required
 * - Exactly one Expires field is required
 * - More than one Expires field is an error
 */
export function checkRequiredFields(lines: ParsedLine[]): Finding[] {
  const findings: Finding[] = [];

  const fields = lines.filter(
    (line): line is Extract<ParsedLine, { kind: 'field' }> => line.kind === 'field'
  );

  const contactFields = fields.filter(f => f.name.toLowerCase() === 'contact');
  const expiresFields = fields.filter(f => f.name.toLowerCase() === 'expires');

  if (contactFields.length === 0) {
    findings.push({
      severity: 'error',
      title: 'Missing Contact field',
      explanation: 'At least one Contact field is required',
      suggestedFix: 'Add a Contact field, e.g. Contact: mailto:security@example.com',
      ruleId: 'required-contact-missing',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.5.3',
    });
  }

  if (expiresFields.length === 0) {
    findings.push({
      severity: 'error',
      title: 'Missing Expires field',
      explanation: 'The Expires field is required',
      suggestedFix: 'Add an Expires field with an RFC 3339 date, e.g. Expires: 2025-12-31T23:59:59z',
      ruleId: 'required-expires-missing',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5',
    });
  }

  if (expiresFields.length > 1) {
    findings.push({
      severity: 'error',
      lineNumber: expiresFields[1].lineNumber,
      title: 'Duplicate Expires field',
      explanation: 'Only one Expires field is allowed',
      suggestedFix: 'Remove the duplicate Expires field so that only one remains.',
      ruleId: 'required-expires-duplicate',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5',
    });
  }

  return findings;
}
