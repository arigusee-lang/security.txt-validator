import type { ParsedLine, Finding } from '../types';
import { KNOWN_FIELD_NAMES } from '../constants';

/**
 * Reports warnings for field names not defined by RFC 9116.
 *
 * Unknown fields do not abort validation — all remaining fields
 * continue to be processed normally.
 */
export function checkUnknownFields(lines: ParsedLine[]): Finding[] {
  const findings: Finding[] = [];

  for (const line of lines) {
    if (line.kind !== 'field') continue;

    if (!KNOWN_FIELD_NAMES.includes(line.name.toLowerCase())) {
      findings.push({
        severity: 'warning',
        lineNumber: line.lineNumber,
        title: 'Unknown field',
        explanation: `"${line.name}" is not a field name defined by RFC 9116. It may be ignored by consumers of this file.`,
        suggestedFix: `Remove the "${line.name}" field or replace it with a recognized RFC 9116 field name.`,
        ruleId: 'unknown-field',
        rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.4',
      });
    }
  }

  return findings;
}
