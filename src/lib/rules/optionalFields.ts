import type { ParsedLine, Finding } from '../types';

/** Simple BCP 47 language tag pattern: 2-3 letter primary subtag, optional region/script subtags */
const BCP47_REGEX = /^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})*$/;

/**
 * Validates optional fields in a security.txt file.
 *
 * Currently checks:
 * - Preferred-Languages: must be a comma-separated list of valid BCP 47 language tags
 */
export function checkOptionalFields(lines: ParsedLine[]): Finding[] {
  const findings: Finding[] = [];

  const fields = lines.filter(
    (line): line is Extract<ParsedLine, { kind: 'field' }> => line.kind === 'field'
  );

  const prefLangFields = fields.filter(
    f => f.name.toLowerCase() === 'preferred-languages'
  );

  for (const field of prefLangFields) {
    const tags = field.value.split(',').map(t => t.trim());

    for (const tag of tags) {
      if (!BCP47_REGEX.test(tag)) {
        findings.push({
          severity: 'error',
          lineNumber: field.lineNumber,
          title: 'Invalid Preferred-Languages value',
          explanation: `"${tag}" is not a valid BCP 47 language tag. Tags must be 2-3 letter language codes, optionally followed by region or script subtags (e.g., "en", "en-US", "zh-Hans").`,
          suggestedFix: 'Use valid BCP 47 language tags separated by commas, e.g. Preferred-Languages: en, fr, de',
          ruleId: 'preferred-languages-invalid',
          rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.5.8',
        });
        break;
      }
    }
  }

  return findings;
}
