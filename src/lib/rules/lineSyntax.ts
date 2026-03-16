import type { ParsedLine, Finding } from '../types';

/**
 * Reports errors for lines classified as `invalid` by the parser.
 *
 * Any line that does not match a recognized format (field, comment, or blank)
 * is flagged with an error referencing that line.
 */
export function checkLineSyntax(lines: ParsedLine[]): Finding[] {
  const findings: Finding[] = [];

  for (const line of lines) {
    if (line.kind === 'invalid') {
      findings.push({
        severity: 'error',
        lineNumber: line.lineNumber,
        title: 'Invalid line syntax',
        explanation: `Line ${line.lineNumber} does not match any recognized format (field, comment, or blank): "${line.raw}"`,
        suggestedFix: 'Rewrite this line as a valid field (e.g. Contact: mailto:security@example.com), a comment (starting with #), or remove it.',
        ruleId: 'line-invalid-syntax',
        rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-4',
      });
    }
  }

  return findings;
}
