import type { ParsedLine, Finding } from '../types';
import { FIELD_URI_SCHEMES } from '../constants';

/**
 * Build a lowercase lookup map from FIELD_URI_SCHEMES so field-name
 * comparison is case-insensitive while preserving the original scheme lists.
 */
const SCHEME_LOOKUP: Record<string, string[]> = Object.fromEntries(
  Object.entries(FIELD_URI_SCHEMES).map(([name, schemes]) => [name.toLowerCase(), schemes]),
);

/**
 * Validates URI schemes and basic syntax for all URI-based fields per RFC 9116.
 *
 * Rules:
 * - Each URI-based field value must start with one of its allowed schemes
 * - https:// URIs must have at least a hostname after the scheme
 * - mailto: URIs must contain an @ in the address part
 * - tel: URIs must contain at least one digit
 * - openpgp4fpr: URIs must have a fingerprint after the scheme
 */
export function checkUriValidation(lines: ParsedLine[]): Finding[] {
  const findings: Finding[] = [];

  for (const line of lines) {
    if (line.kind !== 'field') continue;

    const nameLower = line.name.toLowerCase();
    const allowedSchemes = SCHEME_LOOKUP[nameLower];
    if (!allowedSchemes) continue;

    const value = line.value.trim();
    const matchedScheme = allowedSchemes.find((scheme) => value.toLowerCase().startsWith(scheme));

    if (!matchedScheme) {
      findings.push({
        severity: 'error',
        lineNumber: line.lineNumber,
        title: `Invalid URI scheme for ${line.name}`,
        explanation: `The value must start with one of the allowed schemes: ${allowedSchemes.join(', ')}`,
        suggestedFix: `Change the value to use an accepted scheme, e.g. ${allowedSchemes[0]}`,
        ruleId: 'uri-invalid-scheme',
        rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.5',
      });
      continue;
    }

    // Basic syntax checks per scheme
    const syntaxError = checkSchemeSyntax(value, matchedScheme, line.name, line.lineNumber);
    if (syntaxError) {
      findings.push(syntaxError);
    }
  }

  return findings;
}

function checkSchemeSyntax(
  value: string,
  scheme: string,
  fieldName: string,
  lineNumber: number,
): Finding | null {
  const afterScheme = value.slice(scheme.length);

  switch (scheme) {
    case 'https://': {
      // Must have at least a hostname (non-empty, contains a dot or is localhost-like)
      if (!afterScheme || afterScheme.trim().length === 0) {
        return makeSyntaxFinding(
          lineNumber,
          fieldName,
          'The https:// URI is missing a hostname.',
          `Provide a full URL, e.g. https://example.com/.well-known/security.txt`,
        );
      }
      break;
    }
    case 'mailto:': {
      if (!afterScheme.includes('@')) {
        return makeSyntaxFinding(
          lineNumber,
          fieldName,
          'The mailto: URI is missing an @ sign in the address.',
          `Provide a valid email address, e.g. mailto:security@example.com`,
        );
      }
      break;
    }
    case 'tel:': {
      if (!/\d/.test(afterScheme)) {
        return makeSyntaxFinding(
          lineNumber,
          fieldName,
          'The tel: URI does not contain any digits.',
          `Provide a valid phone number, e.g. tel:+1-201-555-0123`,
        );
      }
      break;
    }
    case 'openpgp4fpr:': {
      if (!afterScheme || afterScheme.trim().length === 0) {
        return makeSyntaxFinding(
          lineNumber,
          fieldName,
          'The openpgp4fpr: URI is missing a fingerprint.',
          `Provide a PGP fingerprint, e.g. openpgp4fpr:ABC123...`,
        );
      }
      break;
    }
  }

  return null;
}

function makeSyntaxFinding(
  lineNumber: number,
  fieldName: string,
  explanation: string,
  suggestedFix: string,
): Finding {
  return {
    severity: 'error',
    lineNumber,
    title: `Invalid URI syntax for ${fieldName}`,
    explanation,
    suggestedFix,
    ruleId: 'uri-invalid-syntax',
  };
}
