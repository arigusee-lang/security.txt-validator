import type { ParsedLine, FetchMetadata, ValidationResult, Finding, Severity, PgpInfo } from './types';
import { checkLineSyntax } from './rules/lineSyntax';
import { checkRequiredFields } from './rules/requiredFields';
import { checkExpiresField } from './rules/expiresField';
import { checkUriValidation } from './rules/uriValidation';
import { checkOptionalFields } from './rules/optionalFields';
import { checkUnknownFields } from './rules/unknownFields';
import { checkHostingChecks } from './rules/hostingChecks';
import { checkPgpSignature } from './rules/pgpSignature';

const SEVERITY_ORDER: Record<Severity, number> = {
  error: 0,
  warning: 1,
  info: 2,
};

/**
 * Validates parsed security.txt lines against RFC 9116 rules.
 * Optionally includes fetch metadata for URL-mode hosting checks.
 *
 * Never throws — all issues are captured as Finding objects.
 */
export function validate(lines: ParsedLine[], fetchMeta?: FetchMetadata, pgp?: PgpInfo): ValidationResult {
  const hasFieldLines = lines.some((line) => line.kind === 'field');

  let findings: Finding[] = [];

  if (!hasFieldLines) {
    findings.push({
      severity: 'error',
      title: 'No fields found',
      explanation: 'The input does not contain any valid fields.',
      suggestedFix: 'Add at least the required Contact and Expires fields.',
      ruleId: 'no-fields-found',
    });
  }

  // Run all rule functions and merge findings
  findings = findings.concat(
    checkLineSyntax(lines),
    checkRequiredFields(lines),
    checkExpiresField(lines),
    checkUriValidation(lines),
    checkOptionalFields(lines),
    checkUnknownFields(lines),
    checkHostingChecks(lines, fetchMeta),
    checkPgpSignature(lines, pgp),
  );

  // Sort: errors first, then warnings, then info; within each group by line number
  findings.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sevDiff !== 0) return sevDiff;
    const aLine = a.lineNumber ?? Number.MAX_SAFE_INTEGER;
    const bLine = b.lineNumber ?? Number.MAX_SAFE_INTEGER;
    return aLine - bLine;
  });

  const errorCount = findings.filter((f) => f.severity === 'error').length;
  const warningCount = findings.filter((f) => f.severity === 'warning').length;
  const infoCount = findings.filter((f) => f.severity === 'info').length;

  let status: ValidationResult['status'];
  if (errorCount > 0) {
    status = 'invalid';
  } else if (warningCount > 0) {
    status = 'valid-with-warnings';
  } else {
    status = 'valid';
  }

  return {
    status,
    errorCount,
    warningCount,
    infoCount,
    findings,
    parsedFields: lines,
  };
}
