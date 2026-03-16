import type { ParsedLine, Finding } from './types';
import { RECOMMENDED_ORDER, KNOWN_FIELD_NAMES, FIELD_URI_SCHEMES } from './constants';

/**
 * Generates a corrected security.txt from parsed lines and validation findings.
 *
 * Algorithm:
 * 1. Remove lines flagged as `invalid`
 * 2. For each field with a correctable error (e.g., expired Expires), replace the value
 * 3. If Contact is missing, insert placeholder
 * 4. If Expires is missing or expired, insert/replace with date 365 days from now
 * 5. Preserve all valid comments in their original positions
 * 6. If sortToRecommended, reorder fields per RECOMMENDED_ORDER
 * 7. Join lines with \n and return
 */
export function generateCorrectedOutput(
  lines: ParsedLine[],
  findings: Finding[],
  options?: { sortToRecommended?: boolean },
): string {
  const sortToRecommended = options?.sortToRecommended ?? false;

  // Build a set of ruleIds for quick lookup
  const ruleIds = new Set(findings.map((f) => f.ruleId));

  // Build a set of line numbers that have expires-past errors (for replacement)
  const expiredLineNumbers = new Set(
    findings
      .filter((f) => f.ruleId === 'expires-past' && f.lineNumber != null)
      .map((f) => f.lineNumber!),
  );

  // Build a set of line numbers for duplicate Expires fields
  const duplicateExpiresLineNumbers = new Set(
    findings
      .filter((f) => f.ruleId === 'required-expires-duplicate' && f.lineNumber != null)
      .map((f) => f.lineNumber!),
  );

  const futureExpires = generateFutureExpires();

  // Step 1: Filter out invalid lines and duplicate Expires lines
  let correctedLines: ParsedLine[] = lines.filter((line) => {
    if (line.kind === 'invalid') return false;
    if (line.kind === 'field' && duplicateExpiresLineNumbers.has(line.lineNumber)) return false;
    return true;
  });

  // Step 2: Replace expired Expires values in-place
  correctedLines = correctedLines.map((line) => {
    if (
      line.kind === 'field' &&
      line.name.toLowerCase() === 'expires' &&
      expiredLineNumbers.has(line.lineNumber)
    ) {
      return { ...line, value: futureExpires, raw: `Expires: ${futureExpires}` };
    }
    return line;
  });

  // Step 2b: Fix missing URI schemes for fields with uri-invalid-scheme errors
  const uriSchemeErrorLines = new Set(
    findings
      .filter((f) => f.ruleId === 'uri-invalid-scheme' && f.lineNumber != null)
      .map((f) => f.lineNumber!),
  );

  correctedLines = correctedLines.map((line) => {
    if (line.kind !== 'field' || !uriSchemeErrorLines.has(line.lineNumber)) return line;
    const nameLower = line.name.toLowerCase();
    const value = line.value.trim();

    if (nameLower === 'contact') {
      // If it looks like an email, add mailto:
      if (value.includes('@') && !value.includes('://')) {
        const fixed = `mailto:${value}`;
        return { ...line, value: fixed, raw: `${line.name}: ${fixed}` };
      }
    }

    // For all other URI fields, prepend https:// if no scheme present
    const schemes = FIELD_URI_SCHEMES[line.name] ?? FIELD_URI_SCHEMES[Object.keys(FIELD_URI_SCHEMES).find(k => k.toLowerCase() === nameLower) ?? ''];
    if (schemes && schemes.includes('https://') && !value.includes('://')) {
      const fixed = `https://${value}`;
      return { ...line, value: fixed, raw: `${line.name}: ${fixed}` };
    }

    return line;
  });

  // Step 3 & 4: Insert missing Contact and/or Expires
  const hasContact = correctedLines.some(
    (l) => l.kind === 'field' && l.name.toLowerCase() === 'contact',
  );
  const hasExpires = correctedLines.some(
    (l) => l.kind === 'field' && l.name.toLowerCase() === 'expires',
  );

  const insertions: ParsedLine[] = [];

  if (!hasContact && ruleIds.has('required-contact-missing')) {
    insertions.push({
      kind: 'field',
      lineNumber: 0,
      raw: 'Contact: mailto:security@example.com',
      name: 'Contact',
      value: 'mailto:security@example.com',
    });
  }

  if (!hasExpires) {
    insertions.push({
      kind: 'field',
      lineNumber: 0,
      raw: `Expires: ${futureExpires}`,
      name: 'Expires',
      value: futureExpires,
    });
  }

  // Insert missing fields at the top (before other fields, but after leading comments)
  if (insertions.length > 0) {
    correctedLines = [...insertions, ...correctedLines];
  }

  // Step 6: Sort to recommended order if requested
  if (sortToRecommended) {
    correctedLines = sortLines(correctedLines);
  }

  // Step 7: Join and return
  return correctedLines.map((line) => lineToString(line)).join('\n');
}

/**
 * Generates an RFC 3339 date-time string 365 days from now.
 */
function generateFutureExpires(): string {
  const future = new Date();
  future.setUTCDate(future.getUTCDate() + 365);
  return future.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Converts a ParsedLine back to its string representation.
 */
function lineToString(line: ParsedLine): string {
  switch (line.kind) {
    case 'field':
      return `${line.name}: ${line.value}`;
    case 'comment':
      return line.raw;
    case 'blank':
      return '';
    case 'invalid':
      return line.raw;
  }
}

/**
 * Sorts lines according to RECOMMENDED_ORDER.
 *
 * Groups fields by their canonical name (case-insensitive).
 * Comments are associated with the field group that follows them.
 * Unknown fields go at the end.
 * Blank lines are removed during sorting to avoid ambiguity.
 */
function sortLines(lines: ParsedLine[]): ParsedLine[] {
  // Build groups: each group is a set of comment lines followed by field lines
  // We walk through the lines and accumulate comments until we hit a field
  const groups: { fieldName: string | null; lines: ParsedLine[] }[] = [];
  let pendingComments: ParsedLine[] = [];

  for (const line of lines) {
    if (line.kind === 'blank') {
      // Skip blank lines in sorted mode
      continue;
    }

    if (line.kind === 'comment') {
      pendingComments.push(line);
      continue;
    }

    if (line.kind === 'field') {
      const fieldNameLower = line.name.toLowerCase();
      groups.push({
        fieldName: fieldNameLower,
        lines: [...pendingComments, line],
      });
      pendingComments = [];
      continue;
    }
  }

  // If there are trailing comments with no following field, add them as a group
  if (pendingComments.length > 0) {
    groups.push({ fieldName: null, lines: pendingComments });
  }

  // Build the order index map from RECOMMENDED_ORDER
  const orderMap = new Map<string, number>();
  RECOMMENDED_ORDER.forEach((name, idx) => {
    orderMap.set(name.toLowerCase(), idx);
  });

  // Sort groups by recommended order; unknown fields go at the end
  const unknownIndex = RECOMMENDED_ORDER.length;
  groups.sort((a, b) => {
    const aIdx = a.fieldName != null ? (orderMap.get(a.fieldName) ?? unknownIndex) : unknownIndex + 1;
    const bIdx = b.fieldName != null ? (orderMap.get(b.fieldName) ?? unknownIndex) : unknownIndex + 1;
    return aIdx - bIdx;
  });

  // Flatten groups back into a single array
  return groups.flatMap((g) => g.lines);
}
