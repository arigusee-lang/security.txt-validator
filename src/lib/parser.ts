import type { ParsedLine, PgpInfo, ParseResult } from './types';

const PGP_SIGNED_HEADER = '-----BEGIN PGP SIGNED MESSAGE-----';
const PGP_SIGNATURE_BEGIN = '-----BEGIN PGP SIGNATURE-----';
const PGP_SIGNATURE_END = '-----END PGP SIGNATURE-----';

/**
 * Strips a PGP ClearSign wrapper from raw input, if present.
 *
 * ClearSign format (RFC 4880 §7):
 *   -----BEGIN PGP SIGNED MESSAGE-----
 *   Hash: SHA256
 *   <blank line>
 *   <actual content>
 *   -----BEGIN PGP SIGNATURE-----
 *   <base64 signature>
 *   -----END PGP SIGNATURE-----
 *
 * Returns the inner content and PGP metadata.
 */
export function stripPgpWrapper(raw: string): { content: string; pgp: PgpInfo } {
  const trimmed = raw.trim();

  if (!trimmed.startsWith(PGP_SIGNED_HEADER)) {
    return { content: raw, pgp: { isSigned: false, wellFormed: false } };
  }

  const sigBeginIdx = trimmed.indexOf(PGP_SIGNATURE_BEGIN);
  const sigEndIdx = trimmed.indexOf(PGP_SIGNATURE_END);

  // Has header but missing signature block ? malformed
  if (sigBeginIdx === -1 || sigEndIdx === -1) {
    return { content: raw, pgp: { isSigned: true, wellFormed: false } };
  }

  // Extract the part between the header line and the signature block
  const afterHeader = trimmed.slice(PGP_SIGNED_HEADER.length, sigBeginIdx);

  // Parse Hash: header and find the blank line separator
  let hashAlgorithm: string | undefined;
  const headerLines = afterHeader.split('\n');
  let contentStartIdx = 0;
  let foundBlankSeparator = false;

  for (let i = 0; i < headerLines.length; i++) {
    const line = headerLines[i].replace(/\r$/, '').trim();

    // Skip the very first line if it's empty (newline right after header marker)
    if (i === 0 && line === '') continue;

    // Hash header line
    const hashMatch = line.match(/^Hash:\s*(.+)$/i);
    if (hashMatch) {
      hashAlgorithm = hashMatch[1].trim();
      continue;
    }

    // First blank line after headers marks start of content
    if (line === '') {
      contentStartIdx = i + 1;
      foundBlankSeparator = true;
      break;
    }
  }

  // If no blank separator found, treat everything after header as content
  if (!foundBlankSeparator) {
    contentStartIdx = 1;
  }

  const contentLines = headerLines.slice(contentStartIdx);
  const content = contentLines.join('\n').replace(/\r?\n$/, '');

  return {
    content,
    pgp: { isSigned: true, hashAlgorithm, wellFormed: true },
  };
}


/**
 * Parses raw security.txt content into structured lines.
 * Automatically detects and strips PGP ClearSign wrappers.
 *
 * Algorithm:
 * 1. Strip BOM if present (U+FEFF at start of input)
 * 2. Detect and strip PGP ClearSign wrapper if present
 * 3. Split input on \n (handle \r\n by trimming \r)
 * 4. For each line, assign a 1-based line number
 * 5. Empty or whitespace-only ? blank
 * 6. Starts with # ? comment
 * 7. Contains : ? field (split on first :)
 * 8. Otherwise ? invalid
 */
export function parse(raw: string): ParsedLine[];
export function parse(raw: string, options: { withPgp: true }): ParseResult;
export function parse(raw: string, options?: { withPgp?: boolean }): ParsedLine[] | ParseResult {
  // Strip BOM if present
  const input = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;

  const { content, pgp } = stripPgpWrapper(input);

  const textLines = content.split('\n');
  const result: ParsedLine[] = [];

  for (let i = 0; i < textLines.length; i++) {
    const lineNumber = i + 1;
    // Handle \r\n by trimming trailing \r
    const line = textLines[i].replace(/\r$/, '');

    if (line.trim() === '') {
      result.push({ kind: 'blank', lineNumber });
    } else if (line.startsWith('#')) {
      result.push({ kind: 'comment', lineNumber, raw: line, text: line.slice(1) });
    } else if (line.includes(':')) {
      const colonIndex = line.indexOf(':');
      const name = line.slice(0, colonIndex).trim();
      const value = line.slice(colonIndex + 1).trim();
      result.push({ kind: 'field', lineNumber, raw: line, name, value });
    } else {
      result.push({ kind: 'invalid', lineNumber, raw: line });
    }
  }

  if (options?.withPgp) {
    return { lines: result, pgp };
  }

  return result;
}
