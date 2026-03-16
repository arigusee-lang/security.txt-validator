import type { ParsedLine, Finding, PgpInfo } from '../types';

/**
 * Checks PGP ClearSign wrapper status and reports findings.
 *
 * Rules:
 * - If signed and well-formed ? info: file is PGP signed
 * - If signed but malformed ? warning: PGP structure is broken
 * - If not signed ? no finding (signing is optional per RFC 9116 §2.3)
 */
export function checkPgpSignature(_lines: ParsedLine[], pgp?: PgpInfo): Finding[] {
  if (!pgp || !pgp.isSigned) return [];

  const findings: Finding[] = [];

  if (pgp.wellFormed) {
    findings.push({
      severity: 'info',
      title: 'PGP signed',
      explanation: `This file is digitally signed with PGP ClearSign${pgp.hashAlgorithm ? ` (${pgp.hashAlgorithm})` : ''}. The signature helps verify the file has not been tampered with.`,
      suggestedFix: 'No action needed. Ensure the signing key is published so verifiers can validate the signature.',
      ruleId: 'pgp-signed',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.3',
    });
  } else {
    findings.push({
      severity: 'warning',
      title: 'Malformed PGP signature',
      explanation: 'The file appears to start with a PGP ClearSign header but the signature block is missing or incomplete.',
      suggestedFix: 'Ensure the file contains both -----BEGIN PGP SIGNED MESSAGE----- and a complete -----BEGIN/END PGP SIGNATURE----- block.',
      ruleId: 'pgp-malformed',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-2.3',
    });
  }

  return findings;
}
