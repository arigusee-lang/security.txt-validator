import type { ParsedLine, Finding, FetchMetadata } from '../types';

/**
 * Checks FetchMetadata for hosting configuration issues (URL mode only).
 *
 * These findings have no line numbers because they relate to how the
 * file is served, not to the file content itself.
 *
 * If fetchMeta is undefined (paste mode), returns an empty array.
 */
export function checkHostingChecks(lines: ParsedLine[], fetchMeta?: FetchMetadata): Finding[] {
  if (!fetchMeta) return [];

  const findings: Finding[] = [];

  // 1. Content-Type must contain text/plain
  if (!fetchMeta.contentType.includes('text/plain')) {
    findings.push({
      severity: 'warning',
      title: 'Incorrect Content-Type',
      explanation: 'RFC 9116 requires text/plain content type',
      suggestedFix: 'Configure your web server to serve security.txt with Content-Type: text/plain; charset=utf-8.',
      ruleId: 'hosting-content-type',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-3',
    });
  }

  // 2. Fallback location used instead of /.well-known/
  if (fetchMeta.fallbackUsed && !fetchMeta.wellKnownFound) {
    findings.push({
      severity: 'warning',
      title: 'Non-standard file location',
      explanation: 'Recommend /.well-known/ location',
      suggestedFix: 'Move your security.txt file to /.well-known/security.txt for RFC 9116 compliance.',
      ruleId: 'hosting-location',
      rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-3',
    });
  }

  // 3. Redirect chain — only report if redirects go to a different domain (not just www variant)
  if (fetchMeta.redirectChain.length > 0) {
    const originHost = new URL(fetchMeta.fetchedFrom).hostname.replace(/^www\./, '');
    const crossDomain = fetchMeta.redirectChain.some(url => {
      try {
        return new URL(url).hostname.replace(/^www\./, '') !== originHost;
      } catch { return true; }
    });

    if (crossDomain) {
      findings.push({
        severity: 'info',
        title: 'Redirect chain detected',
        explanation: `The request was redirected through: ${fetchMeta.redirectChain.join(' ? ')}`,
        suggestedFix: 'Consider serving security.txt directly without redirects to improve reliability.',
        ruleId: 'hosting-redirect',
        rfcRef: 'https://www.rfc-editor.org/rfc/rfc9116#section-5.2',
      });
    }
  }

  return findings;
}
