import { describe, it, expect } from 'vitest';
import { checkHostingChecks } from './hostingChecks';
import type { ParsedLine, FetchMetadata } from '../types';

const dummyLines: ParsedLine[] = [
  { kind: 'field', lineNumber: 1, raw: 'Contact: mailto:a@b.com', name: 'Contact', value: 'mailto:a@b.com' },
];

function makeMeta(overrides: Partial<FetchMetadata> = {}): FetchMetadata {
  return {
    contentType: 'text/plain; charset=utf-8',
    fetchedFrom: 'https://example.com/.well-known/security.txt',
    redirectChain: [],
    wellKnownFound: true,
    fallbackUsed: false,
    usedHttps: true,
    ...overrides,
  };
}

describe('checkHostingChecks', () => {
  it('returns empty array when fetchMeta is undefined (paste mode)', () => {
    expect(checkHostingChecks(dummyLines)).toEqual([]);
  });

  it('returns empty array when all hosting checks pass', () => {
    expect(checkHostingChecks(dummyLines, makeMeta())).toEqual([]);
  });

  it('warns when Content-Type does not contain text/plain', () => {
    const findings = checkHostingChecks(dummyLines, makeMeta({ contentType: 'text/html' }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('warning');
    expect(findings[0].ruleId).toBe('hosting-content-type');
    expect(findings[0].lineNumber).toBeUndefined();
  });

  it('warns when fallback location was used', () => {
    const findings = checkHostingChecks(dummyLines, makeMeta({
      fallbackUsed: true,
      wellKnownFound: false,
    }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('warning');
    expect(findings[0].ruleId).toBe('hosting-location');
    expect(findings[0].lineNumber).toBeUndefined();
  });

  it('does not warn about location when wellKnownFound is true even if fallbackUsed', () => {
    const findings = checkHostingChecks(dummyLines, makeMeta({
      fallbackUsed: true,
      wellKnownFound: true,
    }));
    expect(findings).toEqual([]);
  });

  it('reports info when redirect chain goes to a different domain', () => {
    const chain = ['https://other-domain.com/a', 'https://other-domain.com/b'];
    const findings = checkHostingChecks(dummyLines, makeMeta({ redirectChain: chain }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('info');
    expect(findings[0].ruleId).toBe('hosting-redirect');
    expect(findings[0].explanation).toContain('https://other-domain.com/a');
    expect(findings[0].explanation).toContain('https://other-domain.com/b');
    expect(findings[0].lineNumber).toBeUndefined();
  });

  it('does not report info for same-domain www redirect', () => {
    const chain = ['https://www.example.com/.well-known/security.txt'];
    const findings = checkHostingChecks(dummyLines, makeMeta({ redirectChain: chain }));
    expect(findings).toHaveLength(0);
  });

  it('reports multiple findings when multiple issues exist', () => {
    const findings = checkHostingChecks(dummyLines, makeMeta({
      contentType: 'application/json',
      fallbackUsed: true,
      wellKnownFound: false,
      redirectChain: ['https://other-domain.com/redirect'],
    }));
    expect(findings).toHaveLength(3);
    const ruleIds = findings.map(f => f.ruleId);
    expect(ruleIds).toContain('hosting-content-type');
    expect(ruleIds).toContain('hosting-location');
    expect(ruleIds).toContain('hosting-redirect');
  });

  it('all findings have complete human-readable content', () => {
    const findings = checkHostingChecks(dummyLines, makeMeta({
      contentType: 'text/html',
      fallbackUsed: true,
      wellKnownFound: false,
      redirectChain: ['https://other-domain.com/r'],
    }));
    for (const f of findings) {
      expect(f.title).toBeTruthy();
      expect(f.explanation).toBeTruthy();
      expect(f.suggestedFix).toBeTruthy();
      expect(f.ruleId).toBeTruthy();
    }
  });
});
