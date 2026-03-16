import { describe, it, expect } from 'vitest';
import { checkPgpSignature } from './pgpSignature';
import type { ParsedLine, PgpInfo } from '../types';

const dummyLines: ParsedLine[] = [
  { kind: 'field', lineNumber: 1, raw: 'Contact: mailto:a@b.com', name: 'Contact', value: 'mailto:a@b.com' },
];

describe('checkPgpSignature', () => {
  it('returns empty array when pgp is undefined', () => {
    expect(checkPgpSignature(dummyLines)).toEqual([]);
  });

  it('returns empty array when not signed', () => {
    const pgp: PgpInfo = { isSigned: false, wellFormed: false };
    expect(checkPgpSignature(dummyLines, pgp)).toEqual([]);
  });

  it('returns info finding for well-formed PGP signature', () => {
    const pgp: PgpInfo = { isSigned: true, wellFormed: true, hashAlgorithm: 'SHA256' };
    const findings = checkPgpSignature(dummyLines, pgp);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('info');
    expect(findings[0].ruleId).toBe('pgp-signed');
    expect(findings[0].explanation).toContain('SHA256');
  });

  it('returns info finding without hash algorithm', () => {
    const pgp: PgpInfo = { isSigned: true, wellFormed: true };
    const findings = checkPgpSignature(dummyLines, pgp);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('info');
    expect(findings[0].ruleId).toBe('pgp-signed');
    expect(findings[0].explanation).not.toContain('undefined');
  });

  it('returns warning for malformed PGP signature', () => {
    const pgp: PgpInfo = { isSigned: true, wellFormed: false };
    const findings = checkPgpSignature(dummyLines, pgp);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('warning');
    expect(findings[0].ruleId).toBe('pgp-malformed');
  });

  it('all findings have required fields', () => {
    const pgp: PgpInfo = { isSigned: true, wellFormed: true, hashAlgorithm: 'SHA512' };
    for (const f of checkPgpSignature(dummyLines, pgp)) {
      expect(f.title).toBeTruthy();
      expect(f.explanation).toBeTruthy();
      expect(f.suggestedFix).toBeTruthy();
      expect(f.ruleId).toBeTruthy();
      expect(f.rfcRef).toContain('rfc9116');
    }
  });
});
