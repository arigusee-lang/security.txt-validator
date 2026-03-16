import { describe, it, expect } from 'vitest';
import { parse } from './parser';

describe('parse', () => {
  it('parses a minimal valid security.txt', () => {
    const input = 'Contact: mailto:security@example.com\nExpires: 2025-12-31T23:59:59z\n';
    const result = parse(input);

    expect(result[0]).toEqual({
      kind: 'field', lineNumber: 1, raw: 'Contact: mailto:security@example.com',
      name: 'Contact', value: 'mailto:security@example.com',
    });
    expect(result[1]).toEqual({
      kind: 'field', lineNumber: 2, raw: 'Expires: 2025-12-31T23:59:59z',
      name: 'Expires', value: '2025-12-31T23:59:59z',
    });
    expect(result[2]).toEqual({ kind: 'blank', lineNumber: 3 });
  });

  it('classifies blank lines', () => {
    const result = parse('\n  \n\t\n');
    expect(result).toEqual([
      { kind: 'blank', lineNumber: 1 },
      { kind: 'blank', lineNumber: 2 },
      { kind: 'blank', lineNumber: 3 },
      { kind: 'blank', lineNumber: 4 },
    ]);
  });

  it('classifies comment lines', () => {
    const result = parse('# This is a comment\n#Another comment');
    expect(result[0]).toEqual({ kind: 'comment', lineNumber: 1, raw: '# This is a comment', text: ' This is a comment' });
    expect(result[1]).toEqual({ kind: 'comment', lineNumber: 2, raw: '#Another comment', text: 'Another comment' });
  });

  it('classifies invalid lines', () => {
    const result = parse('this has no colon');
    expect(result[0]).toEqual({ kind: 'invalid', lineNumber: 1, raw: 'this has no colon' });
  });

  it('strips BOM from input', () => {
    const bom = '\uFEFF';
    const result = parse(bom + 'Contact: mailto:test@example.com');
    expect(result[0]).toEqual({
      kind: 'field', lineNumber: 1, raw: 'Contact: mailto:test@example.com',
      name: 'Contact', value: 'mailto:test@example.com',
    });
  });

  it('handles \\r\\n line endings', () => {
    const result = parse('Contact: mailto:a@b.com\r\nExpires: 2026-01-01T00:00:00z\r\n');
    expect(result[0]).toEqual({
      kind: 'field', lineNumber: 1, raw: 'Contact: mailto:a@b.com',
      name: 'Contact', value: 'mailto:a@b.com',
    });
    expect(result[1]).toEqual({
      kind: 'field', lineNumber: 2, raw: 'Expires: 2026-01-01T00:00:00z',
      name: 'Expires', value: '2026-01-01T00:00:00z',
    });
  });

  it('splits on first colon only (multiple colons)', () => {
    const result = parse('Contact: https://example.com/report:issue');
    expect(result[0]).toEqual({
      kind: 'field', lineNumber: 1, raw: 'Contact: https://example.com/report:issue',
      name: 'Contact', value: 'https://example.com/report:issue',
    });
  });

  it('returns a single blank for empty input', () => {
    const result = parse('');
    expect(result).toEqual([{ kind: 'blank', lineNumber: 1 }]);
  });

  it('preserves field name casing as-is', () => {
    const result = parse('contact: mailto:a@b.com\nEXPIRES: 2026-01-01T00:00:00z');
    expect(result[0]).toMatchObject({ kind: 'field', name: 'contact' });
    expect(result[1]).toMatchObject({ kind: 'field', name: 'EXPIRES' });
  });
});

describe('parse with PGP ClearSign', () => {
  const signedInput = [
    '-----BEGIN PGP SIGNED MESSAGE-----',
    'Hash: SHA256',
    '',
    'Contact: mailto:security@example.com',
    'Expires: 2026-12-31T23:59:59z',
    '-----BEGIN PGP SIGNATURE-----',
    '',
    'iQEzBAEBCAAdFiEEexample==',
    '-----END PGP SIGNATURE-----',
  ].join('\n');

  it('strips PGP wrapper and parses inner content', () => {
    const result = parse(signedInput);
    expect(result).toHaveLength(2);
    expect(result[0]).toMatchObject({ kind: 'field', name: 'Contact' });
    expect(result[1]).toMatchObject({ kind: 'field', name: 'Expires' });
  });

  it('returns PGP info when withPgp is true', () => {
    const result = parse(signedInput, { withPgp: true });
    expect(result.pgp.isSigned).toBe(true);
    expect(result.pgp.wellFormed).toBe(true);
    expect(result.pgp.hashAlgorithm).toBe('SHA256');
    expect(result.lines).toHaveLength(2);
  });

  it('reports not signed for regular input', () => {
    const result = parse('Contact: mailto:a@b.com', { withPgp: true });
    expect(result.pgp.isSigned).toBe(false);
  });

  it('reports malformed when signature block is missing', () => {
    const malformed = [
      '-----BEGIN PGP SIGNED MESSAGE-----',
      'Hash: SHA256',
      '',
      'Contact: mailto:security@example.com',
    ].join('\n');
    const result = parse(malformed, { withPgp: true });
    expect(result.pgp.isSigned).toBe(true);
    expect(result.pgp.wellFormed).toBe(false);
  });

  it('handles PGP signed input with comments', () => {
    const input = [
      '-----BEGIN PGP SIGNED MESSAGE-----',
      'Hash: SHA512',
      '',
      '# Security contact',
      'Contact: mailto:sec@example.com',
      'Expires: 2026-06-01T00:00:00Z',
      '-----BEGIN PGP SIGNATURE-----',
      'abc123==',
      '-----END PGP SIGNATURE-----',
    ].join('\n');
    const result = parse(input, { withPgp: true });
    expect(result.pgp.hashAlgorithm).toBe('SHA512');
    expect(result.lines[0]).toMatchObject({ kind: 'comment' });
    expect(result.lines[1]).toMatchObject({ kind: 'field', name: 'Contact' });
  });
});
