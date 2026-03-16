import { describe, it, expect } from 'vitest';
import { validate } from './validator';
import type { ParsedLine, FetchMetadata } from './types';

describe('validate', () => {
  it('returns "valid" for a well-formed security.txt', () => {
    const futureDate = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString();
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: `Contact: mailto:sec@example.com`, name: 'Contact', value: 'mailto:sec@example.com' },
      { kind: 'field', lineNumber: 2, raw: `Expires: ${futureDate}`, name: 'Expires', value: futureDate },
    ];

    const result = validate(lines);

    expect(result.status).toBe('valid');
    expect(result.errorCount).toBe(0);
    expect(result.warningCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.parsedFields).toBe(lines);
  });

  it('returns "invalid" when required fields are missing', () => {
    const lines: ParsedLine[] = [
      { kind: 'comment', lineNumber: 1, raw: '# just a comment', text: ' just a comment' },
    ];

    const result = validate(lines);

    expect(result.status).toBe('invalid');
    expect(result.errorCount).toBeGreaterThanOrEqual(2);
    expect(result.findings.some(f => f.ruleId === 'required-contact-missing')).toBe(true);
    expect(result.findings.some(f => f.ruleId === 'required-expires-missing')).toBe(true);
  });

  it('reports "no-fields-found" for empty input', () => {
    const result = validate([]);

    expect(result.status).toBe('invalid');
    expect(result.findings.some(f => f.ruleId === 'no-fields-found')).toBe(true);
  });

  it('reports "no-fields-found" for input with only comments and blanks', () => {
    const lines: ParsedLine[] = [
      { kind: 'comment', lineNumber: 1, raw: '# comment', text: ' comment' },
      { kind: 'blank', lineNumber: 2 },
      { kind: 'comment', lineNumber: 3, raw: '# another', text: ' another' },
    ];

    const result = validate(lines);

    expect(result.findings.some(f => f.ruleId === 'no-fields-found')).toBe(true);
  });

  it('reports "no-fields-found" for input with only invalid lines', () => {
    const lines: ParsedLine[] = [
      { kind: 'invalid', lineNumber: 1, raw: 'garbage' },
    ];

    const result = validate(lines);

    expect(result.findings.some(f => f.ruleId === 'no-fields-found')).toBe(true);
    expect(result.findings.some(f => f.ruleId === 'line-invalid-syntax')).toBe(true);
  });

  it('sorts findings: errors first, then warnings, then info', () => {
    const futureDate = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString();
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'Contact: mailto:sec@example.com', name: 'Contact', value: 'mailto:sec@example.com' },
      { kind: 'field', lineNumber: 2, raw: `Expires: ${futureDate}`, name: 'Expires', value: futureDate },
      { kind: 'field', lineNumber: 3, raw: 'X-Custom: value', name: 'X-Custom', value: 'value' },
    ];

    const result = validate(lines);

    // Unknown field produces a warning
    expect(result.status).toBe('valid-with-warnings');
    expect(result.warningCount).toBe(1);

    // Verify sort order: all errors before warnings before info
    for (let i = 1; i < result.findings.length; i++) {
      const prev = result.findings[i - 1];
      const curr = result.findings[i];
      const order = { error: 0, warning: 1, info: 2 };
      expect(order[prev.severity]).toBeLessThanOrEqual(order[curr.severity]);
    }
  });

  it('returns "valid-with-warnings" when there are warnings but no errors', () => {
    const futureDate = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString();
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'Contact: mailto:sec@example.com', name: 'Contact', value: 'mailto:sec@example.com' },
      { kind: 'field', lineNumber: 2, raw: `Expires: ${futureDate}`, name: 'Expires', value: futureDate },
      { kind: 'field', lineNumber: 3, raw: 'FooBar: something', name: 'FooBar', value: 'something' },
    ];

    const result = validate(lines);

    expect(result.status).toBe('valid-with-warnings');
    expect(result.errorCount).toBe(0);
    expect(result.warningCount).toBe(1);
  });

  it('includes hosting check findings when fetchMeta is provided', () => {
    const futureDate = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString();
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'Contact: mailto:sec@example.com', name: 'Contact', value: 'mailto:sec@example.com' },
      { kind: 'field', lineNumber: 2, raw: `Expires: ${futureDate}`, name: 'Expires', value: futureDate },
    ];
    const fetchMeta: FetchMetadata = {
      contentType: 'text/html',
      fetchedFrom: 'https://example.com/security.txt',
      redirectChain: ['https://other-domain.com/.well-known/security.txt'],
      wellKnownFound: false,
      fallbackUsed: true,
      usedHttps: true,
    };

    const result = validate(lines, fetchMeta);

    expect(result.findings.some(f => f.ruleId === 'hosting-content-type')).toBe(true);
    expect(result.findings.some(f => f.ruleId === 'hosting-location')).toBe(true);
    expect(result.findings.some(f => f.ruleId === 'hosting-redirect')).toBe(true);
  });

  it('counts errorCount, warningCount, infoCount correctly', () => {
    const futureDate = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString();
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'Contact: mailto:sec@example.com', name: 'Contact', value: 'mailto:sec@example.com' },
      { kind: 'field', lineNumber: 2, raw: `Expires: ${futureDate}`, name: 'Expires', value: futureDate },
    ];
    const fetchMeta: FetchMetadata = {
      contentType: 'text/html',
      fetchedFrom: 'https://example.com/security.txt',
      redirectChain: ['https://other-domain.com/.well-known/security.txt'],
      wellKnownFound: false,
      fallbackUsed: true,
      usedHttps: true,
    };

    const result = validate(lines, fetchMeta);

    const errors = result.findings.filter(f => f.severity === 'error').length;
    const warnings = result.findings.filter(f => f.severity === 'warning').length;
    const infos = result.findings.filter(f => f.severity === 'info').length;

    expect(result.errorCount).toBe(errors);
    expect(result.warningCount).toBe(warnings);
    expect(result.infoCount).toBe(infos);
  });

  it('never throws, even with unusual input', () => {
    expect(() => validate([])).not.toThrow();
    expect(() => validate([{ kind: 'blank', lineNumber: 1 }])).not.toThrow();
    expect(() => validate([{ kind: 'invalid', lineNumber: 1, raw: '\x00\x01\x02' }])).not.toThrow();
  });
});
