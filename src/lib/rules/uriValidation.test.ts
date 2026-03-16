import { describe, it, expect } from 'vitest';
import { checkUriValidation } from './uriValidation';
import type { ParsedLine } from '../types';

function field(name: string, value: string, lineNumber = 1): ParsedLine {
  return { kind: 'field', lineNumber, raw: `${name}: ${value}`, name, value };
}

describe('checkUriValidation', () => {
  // --- Valid URIs produce no findings ---

  it('accepts valid Contact mailto URI', () => {
    const findings = checkUriValidation([field('Contact', 'mailto:sec@example.com')]);
    expect(findings).toHaveLength(0);
  });

  it('accepts valid Contact https URI', () => {
    const findings = checkUriValidation([field('Contact', 'https://example.com/contact')]);
    expect(findings).toHaveLength(0);
  });

  it('accepts valid Contact tel URI', () => {
    const findings = checkUriValidation([field('Contact', 'tel:+1-201-555-0123')]);
    expect(findings).toHaveLength(0);
  });

  it('accepts valid Encryption https URI', () => {
    const findings = checkUriValidation([field('Encryption', 'https://example.com/key.asc')]);
    expect(findings).toHaveLength(0);
  });

  it('accepts valid Encryption openpgp4fpr URI', () => {
    const findings = checkUriValidation([field('Encryption', 'openpgp4fpr:ABCDEF1234567890')]);
    expect(findings).toHaveLength(0);
  });

  it('accepts valid Policy https URI', () => {
    const findings = checkUriValidation([field('Policy', 'https://example.com/policy')]);
    expect(findings).toHaveLength(0);
  });

  it('accepts valid CSAF https URI', () => {
    const findings = checkUriValidation([field('CSAF', 'https://example.com/.well-known/csaf')]);
    expect(findings).toHaveLength(0);
  });

  // --- Invalid scheme ---

  it('reports error for Contact with http:// scheme', () => {
    const findings = checkUriValidation([field('Contact', 'http://example.com')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('uri-invalid-scheme');
    expect(findings[0].severity).toBe('error');
  });

  it('reports error for Encryption with http:// scheme', () => {
    const findings = checkUriValidation([field('Encryption', 'http://example.com/key')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('uri-invalid-scheme');
  });

  it('reports error for Policy with ftp:// scheme', () => {
    const findings = checkUriValidation([field('Policy', 'ftp://example.com/policy')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('uri-invalid-scheme');
  });

  it('reports error for Hiring with plain text value', () => {
    const findings = checkUriValidation([field('Hiring', 'we are hiring!')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('uri-invalid-scheme');
  });

  // --- Invalid syntax ---

  it('reports error for https:// with no hostname', () => {
    const findings = checkUriValidation([field('Policy', 'https://')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('uri-invalid-syntax');
  });

  it('reports error for mailto: without @', () => {
    const findings = checkUriValidation([field('Contact', 'mailto:nope')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('uri-invalid-syntax');
  });

  it('reports error for tel: without digits', () => {
    const findings = checkUriValidation([field('Contact', 'tel:abc')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('uri-invalid-syntax');
  });

  it('reports error for openpgp4fpr: with no fingerprint', () => {
    const findings = checkUriValidation([field('Encryption', 'openpgp4fpr:')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('uri-invalid-syntax');
  });

  // --- Case insensitivity ---

  it('validates field names case-insensitively', () => {
    const findings = checkUriValidation([field('CONTACT', 'http://example.com')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('uri-invalid-scheme');
  });

  it('validates field names with mixed case', () => {
    const findings = checkUriValidation([field('Canonical', 'https://example.com/.well-known/security.txt')]);
    expect(findings).toHaveLength(0);
  });

  // --- Non-URI fields are ignored ---

  it('ignores Expires field', () => {
    const findings = checkUriValidation([field('Expires', '2025-12-31T23:59:59z')]);
    expect(findings).toHaveLength(0);
  });

  it('ignores Preferred-Languages field', () => {
    const findings = checkUriValidation([field('Preferred-Languages', 'en, fr')]);
    expect(findings).toHaveLength(0);
  });

  // --- Non-field lines are ignored ---

  it('ignores comments and blanks', () => {
    const lines: ParsedLine[] = [
      { kind: 'comment', lineNumber: 1, raw: '# comment', text: 'comment' },
      { kind: 'blank', lineNumber: 2 },
    ];
    expect(checkUriValidation(lines)).toHaveLength(0);
  });

  // --- Multiple fields ---

  it('reports multiple errors for multiple invalid fields', () => {
    const lines: ParsedLine[] = [
      field('Contact', 'ftp://bad', 1),
      field('Policy', 'http://bad', 2),
      field('Encryption', 'ftp://bad', 3),
    ];
    const findings = checkUriValidation(lines);
    expect(findings).toHaveLength(3);
    expect(findings.every(f => f.ruleId === 'uri-invalid-scheme')).toBe(true);
  });

  // --- Finding structure ---

  it('includes all required Finding fields', () => {
    const findings = checkUriValidation([field('Contact', 'ftp://bad', 5)]);
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.severity).toBe('error');
    expect(f.lineNumber).toBe(5);
    expect(f.title).toBeTruthy();
    expect(f.explanation).toBeTruthy();
    expect(f.suggestedFix).toBeTruthy();
    expect(f.ruleId).toBeTruthy();
  });
});
