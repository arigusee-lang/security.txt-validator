import { describe, it, expect } from 'vitest';
import { checkUnknownFields } from './unknownFields';
import type { ParsedLine } from '../types';

describe('checkUnknownFields', () => {
  it('returns no findings for known fields', () => {
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'Contact: mailto:sec@example.com', name: 'Contact', value: 'mailto:sec@example.com' },
      { kind: 'field', lineNumber: 2, raw: 'Expires: 2025-12-01T00:00:00Z', name: 'Expires', value: '2025-12-01T00:00:00Z' },
    ];
    expect(checkUnknownFields(lines)).toEqual([]);
  });

  it('returns a warning for an unknown field', () => {
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'X-Custom: value', name: 'X-Custom', value: 'value' },
    ];
    const findings = checkUnknownFields(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('warning');
    expect(findings[0].ruleId).toBe('unknown-field');
    expect(findings[0].lineNumber).toBe(1);
    expect(findings[0].title).toBeTruthy();
    expect(findings[0].explanation).toContain('X-Custom');
    expect(findings[0].suggestedFix).toBeTruthy();
  });

  it('is case-insensitive for known field names', () => {
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'CONTACT: mailto:a@b.com', name: 'CONTACT', value: 'mailto:a@b.com' },
      { kind: 'field', lineNumber: 2, raw: 'expires: 2025-12-01T00:00:00Z', name: 'expires', value: '2025-12-01T00:00:00Z' },
      { kind: 'field', lineNumber: 3, raw: 'Preferred-Languages: en', name: 'Preferred-Languages', value: 'en' },
    ];
    expect(checkUnknownFields(lines)).toEqual([]);
  });

  it('skips non-field lines', () => {
    const lines: ParsedLine[] = [
      { kind: 'comment', lineNumber: 1, raw: '# comment', text: 'comment' },
      { kind: 'blank', lineNumber: 2 },
      { kind: 'invalid', lineNumber: 3, raw: 'garbage' },
    ];
    expect(checkUnknownFields(lines)).toEqual([]);
  });

  it('reports multiple unknown fields', () => {
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'Foo: bar', name: 'Foo', value: 'bar' },
      { kind: 'field', lineNumber: 2, raw: 'Contact: mailto:a@b.com', name: 'Contact', value: 'mailto:a@b.com' },
      { kind: 'field', lineNumber: 3, raw: 'Baz: qux', name: 'Baz', value: 'qux' },
    ];
    const findings = checkUnknownFields(lines);
    expect(findings).toHaveLength(2);
    expect(findings[0].lineNumber).toBe(1);
    expect(findings[1].lineNumber).toBe(3);
  });

  it('does not abort validation — known fields still pass through', () => {
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'Unknown: val', name: 'Unknown', value: 'val' },
      { kind: 'field', lineNumber: 2, raw: 'Contact: mailto:a@b.com', name: 'Contact', value: 'mailto:a@b.com' },
    ];
    const findings = checkUnknownFields(lines);
    // Only the unknown field produces a finding; known fields are untouched
    expect(findings).toHaveLength(1);
    expect(findings[0].explanation).toContain('Unknown');
  });
});
