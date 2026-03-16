import { describe, it, expect } from 'vitest';
import { checkOptionalFields } from './optionalFields';
import type { ParsedLine } from '../types';

function langField(value: string, lineNumber = 1): ParsedLine {
  return { kind: 'field', lineNumber, raw: `Preferred-Languages: ${value}`, name: 'Preferred-Languages', value };
}

describe('checkOptionalFields', () => {
  it('returns no findings when no Preferred-Languages field is present', () => {
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'Contact: mailto:a@b.com', name: 'Contact', value: 'mailto:a@b.com' },
    ];
    expect(checkOptionalFields(lines)).toEqual([]);
  });

  it('accepts a single valid BCP 47 tag', () => {
    expect(checkOptionalFields([langField('en')])).toEqual([]);
  });

  it('accepts multiple valid BCP 47 tags', () => {
    expect(checkOptionalFields([langField('en, fr, de')])).toEqual([]);
  });

  it('accepts tags with region subtags', () => {
    expect(checkOptionalFields([langField('en-US, zh-Hans, pt-BR')])).toEqual([]);
  });

  it('accepts 3-letter primary language subtags', () => {
    expect(checkOptionalFields([langField('yue, sgn')])).toEqual([]);
  });

  it('reports error for invalid tag', () => {
    const findings = checkOptionalFields([langField('en, 123invalid')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('error');
    expect(findings[0].ruleId).toBe('preferred-languages-invalid');
    expect(findings[0].lineNumber).toBe(1);
  });

  it('reports error for empty tag in list', () => {
    const findings = checkOptionalFields([langField('en, , fr')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('preferred-languages-invalid');
  });

  it('reports error for tag with only numbers', () => {
    const findings = checkOptionalFields([langField('123')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('preferred-languages-invalid');
  });

  it('trims whitespace around tags before validation', () => {
    expect(checkOptionalFields([langField('  en ,  fr  , de  ')])).toEqual([]);
  });

  it('is case-insensitive on field name', () => {
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'preferred-languages: en', name: 'preferred-languages', value: 'en' },
    ];
    expect(checkOptionalFields(lines)).toEqual([]);
  });

  it('handles uppercase field name', () => {
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'PREFERRED-LANGUAGES: en', name: 'PREFERRED-LANGUAGES', value: 'en' },
    ];
    expect(checkOptionalFields(lines)).toEqual([]);
  });

  it('ignores non-field lines', () => {
    const lines: ParsedLine[] = [
      { kind: 'comment', lineNumber: 1, raw: '# comment', text: 'comment' },
      { kind: 'blank', lineNumber: 2 },
    ];
    expect(checkOptionalFields(lines)).toEqual([]);
  });

  it('reports one error per Preferred-Languages field with invalid tags', () => {
    const lines: ParsedLine[] = [
      langField('!!!', 1),
      langField('en, @@@', 2),
    ];
    const findings = checkOptionalFields(lines);
    expect(findings).toHaveLength(2);
    expect(findings[0].lineNumber).toBe(1);
    expect(findings[1].lineNumber).toBe(2);
  });
});
