import { describe, it, expect } from 'vitest';
import { checkLineSyntax } from './lineSyntax';
import type { ParsedLine } from '../types';

describe('checkLineSyntax', () => {
  it('returns no findings when there are no invalid lines', () => {
    const lines: ParsedLine[] = [
      { kind: 'field', lineNumber: 1, raw: 'Contact: mailto:a@b.com', name: 'Contact', value: 'mailto:a@b.com' },
      { kind: 'comment', lineNumber: 2, raw: '# a comment', text: 'a comment' },
      { kind: 'blank', lineNumber: 3 },
    ];
    expect(checkLineSyntax(lines)).toEqual([]);
  });

  it('returns an error for each invalid line', () => {
    const lines: ParsedLine[] = [
      { kind: 'invalid', lineNumber: 1, raw: 'garbage line' },
      { kind: 'field', lineNumber: 2, raw: 'Contact: mailto:a@b.com', name: 'Contact', value: 'mailto:a@b.com' },
      { kind: 'invalid', lineNumber: 3, raw: '???what???' },
    ];
    const findings = checkLineSyntax(lines);
    expect(findings).toHaveLength(2);

    expect(findings[0].severity).toBe('error');
    expect(findings[0].lineNumber).toBe(1);
    expect(findings[0].ruleId).toBe('line-invalid-syntax');
    expect(findings[0].explanation).toContain('garbage line');

    expect(findings[1].severity).toBe('error');
    expect(findings[1].lineNumber).toBe(3);
    expect(findings[1].ruleId).toBe('line-invalid-syntax');
    expect(findings[1].explanation).toContain('???what???');
  });

  it('includes raw content in the explanation', () => {
    const lines: ParsedLine[] = [
      { kind: 'invalid', lineNumber: 5, raw: 'no colon here' },
    ];
    const findings = checkLineSyntax(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0].explanation).toContain('no colon here');
  });

  it('returns an empty array for empty input', () => {
    expect(checkLineSyntax([])).toEqual([]);
  });

  it('each finding has all required fields', () => {
    const lines: ParsedLine[] = [
      { kind: 'invalid', lineNumber: 1, raw: 'bad' },
    ];
    const [finding] = checkLineSyntax(lines);
    expect(finding.severity).toBe('error');
    expect(finding.lineNumber).toBe(1);
    expect(finding.title).toBeTruthy();
    expect(finding.explanation).toBeTruthy();
    expect(finding.suggestedFix).toBeTruthy();
    expect(finding.ruleId).toBe('line-invalid-syntax');
  });
});
