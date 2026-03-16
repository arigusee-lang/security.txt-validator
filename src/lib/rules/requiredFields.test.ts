import { describe, it, expect } from 'vitest';
import { checkRequiredFields } from './requiredFields';
import { parse } from '../parser';

describe('checkRequiredFields', () => {
  it('returns no findings when both Contact and Expires are present', () => {
    const lines = parse('Contact: mailto:sec@example.com\nExpires: 2026-01-01T00:00:00z\n');
    const findings = checkRequiredFields(lines);
    expect(findings).toEqual([]);
  });

  it('reports error when Contact is missing', () => {
    const lines = parse('Expires: 2026-01-01T00:00:00z\n');
    const findings = checkRequiredFields(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: 'error',
      ruleId: 'required-contact-missing',
    });
  });

  it('reports error when Expires is missing', () => {
    const lines = parse('Contact: mailto:sec@example.com\n');
    const findings = checkRequiredFields(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: 'error',
      ruleId: 'required-expires-missing',
    });
  });

  it('reports errors when both Contact and Expires are missing', () => {
    const lines = parse('# just a comment\n');
    const findings = checkRequiredFields(lines);
    const ruleIds = findings.map(f => f.ruleId);
    expect(ruleIds).toContain('required-contact-missing');
    expect(ruleIds).toContain('required-expires-missing');
  });

  it('reports error for duplicate Expires fields', () => {
    const lines = parse(
      'Contact: mailto:sec@example.com\nExpires: 2026-01-01T00:00:00z\nExpires: 2027-01-01T00:00:00z\n'
    );
    const findings = checkRequiredFields(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: 'error',
      ruleId: 'required-expires-duplicate',
      lineNumber: 3,
    });
  });

  it('matches field names case-insensitively', () => {
    const lines = parse('CONTACT: mailto:sec@example.com\nexpires: 2026-01-01T00:00:00z\n');
    const findings = checkRequiredFields(lines);
    expect(findings).toEqual([]);
  });

  it('allows multiple Contact fields without error', () => {
    const lines = parse(
      'Contact: mailto:a@example.com\nContact: mailto:b@example.com\nExpires: 2026-01-01T00:00:00z\n'
    );
    const findings = checkRequiredFields(lines);
    expect(findings).toEqual([]);
  });

  it('ignores non-field lines (comments, blanks, invalid)', () => {
    const lines = parse('# comment\n\ninvalid line without colon\n');
    const findings = checkRequiredFields(lines);
    const ruleIds = findings.map(f => f.ruleId);
    expect(ruleIds).toContain('required-contact-missing');
    expect(ruleIds).toContain('required-expires-missing');
  });

  it('every finding has non-empty title, explanation, and suggestedFix', () => {
    const lines = parse('');
    const findings = checkRequiredFields(lines);
    for (const f of findings) {
      expect(f.title.length).toBeGreaterThan(0);
      expect(f.explanation.length).toBeGreaterThan(0);
      expect(f.suggestedFix.length).toBeGreaterThan(0);
    }
  });
});
