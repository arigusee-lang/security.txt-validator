import { describe, it, expect, vi, afterEach } from 'vitest';
import { checkExpiresField } from './expiresField';
import { parse } from '../parser';

/** Helper to build a minimal valid input with a given Expires value */
function makeInput(expiresValue: string): string {
  return `Contact: mailto:sec@example.com\nExpires: ${expiresValue}\n`;
}

/** Returns an ISO string N days from now */
function daysFromNow(days: number): string {
  const d = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  return d.toISOString().replace('.000Z', 'Z').replace(/\.\d+Z$/, 'Z');
}

describe('checkExpiresField', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns no findings for a valid future Expires within 30-365 days', () => {
    const lines = parse(makeInput(daysFromNow(180)));
    const findings = checkExpiresField(lines);
    expect(findings).toEqual([]);
  });

  it('skips validation when there are 0 Expires fields', () => {
    const lines = parse('Contact: mailto:sec@example.com\n');
    const findings = checkExpiresField(lines);
    expect(findings).toEqual([]);
  });

  it('skips validation when there are 2+ Expires fields', () => {
    const lines = parse(
      `Contact: mailto:sec@example.com\nExpires: ${daysFromNow(90)}\nExpires: ${daysFromNow(180)}\n`
    );
    const findings = checkExpiresField(lines);
    expect(findings).toEqual([]);
  });

  it('reports error for invalid RFC 3339 format', () => {
    const lines = parse(makeInput('not-a-date'));
    const findings = checkExpiresField(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: 'error',
      ruleId: 'expires-invalid-format',
      lineNumber: 2,
    });
  });

  it('reports error for date without time component', () => {
    const lines = parse(makeInput('2026-01-01'));
    const findings = checkExpiresField(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: 'error',
      ruleId: 'expires-invalid-format',
    });
  });

  it('reports error for expired date', () => {
    const lines = parse(makeInput('2020-01-01T00:00:00Z'));
    const findings = checkExpiresField(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: 'error',
      ruleId: 'expires-past',
    });
    expect(findings[0].explanation).toContain('expired');
  });

  it('reports warning for near expiry (within 30 days)', () => {
    const lines = parse(makeInput(daysFromNow(10)));
    const findings = checkExpiresField(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: 'warning',
      ruleId: 'expires-near-expiry',
    });
  });

  it('reports warning for expiry too far in the future (>365 days)', () => {
    const lines = parse(makeInput(daysFromNow(400)));
    const findings = checkExpiresField(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: 'warning',
      ruleId: 'expires-too-far',
    });
  });

  it('accepts timezone offset format like +00:00', () => {
    const lines = parse(makeInput('2026-06-15T12:00:00+00:00'));
    const findings = checkExpiresField(lines);
    expect(findings).toEqual([]);
  });

  it('accepts negative timezone offset', () => {
    const lines = parse(makeInput('2026-06-15T12:00:00-05:00'));
    const findings = checkExpiresField(lines);
    expect(findings).toEqual([]);
  });

  it('matches field name case-insensitively', () => {
    const lines = parse(`Contact: mailto:sec@example.com\nEXPIRES: ${daysFromNow(180)}\n`);
    const findings = checkExpiresField(lines);
    expect(findings).toEqual([]);
  });

  it('accepts fractional seconds', () => {
    const lines = parse(makeInput('2026-06-15T12:00:00.123Z'));
    const findings = checkExpiresField(lines);
    expect(findings).toEqual([]);
  });

  it('every finding has non-empty title, explanation, and suggestedFix', () => {
    // Test with an invalid format
    const lines1 = parse(makeInput('bad'));
    for (const f of checkExpiresField(lines1)) {
      expect(f.title.length).toBeGreaterThan(0);
      expect(f.explanation.length).toBeGreaterThan(0);
      expect(f.suggestedFix.length).toBeGreaterThan(0);
    }

    // Test with expired date
    const lines2 = parse(makeInput('2020-01-01T00:00:00Z'));
    for (const f of checkExpiresField(lines2)) {
      expect(f.title.length).toBeGreaterThan(0);
      expect(f.explanation.length).toBeGreaterThan(0);
      expect(f.suggestedFix.length).toBeGreaterThan(0);
    }
  });

  it('reports error for impossible date like month 13', () => {
    const lines = parse(makeInput('2026-13-01T00:00:00Z'));
    const findings = checkExpiresField(lines);
    // Should be caught either as invalid format or invalid date
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('error');
  });
});
