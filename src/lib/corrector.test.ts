import { describe, it, expect } from 'vitest';
import { generateCorrectedOutput } from './corrector';
import { parse } from './parser';
import { validate } from './validator';

describe('generateCorrectedOutput', () => {
  it('removes invalid lines', () => {
    const input = `Contact: mailto:security@example.com\nthis is garbage\nExpires: ${futureDate()}`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    expect(corrected).not.toContain('this is garbage');
    expect(corrected).toContain('Contact: mailto:security@example.com');
  });

  it('inserts missing Contact placeholder', () => {
    const input = `Expires: ${futureDate()}`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    expect(corrected).toContain('Contact: mailto:security@example.com');
  });

  it('inserts missing Expires when absent', () => {
    const input = 'Contact: mailto:security@example.com';
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    expect(corrected).toContain('Expires:');
    // Verify the inserted Expires is a valid future date
    const expiresMatch = corrected.match(/Expires:\s*(.+)/);
    expect(expiresMatch).not.toBeNull();
    const expiresDate = new Date(expiresMatch![1]);
    expect(expiresDate.getTime()).toBeGreaterThan(Date.now());
  });

  it('replaces expired Expires value', () => {
    const input = 'Contact: mailto:security@example.com\nExpires: 2020-01-01T00:00:00Z';
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    expect(corrected).not.toContain('2020-01-01');
    // Should have a future Expires
    const expiresMatch = corrected.match(/Expires:\s*(.+)/);
    expect(expiresMatch).not.toBeNull();
    const expiresDate = new Date(expiresMatch![1]);
    expect(expiresDate.getTime()).toBeGreaterThan(Date.now());
  });

  it('preserves comments in their original positions', () => {
    const input = `# This is a comment\nContact: mailto:security@example.com\n# Another comment\nExpires: ${futureDate()}`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    expect(corrected).toContain('# This is a comment');
    expect(corrected).toContain('# Another comment');
  });

  it('preserves original field order by default', () => {
    const input = `Expires: ${futureDate()}\nContact: mailto:security@example.com\nPolicy: https://example.com/policy`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    const expiresIdx = corrected.indexOf('Expires:');
    const contactIdx = corrected.indexOf('Contact:');
    const policyIdx = corrected.indexOf('Policy:');
    expect(expiresIdx).toBeLessThan(contactIdx);
    expect(contactIdx).toBeLessThan(policyIdx);
  });

  it('sorts fields to recommended order when sortToRecommended is true', () => {
    const input = `Policy: https://example.com/policy\nExpires: ${futureDate()}\nContact: mailto:security@example.com`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings, { sortToRecommended: true });
    const contactIdx = corrected.indexOf('Contact:');
    const expiresIdx = corrected.indexOf('Expires:');
    const policyIdx = corrected.indexOf('Policy:');
    // Recommended order: Contact, Expires, ..., Policy
    expect(contactIdx).toBeLessThan(expiresIdx);
    expect(expiresIdx).toBeLessThan(policyIdx);
  });

  it('removes duplicate Expires fields', () => {
    const input = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\nExpires: ${futureDate()}`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    const expiresCount = (corrected.match(/Expires:/g) || []).length;
    expect(expiresCount).toBe(1);
  });

  it('corrected output passes validation with zero errors', () => {
    const input = 'this is garbage\nmore garbage';
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    const revalidated = validate(parse(corrected));
    expect(revalidated.errorCount).toBe(0);
  });

  it('handles empty input', () => {
    const lines = parse('');
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    // Should have Contact and Expires inserted
    expect(corrected).toContain('Contact:');
    expect(corrected).toContain('Expires:');
    const revalidated = validate(parse(corrected));
    expect(revalidated.errorCount).toBe(0);
  });

  it('valid input round-trip preserves fields', () => {
    const exp = futureDate();
    const input = `Contact: mailto:security@example.com\nExpires: ${exp}`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    const reparsed = parse(corrected);
    const originalFields = lines.filter((l) => l.kind === 'field') as Array<{ name: string; value: string }>;
    const correctedFields = reparsed.filter((l) => l.kind === 'field') as Array<{ name: string; value: string }>;
    expect(correctedFields.length).toBe(originalFields.length);
    for (let i = 0; i < originalFields.length; i++) {
      expect(correctedFields[i].name.toLowerCase()).toBe(originalFields[i].name.toLowerCase());
      expect(correctedFields[i].value).toBe(originalFields[i].value);
    }
  });

  it('places unknown fields at the end in sorted mode', () => {
    const input = `CustomField: some-value\nContact: mailto:security@example.com\nExpires: ${futureDate()}`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings, { sortToRecommended: true });
    const correctedLines = corrected.split('\n');
    const lastFieldLine = correctedLines.filter((l) => l.includes(':')).pop();
    expect(lastFieldLine).toContain('CustomField');
  });

  it('associates comments with the following field group in sorted mode', () => {
    const input = `# Policy comment\nPolicy: https://example.com/policy\n# Contact comment\nContact: mailto:security@example.com\nExpires: ${futureDate()}`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings, { sortToRecommended: true });
    // In sorted mode, Contact should come before Policy
    // The comment before Contact should appear before Contact
    const contactCommentIdx = corrected.indexOf('# Contact comment');
    const contactIdx = corrected.indexOf('Contact:');
    const policyCommentIdx = corrected.indexOf('# Policy comment');
    const policyIdx = corrected.indexOf('Policy:');
    expect(contactCommentIdx).toBeLessThan(contactIdx);
    expect(policyCommentIdx).toBeLessThan(policyIdx);
    expect(contactIdx).toBeLessThan(policyIdx);
  });

  it('adds mailto: to Contact with bare email address', () => {
    const input = `Contact: security@example.com\nExpires: ${futureDate()}`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    expect(corrected).toContain('Contact: mailto:security@example.com');
  });

  it('adds https:// to Policy with bare domain', () => {
    const input = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\nPolicy: example.com/security-policy`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    expect(corrected).toContain('Policy: https://example.com/security-policy');
  });

  it('adds https:// to Hiring, Acknowledgments, CSAF fields without scheme', () => {
    const input = `Contact: mailto:security@example.com\nExpires: ${futureDate()}\nHiring: example.com/jobs\nAcknowledgments: example.com/thanks\nCSAF: example.com/csaf`;
    const lines = parse(input);
    const { findings } = validate(lines);
    const corrected = generateCorrectedOutput(lines, findings);
    expect(corrected).toContain('Hiring: https://example.com/jobs');
    expect(corrected).toContain('Acknowledgments: https://example.com/thanks');
    expect(corrected).toContain('CSAF: https://example.com/csaf');
  });
});

/** Helper: returns an RFC 3339 date 180 days from now */
function futureDate(): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + 180);
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
