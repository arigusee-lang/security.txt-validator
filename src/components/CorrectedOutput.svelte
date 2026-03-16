<script lang="ts">
  import type { ParsedLine, Finding } from '../lib/types';
  import { generateCorrectedOutput } from '../lib/corrector';
  import { parse } from '../lib/parser';

  export let correctedText: string = '';
  export let lines: ParsedLine[] = [];
  export let findings: Finding[] = [];
  export let mode: 'paste' | 'url' | 'generate' = 'paste';
  export let rawContent: string = '';

  let sortToRecommended = false;
  let copied = false;
  let copyTimeout: ReturnType<typeof setTimeout> | null = null;

  $: isUrlMode = mode === 'url';
  $: hasErrors = findings.some(f => f.severity === 'error');
  $: heading = isUrlMode
    ? 'Fetched File'
    : hasErrors ? 'Corrected Output' : 'File Contents';

  $: displayText = isUrlMode
    ? rawContent
    : sortToRecommended
      ? generateCorrectedOutput(lines, findings, { sortToRecommended: true })
      : correctedText;

  // In URL mode, use original parsed lines; otherwise re-parse the display text
  $: displayLines = isUrlMode ? lines : parse(displayText);

  // Build a map of lineNumber -> worst severity from findings
  $: severityMap = buildSeverityMap(findings);

  function buildSeverityMap(f: Finding[]): Map<number, 'error' | 'warning'> {
    const map = new Map<number, 'error' | 'warning'>();
    for (const finding of f) {
      if (finding.lineNumber == null) continue;
      const current = map.get(finding.lineNumber);
      if (finding.severity === 'error') {
        map.set(finding.lineNumber, 'error');
      } else if (finding.severity === 'warning' && current !== 'error') {
        map.set(finding.lineNumber, 'warning');
      }
    }
    return map;
  }

  interface HighlightedLine {
    lineNumber: number;
    segments: { text: string; cls: string }[];
    severity: 'error' | 'warning' | null;
  }

  $: highlightedLines = displayLines.map((line): HighlightedLine => {
    const sev = severityMap.get(line.lineNumber) ?? null;
    if (line.kind === 'field') {
      return {
        lineNumber: line.lineNumber,
        segments: [
          { text: line.name + ':', cls: 'hl-field-name' },
          { text: ' ' + line.value, cls: 'hl-field-value' },
        ],
        severity: sev,
      };
    }
    if (line.kind === 'comment') {
      return {
        lineNumber: line.lineNumber,
        segments: [{ text: line.raw, cls: 'hl-comment' }],
        severity: sev,
      };
    }
    if (line.kind === 'blank') {
      return {
        lineNumber: line.lineNumber,
        segments: [{ text: '', cls: '' }],
        severity: sev,
      };
    }
    // invalid
    return {
      lineNumber: line.lineNumber,
      segments: [{ text: line.raw, cls: 'hl-invalid' }],
      severity: sev,
    };
  });

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(displayText);
      copied = true;
      if (copyTimeout) clearTimeout(copyTimeout);
      copyTimeout = setTimeout(() => { copied = false; }, 2000);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = displayText;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand('copy');
        copied = true;
        if (copyTimeout) clearTimeout(copyTimeout);
        copyTimeout = setTimeout(() => { copied = false; }, 2000);
      } catch {
        alert('Copy is not supported in this browser.');
      }
      document.body.removeChild(textarea);
    }
  }

  function handleDownload() {
    const blob = new Blob([displayText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
</script>

<div class="corrected-output" aria-label="Corrected output">
  <div class="toolbar">
    <h3 class="heading">{heading}</h3>
    <div class="actions">
      {#if !isUrlMode}
        <label class="sort-toggle">
          <input type="checkbox" bind:checked={sortToRecommended} aria-label="Sort fields to RFC recommended order" />
          <span>RFC order</span>
        </label>
      {/if}
      <button class="action-btn" on:click={handleCopy} aria-label={copied ? 'Copied to clipboard' : 'Copy output'}>
        {copied ? 'Copied!' : 'Copy'}
      </button>
      {#if !isUrlMode}
        <button class="action-btn" on:click={handleDownload} aria-label="Download as security.txt">
          Download
        </button>
      {/if}
    </div>
  </div>
  <div class="code-block">
    {#each highlightedLines as line (line.lineNumber)}
      <div class="code-line" class:line-error={line.severity === 'error'} class:line-warning={line.severity === 'warning'}>
        {#each line.segments as seg}<span class={seg.cls}>{seg.text}</span>{/each}
        {#if line.segments.length === 1 && line.segments[0].text === ''}&nbsp;{/if}
      </div>
    {/each}
  </div>
</div>

<style>
  .corrected-output {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    padding: 1.25rem;
  }

  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .heading {
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--color-text);
  }

  .actions {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .sort-toggle {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    cursor: pointer;
  }

  .sort-toggle input {
    accent-color: var(--color-accent);
    cursor: pointer;
  }

  .action-btn {
    background: transparent;
    color: var(--color-accent);
    border: 1px solid var(--color-accent);
    border-radius: var(--radius);
    padding: 0.3rem 0.75rem;
    font-family: var(--font-family);
    font-size: 0.8rem;
    font-weight: 500;
    cursor: pointer;
    transition: background var(--transition), color var(--transition);
  }

  .action-btn:hover {
    background: var(--color-accent);
    color: var(--color-bg);
  }

  .code-block {
    background: var(--color-bg);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.75rem 1rem;
    overflow-x: auto;
    font-family: var(--font-mono);
    font-size: 0.8rem;
    line-height: 1.6;
    margin: 0;
  }

  .code-line {
    padding: 0 0.25rem;
    border-radius: 2px;
    white-space: pre;
  }

  .line-error {
    background: rgba(255, 77, 106, 0.1);
    border-left: 2px solid var(--color-error);
    padding-left: 0.5rem;
  }

  .line-warning {
    background: rgba(255, 184, 77, 0.08);
    border-left: 2px solid var(--color-warning);
    padding-left: 0.5rem;
  }

  .code-line :global(.hl-field-name) {
    color: var(--color-accent);
    font-weight: 600;
  }

  .code-line :global(.hl-field-value) {
    color: var(--color-text);
  }

  .code-line :global(.hl-comment) {
    color: var(--color-text-secondary);
    font-style: italic;
  }

  .code-line :global(.hl-invalid) {
    color: var(--color-error);
    text-decoration: wavy underline;
    text-decoration-color: var(--color-error);
  }
</style>
