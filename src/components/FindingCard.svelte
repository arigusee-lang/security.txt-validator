<script lang="ts">
  import type { Finding } from '../lib/types';

  export let finding: Finding;

  $: severityClass = finding.severity;

  $: severityLabel = finding.severity === 'error'
    ? 'Error'
    : finding.severity === 'warning'
      ? 'Warning'
      : 'Info';

  $: rfcLabel = (() => {
    if (!finding.rfcRef) return '';
    const m = finding.rfcRef.match(/#section-(.+)$/);
    return m ? `RFC 9116 \u00A7${m[1]}` : 'RFC 9116';
  })();
</script>

<div
  class="finding-card {severityClass}"
  role="article"
  aria-label="{severityLabel}: {finding.title}"
>
  <div class="header">
    <span class="severity-icon" aria-hidden="true">
      {#if finding.severity === 'error'}
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <circle cx="7" cy="7" r="7" fill="var(--color-error)"/>
          <path d="M4.5 4.5L9.5 9.5M9.5 4.5L4.5 9.5" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
      {:else if finding.severity === 'warning'}
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
          <path d="M8 1L15 14H1L8 1Z" fill="var(--color-warning)"/>
          <path d="M8 6V9.5" stroke="#1a1a2e" stroke-width="1.5" stroke-linecap="round"/>
          <circle cx="8" cy="12" r="0.8" fill="#1a1a2e"/>
        </svg>
      {:else}
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <circle cx="7" cy="7" r="7" fill="var(--color-info)"/>
          <path d="M7 6V10" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>
          <circle cx="7" cy="4" r="0.8" fill="#fff"/>
        </svg>
      {/if}
    </span>
    <span class="severity-tag">{severityLabel}</span>
    <span class="title">{finding.title}</span>
    {#if finding.lineNumber != null}
      <span class="line-number">Line {finding.lineNumber}</span>
    {/if}
  </div>
  <p class="explanation">{finding.explanation}</p>
  <p class="suggested-fix">
    <span class="fix-label">Fix:</span> {finding.suggestedFix}
  </p>
  {#if finding.rfcRef}
    <a class="rfc-link" href={finding.rfcRef} target="_blank" rel="noopener noreferrer">
      {rfcLabel}
      <svg class="external-icon" width="10" height="10" viewBox="0 0 12 12" fill="none">
        <path d="M3.5 1H11V8.5M11 1L1 11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </a>
  {/if}
</div>

<style>
  .finding-card {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.75rem 1rem;
    border-left: 3px solid transparent;
  }

  .finding-card.error { border-left-color: var(--color-error); }
  .finding-card.warning { border-left-color: var(--color-warning); }
  .finding-card.info { border-left-color: var(--color-info); }

  .header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.4rem;
    flex-wrap: wrap;
  }

  .severity-icon {
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
    line-height: 1;
  }

  .severity-tag {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
  }

  .error .severity-tag { color: var(--color-error); background: rgba(255, 77, 106, 0.1); }
  .warning .severity-tag { color: var(--color-warning); background: rgba(255, 184, 77, 0.1); }
  .info .severity-tag { color: var(--color-info); background: rgba(77, 166, 255, 0.1); }

  .title {
    font-weight: 600;
    font-size: 0.875rem;
    color: var(--color-text);
  }

  .line-number {
    margin-left: auto;
    font-size: 0.75rem;
    color: var(--color-text-secondary);
    font-family: var(--font-mono);
  }

  .explanation {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    line-height: 1.5;
    margin-bottom: 0.3rem;
  }

  .suggested-fix {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    line-height: 1.5;
  }

  .fix-label {
    color: var(--color-accent);
    font-weight: 600;
  }

  .rfc-link {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    margin-top: 0.3rem;
    font-size: 0.75rem;
    color: var(--color-accent);
    text-decoration: none;
    opacity: 0.8;
    transition: opacity var(--transition);
  }

  .rfc-link:hover {
    opacity: 1;
    text-decoration: underline;
  }

  .external-icon {
    flex-shrink: 0;
  }
</style>
