<script lang="ts">
  import type { CheckStatus } from '../lib/types';
  import CheckStatusIcon from './CheckStatusIcon.svelte';

  export let checks: { label: string; status: CheckStatus }[] = [];
  export let score: number | null = null;

  $: scoreInt = score !== null ? Math.ceil(score) : null;
  $: scoreClass = scoreInt === null ? ''
    : scoreInt >= 90 ? 'score-good'
    : scoreInt >= 70 ? 'score-warn'
    : 'score-bad';

  $: passCount = checks.filter(c => c.status === 'pass').length;
  $: warnCount = checks.filter(c => c.status === 'warn').length;
  $: failCount = checks.filter(c => c.status === 'fail').length;
  $: total = passCount + warnCount + failCount;

  $: overallStatus = failCount > 0 ? 'fail' as CheckStatus
    : warnCount > 0 ? 'warn' as CheckStatus
    : 'pass' as CheckStatus;

  $: overallClass = overallStatus === 'pass' ? 'valid'
    : overallStatus === 'fail' ? 'invalid' : 'warnings';

  $: overallLabel = overallStatus === 'pass' ? 'All checks passed'
    : overallStatus === 'fail' ? `${failCount} issue${failCount !== 1 ? 's' : ''} found`
    : `${warnCount} warning${warnCount !== 1 ? 's' : ''}`;

  // Surface which cards triggered the warn/fail so the user can jump straight
  // to them instead of scanning the page top-to-bottom.
  $: failedLabels = checks.filter(c => c.status === 'fail').map(c => c.label);
  $: warnLabels = checks.filter(c => c.status === 'warn').map(c => c.label);
</script>

<div class="summary-bar {overallClass}" role="status">
  <div class="summary-main">
    {#if scoreInt !== null}
      <span class="score-pill {scoreClass}" aria-label="Security score {scoreInt} out of 100">
        <span class="score-value">{scoreInt}</span><span class="score-total">/100</span>
      </span>
    {/if}
    <CheckStatusIcon status={overallStatus} />
    <span class="summary-label">{overallLabel}</span>
    <span class="summary-counts">
      {#if passCount > 0}<span class="count pass-count">{passCount} passed</span>{/if}
      {#if warnCount > 0}<span class="count warn-count">{warnCount} warnings</span>{/if}
      {#if failCount > 0}<span class="count fail-count">{failCount} failed</span>{/if}
    </span>
  </div>
  <div class="progress-bar">
    {#if passCount > 0}<div class="seg pass-seg" style="width: {passCount / total * 100}%"></div>{/if}
    {#if warnCount > 0}<div class="seg warn-seg" style="width: {warnCount / total * 100}%"></div>{/if}
    {#if failCount > 0}<div class="seg fail-seg" style="width: {failCount / total * 100}%"></div>{/if}
  </div>
  {#if failedLabels.length > 0 || warnLabels.length > 0}
    <div class="trouble-list">
      {#if failedLabels.length > 0}
        <span class="trouble-label fail-count">Failed:</span>
        <span>{failedLabels.join(', ')}</span>
      {/if}
      {#if warnLabels.length > 0}
        <span class="trouble-label warn-count">Warnings:</span>
        <span>{warnLabels.join(', ')}</span>
      {/if}
    </div>
  {/if}
</div>

<style>
  .summary-bar {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    padding: 0.85rem 1.1rem;
  }

  .summary-bar.valid { border-color: rgba(0, 212, 170, 0.3); }
  .summary-bar.invalid { border-color: rgba(255, 77, 106, 0.3); }
  .summary-bar.warnings { border-color: rgba(255, 184, 77, 0.3); }

  .summary-main {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .score-pill {
    display: inline-flex;
    align-items: baseline;
    gap: 1px;
    padding: 0.25rem 0.55rem;
    border-radius: 999px;
    background: var(--color-surface-2, rgba(255, 255, 255, 0.06));
    border: 1px solid var(--color-border);
    font-family: var(--font-mono);
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--color-text);
    margin-right: 0.25rem;
  }

  .score-pill.score-good {
    background: rgba(0, 212, 170, 0.12);
    border-color: rgba(0, 212, 170, 0.45);
    color: var(--color-valid);
  }
  .score-pill.score-warn {
    background: rgba(255, 184, 77, 0.12);
    border-color: rgba(255, 184, 77, 0.45);
    color: var(--color-warning);
  }
  .score-pill.score-bad {
    background: rgba(255, 77, 106, 0.12);
    border-color: rgba(255, 77, 106, 0.45);
    color: var(--color-error);
  }

  .score-value { color: inherit; }
  .score-total { color: inherit; opacity: 0.6; font-weight: 400; }

  .summary-label {
    font-size: 0.9rem;
    font-weight: 600;
  }

  .valid .summary-label { color: var(--color-valid); }
  .invalid .summary-label { color: var(--color-invalid); }
  .warnings .summary-label { color: var(--color-warning); }

  .summary-counts {
    display: flex;
    gap: 0.6rem;
    margin-left: auto;
    font-size: 0.75rem;
    font-weight: 400;
  }

  .count { opacity: 0.85; }
  .pass-count { color: var(--color-valid); }
  .warn-count { color: var(--color-warning); }
  .fail-count { color: var(--color-error); }
  .info-count { color: var(--color-info); }

  .progress-bar {
    display: flex;
    height: 4px;
    border-radius: 2px;
    overflow: hidden;
    margin-top: 0.6rem;
    gap: 2px;
  }

  .seg {
    border-radius: 2px;
    min-width: 3px;
  }

  .pass-seg { background: var(--color-valid); }
  .warn-seg { background: var(--color-warning); }
  .fail-seg { background: var(--color-error); }
  .info-seg { background: var(--color-border); }

  .trouble-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem 0.75rem;
    margin-top: 0.5rem;
    font-size: 0.72rem;
    color: var(--color-text-secondary);
  }
  .trouble-label {
    font-weight: 600;
    margin-right: 0.25rem;
  }
</style>
