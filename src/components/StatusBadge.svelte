<script lang="ts">
  export let status: 'valid' | 'invalid' | 'valid-with-warnings' = 'valid';
  export let errorCount: number = 0;
  export let warningCount: number = 0;

  $: label = status === 'valid'
    ? 'Valid'
    : status === 'invalid'
      ? 'Invalid'
      : 'Valid with warnings';

  $: statusClass = status === 'valid'
    ? 'valid'
    : status === 'invalid'
      ? 'invalid'
      : 'warnings';
</script>

<div
  class="status-badge {statusClass}"
  role="status"
  aria-label="Validation status: {label}, {errorCount} errors, {warningCount} warnings"
>
  <span class="icon" aria-hidden="true">
    {#if status === 'valid'}
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="8" cy="8" r="8" fill="var(--color-valid)"/>
        <path d="M4.5 8L7 10.5L11.5 5.5" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    {:else if status === 'invalid'}
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="8" cy="8" r="8" fill="var(--color-invalid)"/>
        <path d="M5 5L11 11M11 5L5 11" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/>
      </svg>
    {:else}
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <path d="M8 1L15.5 14H0.5L8 1Z" fill="var(--color-warning)"/>
        <path d="M8 6V10" stroke="#1a1a2e" stroke-width="1.8" stroke-linecap="round"/>
        <circle cx="8" cy="12.5" r="1" fill="#1a1a2e"/>
      </svg>
    {/if}
  </span>
  <span class="label">{label}</span>
  {#if errorCount > 0 || warningCount > 0}
    <span class="counts">
      {#if errorCount > 0}
        <span class="count error-count">{errorCount} {errorCount === 1 ? 'error' : 'errors'}</span>
      {/if}
      {#if warningCount > 0}
        <span class="count warning-count">{warningCount} {warningCount === 1 ? 'warning' : 'warnings'}</span>
      {/if}
    </span>
  {/if}
</div>

<style>
  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    border-radius: var(--radius);
    font-size: 0.9rem;
    font-weight: 600;
  }

  .status-badge.valid {
    background: rgba(0, 212, 170, 0.12);
    color: var(--color-valid);
    border: 1px solid rgba(0, 212, 170, 0.25);
  }

  .status-badge.invalid {
    background: rgba(255, 77, 106, 0.12);
    color: var(--color-invalid);
    border: 1px solid rgba(255, 77, 106, 0.25);
  }

  .status-badge.warnings {
    background: rgba(255, 184, 77, 0.12);
    color: var(--color-warning);
    border: 1px solid rgba(255, 184, 77, 0.25);
  }

  .icon {
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
    line-height: 1;
  }

  .counts {
    display: inline-flex;
    gap: 0.5rem;
    margin-left: 0.25rem;
    font-size: 0.8rem;
    font-weight: 400;
  }

  .count { opacity: 0.85; }
  .error-count { color: var(--color-error); }
  .warning-count { color: var(--color-warning); }
</style>
