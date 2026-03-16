<script lang="ts">
  import type { ValidationResult, Finding } from '../lib/types';
  import StatusBadge from './StatusBadge.svelte';
  import FindingCard from './FindingCard.svelte';

  export let result: ValidationResult | null = null;
  export let mode: 'paste' | 'url' | 'generate' = 'paste';

  $: errors = result?.findings.filter((f) => f.severity === 'error') ?? [];
  $: warnings = result?.findings.filter((f) => f.severity === 'warning') ?? [];
  $: infos = result?.findings.filter((f) => f.severity === 'info') ?? [];
  $: noIssues = result != null && result.findings.length === 0;

  function findingsForDisplay(findings: Finding[]): Finding[] {
    if (mode === 'url') {
      return findings.map((f) => ({ ...f, lineNumber: undefined }));
    }
    return findings;
  }
</script>

{#if result}
  <div class="results-panel" aria-label="Validation results">
    <StatusBadge
      status={result.status}
      errorCount={result.errorCount}
      warningCount={result.warningCount}
    />

    {#if noIssues}
      <p class="no-issues">No issues found. Your security.txt looks good.</p>
    {:else}
      {#if errors.length > 0}
        <div class="finding-group" role="region" aria-label="Errors">
          <h3 class="group-heading error-heading">Errors</h3>
          <div class="findings-list">
            {#each findingsForDisplay(errors) as finding (finding.ruleId + '-' + (finding.lineNumber ?? 'global'))}
              <FindingCard {finding} />
            {/each}
          </div>
        </div>
      {/if}

      {#if warnings.length > 0}
        <div class="finding-group" role="region" aria-label="Warnings">
          <h3 class="group-heading warning-heading">Warnings</h3>
          <div class="findings-list">
            {#each findingsForDisplay(warnings) as finding (finding.ruleId + '-' + (finding.lineNumber ?? 'global'))}
              <FindingCard {finding} />
            {/each}
          </div>
        </div>
      {/if}

      {#if infos.length > 0}
        <div class="finding-group" role="region" aria-label="Informational notes">
          <h3 class="group-heading info-heading">Info</h3>
          <div class="findings-list">
            {#each findingsForDisplay(infos) as finding (finding.ruleId + '-' + (finding.lineNumber ?? 'global'))}
              <FindingCard {finding} />
            {/each}
          </div>
        </div>
      {/if}
    {/if}
  </div>
{/if}

<style>
  .results-panel {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .no-issues {
    color: var(--color-valid);
    font-size: 0.9rem;
    padding: 0.5rem 0;
  }

  .finding-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .group-heading {
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .error-heading {
    color: var(--color-error);
  }

  .warning-heading {
    color: var(--color-warning);
  }

  .info-heading {
    color: var(--color-info);
  }

  .findings-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
</style>
