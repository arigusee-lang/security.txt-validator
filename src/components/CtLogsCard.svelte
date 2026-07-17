<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { CtLogsResult, CtLogEntry } from '../lib/types';
  import type { CheckStatus } from '../lib/types';
  import ResultCard from './ResultCard.svelte';
  import CheckStatusIcon from './CheckStatusIcon.svelte';

  export let data: CtLogsResult;
  export let authenticated: boolean = false;
  // Whether the current user is entitled to see subdomain certificates
  // (premium_plus tier). Controls which upsell message to render below.
  export let hasSubdomainAccess: boolean = false;

  let showAllRecent = false;
  let showAllFlagged = false;
  let refreshing = false;

  const dispatch = createEventDispatcher<{ refresh: void }>();

  function formatDate(d: string): string {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }

  // Date + HH:MM so multiple genuinely distinct certs issued the same day (same
  // CN/CA, different issuance time) are visually distinguishable instead of
  // looking like duplicate rows.
  function formatDateTime(d: string): string {
    if (!d) return '—';
    const dt = new Date(d);
    return `${dt.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}, ${dt.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}`;
  }

  function handleRefresh() {
    refreshing = true;
    dispatch('refresh');
    setTimeout(() => { refreshing = false; }, 2000);
  }

  function cacheAge(cachedAt: string | undefined): string {
    if (!cachedAt) return '';
    const diff = Date.now() - new Date(cachedAt).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h`;
    return `${Math.floor(hours / 24)}d`;
  }

  function staleAge(seconds: number | undefined): string {
    if (!seconds || seconds < 60) return `${seconds ?? 0}s`;
    const mins = Math.floor(seconds / 60);
    if (mins < 60) return `${mins}m`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h`;
    return `${Math.floor(hours / 24)}d`;
  }

  function downloadCsv(certs: CtLogEntry[], domain: string): void {
    const BOM = '\uFEFF';
    const header = 'Common Name,Issuer,Not Before,Not After\n';
    const rows = certs.map(c =>
      `"${c.commonName}","${c.issuerName}","${c.notBefore}","${c.notAfter}"`
    ).join('\n');
    const blob = new Blob([BOM + header + rows], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ct-certs-${domain}-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const severityToStatus: Record<string, CheckStatus> = { warn: 'warn', fail: 'fail', info: 'info' };

  $: allCerts = [...(data.flaggedCerts || []), ...data.recentCerts];
  $: domain = data.recentCerts[0]?.commonName?.replace('*.','') || '';
</script>

<ResultCard title="Certificate Transparency" status={data.status}>
  {#if data.source === 'none' && data.error}
    <div class="error-row">
      <p class="error-text">CT log sources temporarily unavailable</p>
      <button class="refresh-btn" on:click={handleRefresh} disabled={refreshing} aria-label="Retry">
        {refreshing ? '⟳' : '↻'} Retry
      </button>
    </div>
  {:else}
    <!-- Findings section -->
    {#if data.findings && data.findings.length > 0}
      <div class="findings">
        {#each data.findings as finding}
          <div class="finding-row">
            <CheckStatusIcon status={severityToStatus[finding.severity] || 'info'} />
            <div>
              <span class="finding-title">{finding.title}</span>
              <span class="finding-desc">{finding.description}</span>
              {#if finding.subdomain}
                <span class="finding-subdomain">{finding.subdomain}</span>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {:else if data.status === 'pass'}
      <p class="no-findings">No anomalies detected in CT logs</p>
    {/if}

    <p class="summary">{data.totalCerts} certificate{data.totalCerts !== 1 ? 's' : ''} found in CT logs{data.recentCerts.length < data.totalCerts ? ` (showing ${data.recentCerts.length} unique recent)` : ''}</p>
    <p class="scope-note" title="This is a point-in-time scan: it shows certificates that are currently valid plus any that expired within the last 30 days. Older history is out of scope here.">
      Scope: valid + expired ≤30 days
    </p>

    <!-- Flagged Certs Table -->
    {#if data.flaggedCerts && data.flaggedCerts.length > 0}
      <h4 class="table-heading">Flagged Certificates</h4>
      <div class="ct-table-wrap">
        <table class="ct-table">
          <thead><tr><th>Common Name</th><th>Issuer</th><th>Issued</th><th>Expires</th></tr></thead>
          <tbody>
            {#each (showAllFlagged ? data.flaggedCerts : data.flaggedCerts.slice(0, 5)) as cert}
              <tr>
                <td class="cn">{cert.commonName}</td>
                <td>{cert.issuerName}</td>
                <td title={cert.notBefore}>{formatDateTime(cert.notBefore)}</td>
                <td>{formatDate(cert.notAfter)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if data.flaggedCerts.length > 5}
        <button class="toggle-btn" on:click={() => showAllFlagged = !showAllFlagged}>
          {showAllFlagged ? 'Show less' : `Show all ${data.flaggedCerts.length}`}
        </button>
      {/if}
    {/if}

    <!-- Recent Certs Table -->
    {#if data.recentCerts.length > 0}
      <h4 class="table-heading">Recent Certificates</h4>
      <div class="ct-table-wrap">
        <table class="ct-table">
          <thead><tr><th>Common Name</th><th>Issuer</th><th>Issued</th><th>Expires</th></tr></thead>
          <tbody>
            {#each (showAllRecent ? data.recentCerts : data.recentCerts.slice(0, 5)) as cert}
              <tr>
                <td class="cn">{cert.commonName}</td>
                <td>{cert.issuerName}</td>
                <td title={cert.notBefore}>{formatDateTime(cert.notBefore)}</td>
                <td>{formatDate(cert.notAfter)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if data.recentCerts.length > 5}
        <button class="toggle-btn" on:click={() => showAllRecent = !showAllRecent}>
          {showAllRecent ? 'Show less' : `Show all ${data.recentCerts.length}`}
        </button>
      {/if}
    {/if}

    <!-- CSV download + auth/upsell message -->
    <div class="actions-row">
      {#if authenticated}
        <button class="csv-btn" on:click={() => downloadCsv(allCerts, domain)}>Download CSV</button>
      {/if}
      {#if !hasSubdomainAccess}
        <p class="auth-msg">
          {#if authenticated}
            Upgrade to Premium+ to see subdomain certificates
          {:else}
            Sign in to see subdomain certificates
          {/if}
        </p>
      {/if}
    </div>

    <!-- Source indicator -->
    {#if data.source !== 'none'}
      <p class="source" class:cache-note={data.fromCache && !data.stale} class:stale-note={data.stale}>
        Data from
        {#if data.source === 'certspotter'}
          <a href="https://sslmate.com/certspotter/" target="_blank" rel="noopener">CertSpotter</a>
        {:else}
          <a href="https://crt.sh/?q={encodeURIComponent('%.'+domain)}" target="_blank" rel="noopener">crt.sh</a>
        {/if}
        {#if data.stale}
          <span class="stale-tag" title="Upstream CT sources unavailable — showing last known data">
            ⚠ stale ({staleAge(data.staleSeconds)} old)
          </span>
        {:else if data.fromCache}
          (cached {cacheAge(data.cachedAt)} ago)
        {/if}
      </p>
    {/if}
  {/if}
</ResultCard>

<style>
  .error-text { color: var(--color-error); font-size: 0.85rem; }
  .error-row { display: flex; align-items: center; gap: 0.5rem; }
  .summary { font-size: 0.85rem; color: var(--color-text-secondary); margin-bottom: 0.15rem; }
  .scope-note { font-size: 0.72rem; color: var(--color-text-secondary); opacity: 0.65; margin: 0 0 0.5rem; cursor: help; }
  .no-findings { font-size: 0.8rem; color: var(--color-text-secondary); opacity: 0.7; margin-bottom: 0.5rem; }
  .findings { display: flex; flex-direction: column; gap: 0.35rem; margin-bottom: 0.6rem; }
  .finding-row { display: flex; align-items: flex-start; gap: 0.4rem; font-size: 0.8rem; }
  .finding-title { font-weight: 600; }
  .finding-desc { color: var(--color-text-secondary); font-size: 0.75rem; display: block; }
  .finding-subdomain { color: var(--color-text-secondary); font-size: 0.65rem; display: block; opacity: 0.7; font-family: var(--font-mono); }
  .table-heading { font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--color-text-secondary); margin: 0.6rem 0 0.3rem; }
  .ct-table-wrap { overflow-x: auto; }
  .ct-table { width: 100%; border-collapse: collapse; font-size: 0.75rem; }
  .ct-table th {
    text-align: left; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.04em; color: var(--color-text-secondary); padding: 0.3rem 0.5rem;
    border-bottom: 1px solid var(--color-border);
  }
  .ct-table td { padding: 0.35rem 0.5rem; color: var(--color-text-secondary); border-bottom: 1px solid var(--color-border); }
  .ct-table tr:last-child td { border-bottom: none; }
  .cn { font-family: var(--font-mono); color: var(--color-text); font-size: 0.75rem; }
  .toggle-btn {
    background: none; border: 1px solid var(--color-border); border-radius: var(--radius);
    color: var(--color-accent); font-family: var(--font-family); font-size: 0.75rem;
    padding: 0.2rem 0.6rem; cursor: pointer; margin-top: 0.4rem;
  }
  .toggle-btn:hover { background: rgba(0, 212, 170, 0.08); }
  .actions-row { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.5rem; }
  .csv-btn {
    background: none; border: 1px solid var(--color-border); border-radius: var(--radius);
    color: var(--color-accent); font-family: var(--font-family); font-size: 0.75rem;
    padding: 0.25rem 0.7rem; cursor: pointer; transition: background var(--transition);
  }
  .csv-btn:hover { background: rgba(0, 212, 170, 0.08); }
  .auth-msg { font-size: 0.7rem; color: var(--color-text-secondary); opacity: 0.7; font-style: italic; }
  .source { font-size: 0.7rem; color: var(--color-text-secondary); opacity: 0.6; margin-top: 0.4rem; }
  .cache-note { font-style: italic; }
  .stale-note { opacity: 1; }
  .stale-tag {
    margin-left: 0.3rem;
    padding: 0.05rem 0.3rem;
    border-radius: 3px;
    background: rgba(255, 184, 77, 0.12);
    color: var(--color-warning);
    font-size: 0.65rem;
    font-weight: 500;
    font-style: normal;
    letter-spacing: 0.02em;
    white-space: nowrap;
  }
  .refresh-btn {
    background: none; border: 1px solid var(--color-border); border-radius: var(--radius);
    color: var(--color-text-secondary); font-size: 0.85rem; padding: 0.15rem 0.4rem;
    cursor: pointer; line-height: 1; transition: color var(--transition), border-color var(--transition);
  }
  .refresh-btn:hover { color: var(--color-accent); border-color: var(--color-accent); }
  .refresh-btn:disabled { opacity: 0.4; cursor: default; }
</style>
