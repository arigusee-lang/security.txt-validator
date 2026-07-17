<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import DomainInput from './DomainInput.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import SummaryBar from './SummaryBar.svelte';
  import InfrastructureBanner from './InfrastructureBanner.svelte';
  import DiffBanner from './DiffBanner.svelte';
  import SecurityTxtCard from './SecurityTxtCard.svelte';
  import HeadersCard from './HeadersCard.svelte';
  import EmailSecurityCard from './EmailSecurityCard.svelte';
  import DnsSecurityCard from './DnsSecurityCard.svelte';
  import SslCard from './SslCard.svelte';
  import CtLogsCard from './CtLogsCard.svelte';
  import RedirectCard from './RedirectCard.svelte';
  import ReputationCard from './ReputationCard.svelte';
  import { runScanStream, type ScanSection } from '../lib/scanStream';
  import { calculateClientScore } from '../lib/scoreClient';
  import { currentUser } from '../lib/authStore';
  import { exportCsv, exportHtml, exportPdf, type ReportPayload } from '../lib/exportUtils';

  let dns: any = null;
  let web: any = null;
  let expiry: any = null;
  let ct: any = null;
  let redirects: any = null;
  let reputation: any = null;

  let loading = false;
  let errorMessage = '';
  let domainInput: DomainInput;
  let scannedDomain = '';

  // Score and diff data
  let scoreData: { total: number; breakdown: Record<string, { earned: number; max: number }> } | null = null;
  let diffData: {
    previousScanDate: string | null;
    summary: { newIssues: number; resolvedIssues: number; totalChanges: number };
    changes?: Array<{
      category: string;
      type: 'status_changed' | 'value_changed' | 'appeared' | 'disappeared';
      field?: string;
      severity: 'critical' | 'warn' | 'resolved' | 'info';
      previous: unknown;
      current: unknown;
      message: string;
    }>;
  } | null = null;
  let savedToHistory = false;

  // History view mode
  let historyMode = false;
  let historyDomain = '';
  let historyScanDate = '';
  let historyBatch: { id: string; name: string | null } | null = null;

  // Cache indicator — max age across the just-run scan groups (null if all fresh)
  let cacheAgeMs: number | null = null;

  // Auth state
  let user: import('../lib/authStore').AuthUser | null = null;
  const unsubUser = currentUser.subscribe(v => (user = v));
  onDestroy(() => unsubUser());

  $: hasAny = dns || web || expiry || ct || redirects || reputation;

  $: allDone = !loading;
  $: coreLoaded = !!(dns && web);

  // Worst-of helper for per-card aggregation. Matches the order in
  // SummaryBar.svelte (fail > warn > pass > info).
  function worstOf(...statuses: Array<string | undefined | null>): 'pass' | 'warn' | 'fail' | 'info' {
    const order: Record<string, number> = { fail: 3, warn: 2, pass: 1, info: 0 };
    let worst: 'pass' | 'warn' | 'fail' | 'info' = 'info';
    for (const s of statuses) {
      if (!s) continue;
      if ((order[s] ?? 0) > order[worst]) worst = s as any;
    }
    return worst;
  }

  // SummaryBar counts one entry per visible *card*, not per sub-check.
  // That way the counts match what the user sees on the page (e.g. a single
  // "DNS & Domain" warning chip even if DNSSEC alone tripped — instead of 5
  // separate chips for sub-checks where only one fires).
  $: summaryChecks = [
    ...(web?.headers?.items?.length ? [{ label: 'Headers', status: web.headers.status }] : []),
    ...((dns?.dnssec || dns?.caa || dns?.ns || dns?.danglingDns || expiry) ? [{
      label: 'DNS & Domain',
      status: worstOf(dns?.dnssec?.status, dns?.caa?.status, dns?.ns?.status, dns?.danglingDns?.status, expiry?.status),
    }] : []),
    ...((reputation?.safeBrowsing || reputation?.urlhaus || dns?.blacklist) ? [{
      label: 'Reputation',
      status: worstOf(reputation?.safeBrowsing?.status, reputation?.urlhaus?.status, dns?.blacklist?.status),
    }] : []),
    ...((dns?.spf || dns?.dmarc || dns?.dkim || dns?.mx) ? [{
      label: 'Email',
      status: worstOf(dns?.spf?.status, dns?.dmarc?.status, dns?.dkim?.status, dns?.mx?.status),
    }] : []),
    ...(web?.securityTxt ? [{ label: 'security.txt', status: web.securityTxt.status }] : []),
    ...(web?.ssl ? [{ label: 'SSL/TLS', status: web.ssl.status }] : []),
    ...(ct ? [{ label: 'CT logs', status: ct.status }] : []),
    ...(redirects ? [{ label: 'Redirects', status: redirects.status }] : []),
  ];

  let failedGroups: string[] = [];
  let groupErrors: Record<string, string> = {};

  const GROUP_LABELS: Record<string, string> = {
    dns: 'Email & DNS checks (SPF, DMARC, DKIM, DNSSEC, CAA, MX, NS, Blacklist, Expiry)',
    web: 'Web checks (security.txt, headers, SSL/TLS)',
    ct: 'Certificate Transparency',
    redirects: 'HTTPS & Redirects',
    reputation: 'Domain Reputation',
  };

  function handleHashChange() {
    const hash = window.location.hash;
    const params = new URLSearchParams(hash.replace(/^#\/?\??/, ''));
    const d = params.get('domain');
    const scanIdParam = params.get('scanId');
    const viewParam = params.get('view');

    if (d && scanIdParam && viewParam === 'history') {
      loadFromHistory(scanIdParam, d);
    } else if (!d) {
      // Clean URL like /#/ — reset everything
      historyMode = false;
      dns = web = expiry = ct = redirects = reputation = null;
      scoreData = null;
      diffData = null;
      savedToHistory = false;
      errorMessage = '';
      loading = false;
    }
  }

  onMount(() => {
    document.title = 'Domain Security Checker — Headers, SPF, DMARC, DKIM, DNSSEC & security.txt';
    const meta = document.querySelector('meta[name="description"]');
    if (meta) meta.setAttribute('content', 'Free domain security checker.');

    handleHashChange();
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  });

  async function loadFromHistory(scanId: string, domain: string) {
    historyMode = true;
    historyDomain = domain;
    scannedDomain = domain;
    activeScanId = scanId;
    historyBatch = null;
    loading = true;
    errorMessage = '';
    try {
      const res = await fetch(`/api/scans/${scanId}`, { credentials: 'include' });
      if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(data?.message || `HTTP ${res.status}`);
      }
      const scan = await res.json();
      const r = scan.result_json;
      historyScanDate = scan.completed_at || scan.created_at || '';
      historyBatch = scan.batch_id
        ? { id: scan.batch_id, name: scan.batch_name ?? null }
        : null;

      if (r) {
        // Support both flat (old /full + new SSE pipeline) and section-grouped (legacy incremental save)
        if (r.spf || r.dmarc || r.infrastructure) {
          // Flat format — each check stored under its own top-level key.
          dns = {
            spf: r.spf, dmarc: r.dmarc, dkim: r.dkim, dnssec: r.dnssec,
            caa: r.caa, mx: r.mx, ns: r.ns,
            blacklist: r.blacklist, danglingDns: r.danglingDns,
            infrastructure: r.infrastructure,
          };
          web = { securityTxt: r.securityTxt, headers: r.headers, ssl: r.ssl };
          expiry = r.domainExpiry;
          ct = r.ctLogs;
          redirects = r.redirects;
          reputation = { safeBrowsing: r.safeBrowsing, urlhaus: r.urlhaus };
        } else {
          // Section-grouped format from incremental finalize
          dns = r.dns || null;
          web = r.web || null;
          expiry = r.expiry || null;
          ct = r.ct || null;
          redirects = r.redirects || null;
          reputation = r.reputation || null;
        }
      }

      if (scan.score != null) {
        scoreData = { total: scan.score, breakdown: r?.score?.breakdown || {} };
      }
      if (scan.changes_json && scan.changes_json.hasDiff) {
        diffData = scan.changes_json;
      }
    } catch (err: any) {
      errorMessage = err?.message || 'Failed to load scan';
    } finally {
      loading = false;
    }
  }

  // Maps an SSE section to the group label the existing error UI knows about.
  // (Errors are still rendered per-group, not per-check, to avoid littering the
  // results stack with one row per failed dnsbl provider etc.)
  const SECTION_TO_GROUP: Record<ScanSection, string> = {
    infrastructure: 'dns', spf: 'dns', dmarc: 'dns', dkim: 'dns', dnssec: 'dns',
    caa: 'dns', mx: 'dns', ns: 'dns', blacklist: 'dns', danglingDns: 'dns',
    domainExpiry: 'expiry',
    securityTxt: 'web', headers: 'web', ssl: 'web',
    redirects: 'redirects',
    safeBrowsing: 'reputation', urlhaus: 'reputation', ctLogs: 'ct',
  };

  /** Apply a single SSE section result to the right reactive variable. */
  function applySection(section: ScanSection, data: any) {
    switch (section) {
      case 'infrastructure': dns = { ...(dns || {}), infrastructure: data }; break;
      case 'spf':            dns = { ...(dns || {}), spf: data }; break;
      case 'dmarc':          dns = { ...(dns || {}), dmarc: data }; break;
      case 'dkim':           dns = { ...(dns || {}), dkim: data }; break;
      case 'dnssec':         dns = { ...(dns || {}), dnssec: data }; break;
      case 'caa':            dns = { ...(dns || {}), caa: data }; break;
      case 'mx':             dns = { ...(dns || {}), mx: data }; break;
      case 'ns':             dns = { ...(dns || {}), ns: data }; break;
      case 'blacklist':      dns = { ...(dns || {}), blacklist: data }; break;
      case 'danglingDns':    dns = { ...(dns || {}), danglingDns: data }; break;
      case 'domainExpiry':   expiry = data; break;
      case 'securityTxt':    web = { ...(web || {}), securityTxt: data }; break;
      case 'headers':        web = { ...(web || {}), headers: data }; break;
      case 'ssl':            web = { ...(web || {}), ssl: data }; break;
      case 'redirects':      redirects = data; break;
      case 'safeBrowsing':   reputation = { ...(reputation || {}), safeBrowsing: data }; break;
      case 'urlhaus':        reputation = { ...(reputation || {}), urlhaus: data }; break;
      case 'ctLogs':         ct = data; break;
    }
  }

  let cancelStream: (() => void) | null = null;
  // scanId of the scan we launched ourselves — lets handleHashChange tell apart
  // "our own live scan set the hash" from "user refreshed / navigated to a scanId URL".
  let activeScanId: string | undefined;

  async function runCheck(domain: string, noCache: boolean, ctSource?: import('../lib/types').CtSourcePref) {
    // Cancel any previous in-flight scan so we don't merge stale events into a new scan.
    cancelStream?.();
    cancelStream = null;

    dns = web = expiry = ct = redirects = reputation = null;
    scannedDomain = domain;
    groupErrors = {};
    failedGroups = [];
    errorMessage = '';
    scoreData = null;
    diffData = null;
    savedToHistory = false;
    cacheAgeMs = null;
    historyMode = false;
    loading = true;

    // We intentionally do NOT touch the URL during a scan. That keeps a page
    // refresh on the root checker showing the (empty) root page instead of
    // trying to restore a half-scanned state, while history/other views keep
    // their own URLs. scanId is still needed for the authenticated finalize call.
    const scanId = user ? crypto.randomUUID() : undefined;
    activeScanId = scanId;

    cancelStream = runScanStream(
      domain,
      { noCache, ctSource, scanId },
      {
        onSection: (section, data, ageMs) => {
          applySection(section, data);
          if (ageMs !== null && (cacheAgeMs === null || ageMs > cacheAgeMs)) {
            cacheAgeMs = ageMs;
          }
        },
        onSectionError: (section, message) => {
          const group = SECTION_TO_GROUP[section];
          if (!group) return;
          groupErrors[group] = message;
          if (!failedGroups.includes(group)) failedGroups = [...failedGroups, group];
          groupErrors = groupErrors;
        },
        onDone: async () => {
          loading = false;
          cancelStream = null;

          // Instant client-side score for unauth'd users.
          const score = calculateClientScore(dns, web, expiry, redirects, reputation, ct);
          if (score) scoreData = score;

          // Authenticated: ask server to finalize (persists score + diff vs previous scan).
          if (scanId && user) {
            try {
              const res = await fetch('/api/domain-check/finalize', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ scanId }),
              });
              if (res.ok) {
                const finalized = await res.json();
                if (finalized.score) {
                  scoreData = { total: finalized.score.total, breakdown: finalized.score.breakdown ?? {} };
                }
                if (finalized.diff?.hasDiff) {
                  diffData = finalized.diff;
                }
                savedToHistory = true;
              }
            } catch (err) {
              console.warn('[scan] finalize failed:', err);
            }
          }
        },
        onError: (msg) => {
          loading = false;
          cancelStream = null;
          errorMessage = msg || 'Connection lost';
        },
      },
    );
  }

  onDestroy(() => {
    cancelStream?.();
  });

  function handleCheck(e: CustomEvent<{ domain: string; noCache: boolean; ctSource?: import('../lib/types').CtSourcePref }>) {
    runCheck(e.detail.domain, e.detail.noCache, e.detail.ctSource);
  }

  let exportingFormat: 'html' | 'pdf' | null = null;
  let exportError = '';
  let exportMenuOpen = false;

  // Svelte action: invoke a callback when the user clicks outside the node.
  function clickOutside(node: HTMLElement, onOutside: () => void) {
    let cb = onOutside;
    function onDocClick(e: MouseEvent) {
      if (!node.contains(e.target as Node)) cb();
    }
    document.addEventListener('mousedown', onDocClick, true);
    return {
      update(next: () => void) { cb = next; },
      destroy() { document.removeEventListener('mousedown', onDocClick, true); },
    };
  }

  function buildExportPayload(): ReportPayload {
    // Live (authenticated) scans track their id in `activeScanId`; history views
    // carry it in the URL hash. Anonymous scans have none — the footer falls
    // back to a plain timestamp in that case.
    const hashParams = new URLSearchParams(window.location.hash.replace(/^#\/?\??/, ''));
    const scanId = activeScanId || hashParams.get('scanId');

    return {
      domain: scannedDomain,
      scanDate: historyMode && historyScanDate ? historyScanDate : new Date().toISOString(),
      score: scoreData,
      scanId: scanId || null,
      diff: diffData,
      dns,
      web,
      expiry,
      ct,
      redirects,
      reputation,
    };
  }

  async function handleExport(format: 'html' | 'pdf') {
    if (exportingFormat) return;
    exportError = '';
    exportingFormat = format;
    try {
      const payload = buildExportPayload();
      if (format === 'html') {
        await exportHtml(payload);
      } else {
        await exportPdf(payload);
      }
    } catch (err: any) {
      exportError = err?.message || 'Export failed';
    } finally {
      exportingFormat = null;
    }
  }

  async function refreshCt() {
    const domain = scannedDomain;
    if (!domain) return;
    try {
      const res = await fetch(
        `/api/domain-check/ct?domain=${encodeURIComponent(domain)}&noCache=1`,
        { credentials: 'include' },
      );
      if (res.ok) {
        ct = await res.json();
      }
    } catch {
      // ignore
    }
  }

  function formatHistoryDate(iso: string): string {
    if (!iso) return '';
    const d = new Date(iso);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function formatCacheAge(ms: number): string {
    const sec = Math.max(0, Math.round(ms / 1000));
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    const remSec = sec % 60;
    if (min < 60) return remSec ? `${min}m ${remSec}s` : `${min}m`;
    const hr = Math.floor(min / 60);
    const remMin = min % 60;
    return remMin ? `${hr}h ${remMin}m` : `${hr}h`;
  }
</script>

<div class="checker-page">
  {#if historyMode}
    <div class="history-header">
      <h1 class="history-title">Scan report for <span class="history-domain">{historyDomain}</span></h1>
      {#if historyScanDate}
        <p class="history-date">Scanned on {formatHistoryDate(historyScanDate)}</p>
      {/if}
      {#if historyBatch}
        <p class="history-batch">
          Part of batch: <strong>{historyBatch.name || 'Untitled'}</strong>
        </p>
        <a class="back-link" href="/#/dashboard?tab=batch&batchId={historyBatch.id}">← Back to batch</a>
      {:else}
        <a class="back-link" href="/#/dashboard">← Back to history</a>
      {/if}
      <span class="link-sep">|</span>
      <a class="back-link" href="/#/">New scan</a>
    </div>
  {:else}
    <div class="hero">
      <h1 class="title">Domain Security Checker</h1>
      <p class="subtitle">Free comprehensive security audit for any domain — DNS, TLS, email auth, reputation, blacklists and more</p>
      <div class="check-tags">
        <span class="tag">Headers</span>
        <span class="tag">DNSSEC</span>
        <span class="tag">CAA</span>
        <span class="tag">Blacklists</span>
        <span class="tag">Reputation</span>
        <span class="tag">SSL/TLS</span>
        <span class="tag">CT logs</span>
        <span class="tag">SPF</span>
        <span class="tag">DMARC</span>
        <span class="tag">DKIM</span>
        <span class="tag">security.txt</span>
      </div>
    </div>

    <DomainInput bind:this={domainInput} on:check={handleCheck} />
  {/if}

  {#if loading && !hasAny}
    <div class="loading-wrap">
      <LoadingSpinner />
      <p class="loading-text">Running checks…</p>
    </div>
  {/if}

  {#if errorMessage && !hasAny}
    <div class="error-banner" role="alert"><p>{errorMessage}</p></div>
  {/if}

  {#if hasAny}
    {#if scoreData && !loading}
      <div class="score-row">
        {#if savedToHistory && user}
          <span class="saved-indicator" aria-label="Saved to history">✓ Saved to history</span>
        {/if}
        {#if cacheAgeMs !== null && !historyMode}
          <span class="cache-hint">
            Results from cache
            <span class="cache-info" tabindex="0" aria-label="About cached results">
              ?
              <span class="cache-tooltip" role="tooltip">
                Cached {formatCacheAge(cacheAgeMs)} ago.<br />
                Premium users get fresh scans on every request.
              </span>
            </span>
          </span>
        {/if}
        <div class="export-menu" use:clickOutside={() => (exportMenuOpen = false)}>
          <button
            class="export-btn"
            on:click={() => (exportMenuOpen = !exportMenuOpen)}
            disabled={exportingFormat !== null}
            aria-haspopup="menu"
            aria-expanded={exportMenuOpen}
            title="Download report"
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1v9m0 0L5 7m3 3l3-3M2 12v1a2 2 0 002 2h8a2 2 0 002-2v-1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
            {exportingFormat ? `Generating ${exportingFormat.toUpperCase()}…` : 'Export'}
            <svg class="export-caret" width="10" height="10" viewBox="0 0 12 12" fill="none"><path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </button>
          {#if exportMenuOpen && !exportingFormat}
            <div class="export-dropdown" role="menu">
              <button class="export-item" role="menuitem" on:click={() => { exportMenuOpen = false; exportCsv(scannedDomain, dns, web, expiry, ct, redirects, reputation); }}>
                <span class="export-item-label">CSV</span>
                <span class="export-item-hint">Spreadsheet — flat row-per-check</span>
              </button>
              <button class="export-item" role="menuitem" on:click={() => { exportMenuOpen = false; handleExport('html'); }}>
                <span class="export-item-label">HTML</span>
                <span class="export-item-hint">Self-contained web page</span>
              </button>
              <button class="export-item" role="menuitem" disabled aria-disabled="true" title="PDF export is disabled on this deployment">
                <span class="export-item-label">PDF</span>
                <span class="export-item-hint">Unavailable on this deployment</span>
              </button>
            </div>
          {/if}
        </div>
      </div>
      {#if exportError}
        <div class="export-error" role="alert">{exportError}</div>
      {/if}
    {/if}

    {#if diffData && diffData.summary.totalChanges > 0 && !loading}
      <DiffBanner diff={diffData} isHistorical={historyMode} />
    {/if}

    {#if !loading && coreLoaded && summaryChecks.length > 0}
      <SummaryBar checks={summaryChecks} score={scoreData?.total ?? null} />
    {/if}

    {#if dns?.infrastructure || dns?.blacklist}
      <InfrastructureBanner infrastructure={dns?.infrastructure} blacklist={dns?.blacklist} ssl={web?.ssl} />
    {/if}

    {#if loading && hasAny}
      <div class="section-loading"><span class="dot-pulse"></span> Still loading some checks…</div>
    {/if}

    <div class="results-stack">
      <!-- 1. Security Headers (web group) -->
      {#if web?.headers}
        <HeadersCard data={web.headers} />
      {:else if groupErrors.web}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.web}</span>
            <p class="error-card-detail">{groupErrors.web}</p>
          </div>
        </div>
      {:else if loading}
        <div class="section-loading"><span class="dot-pulse"></span> Checking security.txt, headers, SSL…</div>
      {/if}

      <!-- 2. DNS and Domain (dns group).
           In the SSE pipeline each field lands separately, so any one of these
           being present is enough to render the card; missing fields fall back
           to a placeholder until their event arrives. -->
      {#if dns?.dnssec || dns?.caa || dns?.ns || dns?.danglingDns || expiry}
        <DnsSecurityCard
          dnssec={dns?.dnssec || { status: 'info', enabled: false, error: loading ? 'Loading…' : 'Check failed' }}
          caa={dns?.caa || { status: 'info', records: [], error: loading ? 'Loading…' : undefined }}
          ns={dns?.ns || { status: 'info', nameservers: [], error: loading ? 'Loading…' : undefined }}
          domainExpiry={expiry || { status: 'info', expirationDate: null, daysRemaining: null, error: groupErrors.expiry || (loading ? 'Loading…' : 'Check failed') }}
          danglingDns={dns?.danglingDns || { status: 'info', records: [], danglingCount: 0 }} />
      {:else if groupErrors.dns}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.dns}</span>
            <p class="error-card-detail">{groupErrors.dns}</p>
          </div>
        </div>
      {:else if loading}
        <div class="section-loading"><span class="dot-pulse"></span> Checking DNS records…</div>
      {/if}

      <!-- 3. Domain reputation -->
      {#if reputation || dns?.blacklist}
        <ReputationCard
          safeBrowsing={reputation?.safeBrowsing || { status: 'info', safe: null, threats: [], error: groupErrors.reputation || '' }}
          urlhaus={reputation?.urlhaus || { status: 'info', listed: false, urlCount: 0, error: groupErrors.reputation || '' }}
          blacklist={dns?.blacklist || { status: 'info', providers: [] }}
          infrastructure={dns?.infrastructure ?? null}
        />
      {:else if groupErrors.reputation && !dns?.blacklist}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.reputation}</span>
            <p class="error-card-detail">{groupErrors.reputation}</p>
          </div>
        </div>
      {/if}

      <!-- 4. HTTPS & Redirects -->
      {#if redirects}
        <RedirectCard data={redirects} />
      {:else if groupErrors.redirects}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.redirects}</span>
            <p class="error-card-detail">{groupErrors.redirects}</p>
          </div>
        </div>
      {/if}

      <!-- 5. security.txt (web group — error already shown above on HeadersCard slot) -->
      {#if web?.securityTxt}
        <SecurityTxtCard data={web.securityTxt} domain={scannedDomain} />
      {/if}

      <!-- 6. SSL/TLS Certificate (web group) -->
      {#if web?.ssl}
        <SslCard data={web.ssl} />
      {/if}

      <!-- 7. Certificate Transparency -->
      {#if ct}
        <CtLogsCard data={ct} authenticated={!!user} hasSubdomainAccess={user?.plan === 'premium_plus'} on:refresh={refreshCt} />
      {:else if groupErrors.ct}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.ct}</span>
            <p class="error-card-detail">{groupErrors.ct}</p>
          </div>
        </div>
      {/if}

      <!-- 8. Email Security (dns group — error already shown above on DnsSecurityCard slot) -->
      {#if dns?.spf || dns?.dmarc || dns?.dkim || dns?.mx}
        <EmailSecurityCard
          spf={dns?.spf || { status: 'info', record: null, validations: [], mechanisms: [], dnsLookupCount: 0, error: loading ? 'Loading…' : 'Check failed' }}
          dmarc={dns?.dmarc || { status: 'info', record: null, validations: [], tags: [], error: loading ? 'Loading…' : 'Check failed' }}
          dkim={dns?.dkim || { status: 'info', foundCount: 0, totalChecked: 0, selectors: [] }}
          mx={dns?.mx || { status: 'info', records: [] }} />
      {/if}

    </div>
  {/if}
</div>

<style>
  .checker-page { display: flex; flex-direction: column; gap: 1rem; }
  .hero { text-align: center; margin-bottom: 0.5rem; }
  .title { font-size: 1.5rem; font-weight: 700; color: var(--color-text); letter-spacing: -0.02em; }
  .subtitle { color: var(--color-text-secondary); font-size: 0.875rem; margin-top: 0.35rem; }
  .check-tags { display: flex; flex-wrap: wrap; justify-content: center; gap: 0.35rem; margin-top: 0.6rem; }
  .tag {
    font-size: 0.65rem; font-weight: 500; letter-spacing: 0.03em;
    padding: 0.15rem 0.5rem; border-radius: 100px;
    border: 1px solid var(--color-border); color: var(--color-text-secondary);
    background: var(--color-surface);
  }
  .loading-wrap { display: flex; flex-direction: column; align-items: center; gap: 0.3rem; }
  .loading-text { font-size: 0.8rem; color: var(--color-text-secondary); }
  .error-banner { background: rgba(255, 77, 106, 0.1); border: 1px solid var(--color-error); border-radius: var(--radius); padding: 0.75rem 1rem; color: var(--color-error); font-size: 0.875rem; }
  .results-stack { display: flex; flex-direction: column; gap: 0.75rem; }
  .section-loading {
    display: flex; align-items: center; gap: 0.5rem; justify-content: center;
    padding: 0.75rem; font-size: 0.8rem; color: var(--color-text-secondary);
    background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-lg);
  }
  .error-card {
    display: flex; align-items: flex-start; gap: 0.6rem;
    padding: 0.75rem 1rem;
    background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-lg);
    border-left: 3px solid var(--color-error);
  }
  .error-card-icon { color: var(--color-error); font-size: 0.9rem; flex-shrink: 0; margin-top: 0.1rem; }
  .error-card-title { font-size: 0.85rem; font-weight: 600; color: var(--color-text); }
  .error-card-detail { font-size: 0.75rem; color: var(--color-text-secondary); margin-top: 0.15rem; }
  .dot-pulse {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: var(--color-accent); animation: pulse 1s ease-in-out infinite;
  }
  @keyframes pulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }
  .score-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .saved-indicator {
    font-size: 0.75rem;
    color: var(--color-valid);
    font-weight: 500;
  }
  .export-menu {
    position: relative;
    margin-left: auto;
  }
  .export-btn {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.3rem 0.65rem;
    font-size: 0.75rem;
    font-weight: 500;
    color: var(--color-text-secondary);
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    cursor: pointer;
    transition: all 0.15s;
  }
  .export-btn:hover:not(:disabled) {
    background: var(--color-surface-2, rgba(255, 255, 255, 0.04));
    color: var(--color-text);
    border-color: var(--color-text-secondary);
  }
  .export-btn:disabled {
    opacity: 0.6;
    cursor: default;
  }
  .export-caret {
    opacity: 0.7;
    margin-left: 0.1rem;
  }
  .export-dropdown {
    position: absolute;
    top: calc(100% + 4px);
    right: 0;
    min-width: 220px;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: 0.5rem;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
    padding: 0.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
    z-index: 20;
  }
  .export-item {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.1rem;
    padding: 0.45rem 0.6rem;
    background: none;
    border: 0;
    border-radius: 0.3rem;
    text-align: left;
    cursor: pointer;
    color: var(--color-text);
    font-family: inherit;
  }
  .export-item:hover:not(:disabled) {
    background: var(--color-surface-2, rgba(255, 255, 255, 0.05));
  }
  .export-item:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
  .export-item-label {
    font-size: 0.8rem;
    font-weight: 600;
  }
  .export-item-hint {
    font-size: 0.7rem;
    color: var(--color-text-secondary);
  }
  .export-error {
    font-size: 0.75rem;
    color: var(--color-error);
    margin-top: -0.4rem;
  }
  @media print {
    .export-menu, .domain-input-wrapper, .score-row .saved-indicator { display: none; }
  }
  .history-header {
    text-align: center;
    margin-bottom: 0.5rem;
  }
  .history-title {
    font-size: 1.25rem;
    font-weight: 700;
    color: var(--color-text);
  }
  .history-domain {
    color: var(--color-accent);
    font-family: var(--font-mono);
  }
  .history-date {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    margin-top: 0.25rem;
  }
  .history-batch {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    margin-top: 0.25rem;
  }
  .history-batch strong {
    color: var(--color-text);
    font-weight: 600;
  }
  .back-link {
    display: inline-block;
    margin-top: 0.5rem;
    font-size: 0.8rem;
    color: var(--color-accent);
    text-decoration: none;
  }
  .back-link:hover { text-decoration: underline; }
  .link-sep { color: var(--color-text-secondary); margin: 0 0.25rem; font-size: 0.8rem; }
  .cache-hint {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.75rem;
    color: var(--color-text-secondary);
    opacity: 0.85;
    margin-left: auto;
  }
  .cache-info {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: var(--color-surface-2, rgba(255, 255, 255, 0.08));
    border: 1px solid var(--color-border);
    font-size: 0.65rem;
    font-weight: 600;
    color: var(--color-text-secondary);
    cursor: help;
    position: relative;
  }
  .cache-info:focus { outline: 2px solid var(--color-accent); outline-offset: 1px; }
  .cache-tooltip {
    visibility: hidden;
    opacity: 0;
    position: absolute;
    bottom: calc(100% + 6px);
    right: 0;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.5rem 0.7rem;
    width: max-content;
    max-width: 260px;
    font-size: 0.7rem;
    font-weight: 400;
    color: var(--color-text);
    line-height: 1.4;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    z-index: 50;
    transition: opacity 0.12s ease;
    pointer-events: none;
    text-align: left;
  }
  .cache-info:hover .cache-tooltip,
  .cache-info:focus .cache-tooltip {
    visibility: visible;
    opacity: 1;
  }
</style>
