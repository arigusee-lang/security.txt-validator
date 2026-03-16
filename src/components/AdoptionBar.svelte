<script lang="ts">
  interface SiteEntry {
    domain: string;
    status: 'valid' | 'warnings' | 'invalid' | 'missing';
  }

  // Data checked March 2026 against SimilarWeb Top 100 US websites (Feb 2026).
  // Adult sites included in counts but not shown as chips.
  const sites: SiteEntry[] = [
    // Valid (Contact + Expires present, Expires in range)
    { domain: 'github.com', status: 'valid' },
    { domain: 'facebook.com', status: 'valid' },
    { domain: 'microsoft.com', status: 'valid' },
    { domain: 'apple.com', status: 'valid' },
    { domain: 'netflix.com', status: 'valid' },
    { domain: 'reddit.com', status: 'valid' },
    { domain: 'discord.com', status: 'valid' },
    { domain: 'okta.com', status: 'valid' },
    { domain: 'etsy.com', status: 'valid' },
    { domain: 'instructure.com', status: 'valid' },
    { domain: 'weather.com', status: 'valid' },
    { domain: 'yelp.com', status: 'valid' },
    { domain: 'clever.com', status: 'valid' },
    { domain: 'craigslist.org', status: 'valid' },
    { domain: 'figma.com', status: 'valid' },

    // Valid with warnings (Expires too far, near expiry, etc.)
    { domain: 'google.com', status: 'warnings' },
    { domain: 'wikipedia.org', status: 'warnings' },
    { domain: 'yahoo.com', status: 'warnings' },
    { domain: 'bbc.com', status: 'warnings' },
    { domain: 'wayfair.com', status: 'warnings' },
    { domain: 'notion.so', status: 'warnings' },

    // Has errors (missing Expires, expired, non-standard fields, etc.)
    { domain: 'amazon.com', status: 'invalid' },
    { domain: 'linkedin.com', status: 'invalid' },
    { domain: 'spotify.com', status: 'invalid' },
    { domain: 'x.com', status: 'invalid' },
    { domain: 'youtube.com', status: 'invalid' },
    { domain: 'shopify.com', status: 'invalid' },
    { domain: 'paypal.com', status: 'invalid' },
    { domain: 'canva.com', status: 'invalid' },
    { domain: 'nytimes.com', status: 'invalid' },
    { domain: 'walmart.com', status: 'invalid' },
    { domain: 'indeed.com', status: 'invalid' },
    { domain: 'roblox.com', status: 'invalid' },
    { domain: 'chatgpt.com', status: 'invalid' },
    { domain: 'aol.com', status: 'invalid' },
    { domain: 'nextdoor.com', status: 'invalid' },
    { domain: 'people.com', status: 'invalid' },
    { domain: 'brave.com', status: 'invalid' },
    { domain: 'usatoday.com', status: 'invalid' },
    { domain: 'theguardian.com', status: 'invalid' },
  ];

  // 7 adult sites not shown as chips but counted: 3 valid, 1 invalid, 3 missing.
  const hiddenValid = 3;
  const hiddenInvalid = 1;
  const totalChecked = 100;
  const valid = sites.filter(s => s.status === 'valid').length + hiddenValid;
  const warnings = sites.filter(s => s.status === 'warnings').length;
  const invalid = sites.filter(s => s.status === 'invalid').length + hiddenInvalid;
  const totalWithFile = valid + warnings + invalid;
  const totalWithout = totalChecked - totalWithFile;
</script>

<section class="adoption" aria-label="security.txt adoption among top websites">
  <h2 class="adoption-title">security.txt adoption</h2>
  <p class="adoption-subtitle">
    {totalWithFile} of the top {totalChecked} websites have a security.txt file — {valid} fully comply with RFC 9116.
  </p>

  <div class="stats-row">
    <div class="stat">
      <span class="stat-number none-num">{totalWithout}</span>
      <span class="stat-label">no file</span>
    </div>
    <div class="stat">
      <span class="stat-number invalid-num">{invalid}</span>
      <span class="stat-label">errors</span>
    </div>
    <div class="stat">
      <span class="stat-number warnings-num">{warnings}</span>
      <span class="stat-label">warnings</span>
    </div>
    <div class="stat">
      <span class="stat-number valid-num">{valid}</span>
      <span class="stat-label">valid</span>
    </div>
  </div>

  <div class="bar-chart" role="img" aria-label="{totalWithout} missing, {invalid} with errors, {warnings} with warnings, {valid} valid">
    <div class="bar-segment none-bar" style="width: {totalWithout / totalChecked * 100}%"></div>
    <div class="bar-segment invalid-bar" style="width: {invalid / totalChecked * 100}%"></div>
    <div class="bar-segment warnings-bar" style="width: {warnings / totalChecked * 100}%"></div>
    <div class="bar-segment valid-bar" style="width: {valid / totalChecked * 100}%"></div>
  </div>

  <div class="sites-grid">
    {#each sites as site (site.domain)}
      <span class="site-chip {site.status}" title="{site.domain}: {site.status === 'valid' ? 'Valid' : site.status === 'warnings' ? 'Valid with warnings' : 'Has errors'}">
        <span class="dot" aria-hidden="true"></span>
        {site.domain}
      </span>
    {/each}
  </div>

  <p class="adoption-note">Data checked March 2026 against SimilarWeb Top 100 US websites (Feb 2026). Status reflects RFC 9116 compliance.</p>
</section>

<style>
  .adoption {
    border-top: 1px solid var(--color-border);
    padding-top: 1.5rem;
    margin-top: 1.5rem;
  }

  .adoption-title {
    font-size: 1rem;
    font-weight: 600;
    color: var(--color-text);
    margin-bottom: 0.35rem;
  }

  .adoption-subtitle {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    line-height: 1.5;
    margin-bottom: 1rem;
  }

  .stats-row {
    display: flex;
    gap: 1.5rem;
    margin-bottom: 0.75rem;
  }

  .stat {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.15rem;
  }

  .stat-number {
    font-size: 1.5rem;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }

  .valid-num { color: var(--color-valid); }
  .warnings-num { color: var(--color-warning); }
  .invalid-num { color: var(--color-error); }
  .none-num { color: var(--color-text-secondary); }

  .stat-label {
    font-size: 0.7rem;
    color: var(--color-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .bar-chart {
    display: flex;
    height: 8px;
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 1rem;
    gap: 2px;
  }

  .bar-segment {
    border-radius: 4px;
    min-width: 4px;
  }

  .none-bar { background: var(--color-border); }
  .invalid-bar { background: var(--color-error); }
  .warnings-bar { background: var(--color-warning); }
  .valid-bar { background: var(--color-valid); }

  .sites-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }

  .site-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.25rem 0.6rem;
    border-radius: 100px;
    font-size: 0.75rem;
    font-family: var(--font-mono);
    border: 1px solid var(--color-border);
    color: var(--color-text-secondary);
    background: var(--color-surface);
  }

  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .site-chip.valid .dot { background: var(--color-valid); }
  .site-chip.warnings .dot { background: var(--color-warning); }
  .site-chip.invalid .dot { background: var(--color-error); }

  .adoption-note {
    margin-top: 0.75rem;
    font-size: 0.7rem;
    color: var(--color-text-secondary);
    opacity: 0.6;
  }
</style>
