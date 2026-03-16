<script lang="ts">
  import InputPanel from './components/InputPanel.svelte';
  import ResultsPanel from './components/ResultsPanel.svelte';
  import CorrectedOutput from './components/CorrectedOutput.svelte';
  import LoadingSpinner from './components/LoadingSpinner.svelte';
  import FaqSection from './components/FaqSection.svelte';
  import AdoptionBar from './components/AdoptionBar.svelte';
  import { parse } from './lib/parser';
  import { validate } from './lib/validator';
  import { generateCorrectedOutput } from './lib/corrector';
  import { fetchSecurityTxt } from './lib/fetchProxy';
  import type { ValidationResult, ParsedLine, Finding, FetchMetadata, PgpInfo } from './lib/types';
  import type { FetchProxyError } from './lib/fetchProxy';
  import { onMount } from 'svelte';

  let validationResult: ValidationResult | null = null;
  let correctedText = '';
  let rawContent = '';
  let parsedLines: ParsedLine[] = [];
  let findings: Finding[] = [];
  let loading = false;
  let errorMessage = '';
  let mode: 'paste' | 'url' | 'generate' = 'paste';
  let theme: 'dark' | 'light' = 'dark';

  onMount(() => {
    const saved = localStorage.getItem('theme');
    if (saved === 'light' || saved === 'dark') {
      theme = saved;
    } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
      theme = 'light';
    }
    document.documentElement.setAttribute('data-theme', theme);
  });

  function toggleTheme() {
    theme = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }

  function runValidation(content: string, fetchMeta?: FetchMetadata) {
    const result = parse(content, { withPgp: true });
    parsedLines = result.lines;
    const pgp: PgpInfo = result.pgp;
    validationResult = validate(parsedLines, fetchMeta, pgp);
    findings = validationResult.findings;
    correctedText = generateCorrectedOutput(parsedLines, findings);
  }

  function clearResults() {
    validationResult = null;
    correctedText = '';
    rawContent = '';
    parsedLines = [];
    findings = [];
    errorMessage = '';
  }

  async function handleValidate(event: CustomEvent<{ mode: 'paste' | 'url' | 'generate'; content: string; domain: string }>) {
    const { mode: inputMode, content, domain } = event.detail;
    mode = inputMode;
    clearResults();

    if (inputMode === 'paste' || inputMode === 'generate') {
      try {
        runValidation(content);
      } catch {
        errorMessage = 'An unexpected error occurred during validation. Please try again.';
      }
      return;
    }

    // URL mode
    loading = true;
    try {
      const result = await fetchSecurityTxt(domain);
      rawContent = result.content;
      runValidation(result.content, result.metadata);
    } catch (err: unknown) {
      const proxyErr = err as FetchProxyError;
      errorMessage = mapProxyError(proxyErr);
    } finally {
      loading = false;
    }
  }

  function mapProxyError(err: FetchProxyError): string {
    switch (err.error) {
      case 'timeout':
        return 'The remote server did not respond within 10 seconds. Please check the domain and try again.';
      case 'size_limit':
        return 'The remote file exceeds the 100 KB size limit.';
      case 'dns_failure':
        return 'Could not resolve the domain. Please check the spelling.';
      case 'ssrf_blocked':
        return 'The provided URL targets a restricted address and cannot be fetched.';
      case 'invalid_content_type':
        return 'The remote server did not return a text/plain response.';
      case 'not_found':
        return 'No security.txt file was found on the remote server.';
      case 'too_many_redirects':
        return 'Too many redirects while fetching the file.';
      case 'http_error':
        return err.httpStatus
          ? `The remote server returned HTTP ${err.httpStatus}.`
          : 'The remote server returned an error.';
      case 'network_error':
        return 'Unable to reach the validation service. Please try again later.';
      default:
        return err.message || 'An unexpected error occurred. Please try again.';
    }
  }
</script>

<div class="container">
  <header class="header">
    <button class="theme-toggle" on:click={toggleTheme} aria-label="Toggle {theme === 'dark' ? 'light' : 'dark'} theme">
      {#if theme === 'dark'}
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
        </svg>
      {:else}
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        </svg>
      {/if}
    </button>
    <h1 class="title">security.txt validator</h1>
    <p class="subtitle">Validate and fix your security.txt file against RFC 9116</p>
  </header>

  <InputPanel on:validate={handleValidate} />

  {#if loading}
    <LoadingSpinner />
  {/if}

  {#if errorMessage}
    <div class="error-banner" role="alert">
      <p>{errorMessage}</p>
    </div>
  {/if}

  {#if validationResult}
    <div class="results-area">
      <ResultsPanel result={validationResult} {mode} />
      <CorrectedOutput {correctedText} lines={parsedLines} {findings} {mode} {rawContent} />
    </div>
  {/if}

  <FaqSection />

  <AdoptionBar />
</div>

<style>
  .header {
    text-align: center;
    margin-bottom: 2rem;
    position: relative;
  }

  .theme-toggle {
    position: absolute;
    top: 0;
    right: 0;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    color: var(--color-text-secondary);
    padding: 0.4rem;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: color var(--transition), border-color var(--transition);
  }

  .theme-toggle:hover {
    color: var(--color-accent);
    border-color: var(--color-accent);
  }

  .title {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--color-text);
    letter-spacing: -0.02em;
  }

  .subtitle {
    color: var(--color-text-secondary);
    font-size: 0.875rem;
    margin-top: 0.35rem;
  }

  .error-banner {
    background: rgba(255, 77, 106, 0.1);
    border: 1px solid var(--color-error);
    border-radius: var(--radius);
    padding: 0.75rem 1rem;
    margin-top: 1rem;
    color: var(--color-error);
    font-size: 0.875rem;
  }

  .results-area {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    margin-top: 1rem;
  }
</style>
