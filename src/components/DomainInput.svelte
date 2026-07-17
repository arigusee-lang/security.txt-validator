<script lang="ts">
  import { createEventDispatcher, onDestroy } from 'svelte';
  import { currentUser } from '../lib/authStore';
  import type { CtSourcePref } from '../lib/types';

  const dispatch = createEventDispatcher<{ check: { domain: string; noCache: boolean; ctSource?: CtSourcePref } }>();

  let domain = '';
  let error = '';
  let noCache = false;
  // Primary CT source; the other acts as fallback. Defaults to the crt.sh
  // Postgres mirror (fast, full archive); CertSpotter is the alternate.
  let ctSource: CtSourcePref = 'crt.sh-pg';
  let settingsOpen = false;
  let settingsWrap: HTMLDivElement;

  let user: import('../lib/authStore').AuthUser | null = null;
  const unsubUser = currentUser.subscribe(v => (user = v));
  onDestroy(() => unsubUser());

  $: isAdmin = user?.role === 'admin';

  export function setDomain(d: string) {
    domain = d;
  }

  function handleSubmit() {
    error = '';
    const trimmed = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!trimmed) {
      error = 'Please enter a domain.';
      return;
    }
    domain = trimmed;
    dispatch('check', { domain: trimmed, noCache, ctSource });
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') handleSubmit();
  }

  function toggleSettings() {
    settingsOpen = !settingsOpen;
  }

  function handleSettingsKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') settingsOpen = false;
  }

  function handleDocClick(e: MouseEvent) {
    if (settingsOpen && settingsWrap && !settingsWrap.contains(e.target as Node)) {
      settingsOpen = false;
    }
  }
</script>

<svelte:window on:mousedown={handleDocClick} on:keydown={handleSettingsKeydown} />

<div class="domain-input-wrap">
  <div class="input-row">
    <label for="domain-input" class="sr-only">Enter a domain</label>
    <div class="input-field">
      <input
        id="domain-input"
        class="domain-input"
        type="text"
        placeholder="example.com"
        aria-label="Domain to check"
        bind:value={domain}
        on:keydown={handleKeydown}
      />
      {#if isAdmin}
        <div class="settings-wrap" bind:this={settingsWrap}>
          <button
            type="button"
            class="settings-btn"
            on:click={toggleSettings}
            aria-label="Admin scan settings"
            aria-expanded={settingsOpen}
            title="Admin settings"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
          </button>
          {#if settingsOpen}
            <div class="settings-panel" role="dialog" aria-label="Admin scan settings">
              <span class="panel-title">Admin Settings</span>
              <label class="dev-toggle">
                <input type="checkbox" bind:checked={noCache} />
                <span>Skip cache</span>
              </label>
              <fieldset class="source-group">
                <legend>CT data source (primary)</legend>
                <label class="dev-toggle">
                  <input type="radio" name="ctSource" value="crt.sh-pg" bind:group={ctSource} />
                  <span>crt.sh (Postgres)</span>
                </label>
                <label class="dev-toggle">
                  <input type="radio" name="ctSource" value="certspotter" bind:group={ctSource} />
                  <span>CertSpotter</span>
                </label>
              </fieldset>
            </div>
          {/if}
        </div>
      {/if}
    </div>
    <button class="check-btn" on:click={handleSubmit}>Check</button>
  </div>
  {#if error}
    <p class="error-msg" role="alert">{error}</p>
  {/if}
</div>

<style>
  .domain-input-wrap {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .input-row {
    display: flex;
    gap: 0.5rem;
  }

  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0;
  }

  .input-field {
    position: relative;
    flex: 1;
    display: flex;
  }

  .domain-input {
    flex: 1;
    width: 100%;
    background: var(--color-bg);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.7rem 0.9rem;
    font-family: var(--font-family);
    font-size: 0.9rem;
    transition: border-color var(--transition);
  }

  .domain-input:focus {
    border-color: var(--color-accent);
    outline: none;
  }

  .domain-input::placeholder {
    color: var(--color-text-secondary);
  }

  .domain-input:-webkit-autofill,
  .domain-input:-webkit-autofill:hover,
  .domain-input:-webkit-autofill:focus,
  .domain-input:-webkit-autofill:active {
    -webkit-box-shadow: 0 0 0 1000px var(--color-bg) inset;
    -webkit-text-fill-color: var(--color-text);
    caret-color: var(--color-text);
    transition: background-color 9999s ease-in-out 0s;
  }

  .settings-wrap {
    position: absolute;
    top: 50%;
    right: 0.45rem;
    transform: translateY(-50%);
  }

  .settings-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    border: none;
    border-radius: var(--radius);
    color: var(--color-text-secondary);
    padding: 0.25rem;
    cursor: pointer;
    transition: color var(--transition), background var(--transition);
  }

  .settings-btn:hover {
    color: var(--color-accent);
    background: var(--color-surface-2, rgba(255, 255, 255, 0.06));
  }

  .settings-panel {
    position: absolute;
    top: calc(100% + 6px);
    right: 0;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.6rem 0.75rem;
    min-width: 200px;
    z-index: 50;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  .panel-title {
    font-size: 0.65rem;
    font-weight: 600;
    color: var(--color-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding-bottom: 0.3rem;
    border-bottom: 1px solid var(--color-border);
  }

  .check-btn {
    background: var(--color-accent);
    color: var(--color-bg);
    border: none;
    border-radius: var(--radius);
    padding: 0.7rem 1.5rem;
    font-family: var(--font-family);
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: background var(--transition);
    white-space: nowrap;
  }

  .check-btn:hover {
    background: var(--color-accent-hover);
  }

  .error-msg {
    color: var(--color-error);
    font-size: 0.8rem;
  }

  .dev-toggle {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: var(--color-text);
    cursor: pointer;
  }

  .dev-toggle input {
    accent-color: var(--color-accent);
    cursor: pointer;
  }

  .source-group {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    margin: 0;
    padding: 0.4rem 0 0;
    border: none;
    border-top: 1px solid var(--color-border);
  }

  .source-group legend {
    font-size: 0.65rem;
    font-weight: 600;
    color: var(--color-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 0;
    margin-bottom: 0.2rem;
  }
</style>
