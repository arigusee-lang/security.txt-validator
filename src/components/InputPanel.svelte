<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  const dispatch = createEventDispatcher<{
    validate: { mode: 'paste' | 'url' | 'generate'; content: string; domain: string };
  }>();

  type Tab = 'paste' | 'url' | 'generate';
  const tabList: { id: Tab; label: string }[] = [
    { id: 'paste', label: 'Paste' },
    { id: 'url', label: 'Fetch URL' },
    { id: 'generate', label: 'Generate' },
  ];

  let activeTab: Tab = 'url';
  let pasteContent = '';
  let urlInput = '';
  let errorMessage = '';
  let urlWarning = '';
  let isDragging = false;

  // Generator fields
  let genContacts = [''];
  let genExpires = '';
  let genPolicy = '';
  let genAcknowledgments = '';
  let genHiring = '';
  let genCsaf = '';
  let genLanguages = '';
  let genCanonical = '';
  let genCopied = false;
  let genCopyTimeout: ReturnType<typeof setTimeout> | null = null;

  // datetime-local value (no seconds, no Z)
  let genExpiresLocal = '';

  function initExpires() {
    const d = new Date();
    d.setFullYear(d.getFullYear() + 1);
    genExpires = d.toISOString().replace(/\.\d{3}Z$/, 'Z');
    // datetime-local needs YYYY-MM-DDTHH:mm format
    genExpiresLocal = d.toISOString().slice(0, 16);
  }
  initExpires();

  function onExpiresLocalChange() {
    if (genExpiresLocal) {
      // Convert local datetime to RFC 3339 UTC
      const d = new Date(genExpiresLocal);
      if (!isNaN(d.getTime())) {
        genExpires = d.toISOString().replace(/\.\d{3}Z$/, 'Z');
      }
    } else {
      genExpires = '';
    }
  }

  $: generatedText = buildSecurityTxt(genContacts, genExpires, genPolicy, genAcknowledgments, genHiring, genCsaf, genLanguages, genCanonical);

  function buildSecurityTxt(_contacts: string[], _expires: string, _policy: string, _ack: string, _hiring: string, _csaf: string, _lang: string, _canonical: string): string {
    const lines: string[] = [];
    for (const c of genContacts) {
      if (c.trim()) lines.push(`Contact: ${c.trim()}`);
    }
    if (genExpires.trim()) lines.push(`Expires: ${genExpires.trim()}`);
    if (genPolicy.trim()) lines.push(`Policy: ${genPolicy.trim()}`);
    if (genAcknowledgments.trim()) lines.push(`Acknowledgments: ${genAcknowledgments.trim()}`);
    if (genHiring.trim()) lines.push(`Hiring: ${genHiring.trim()}`);
    if (genCsaf.trim()) lines.push(`CSAF: ${genCsaf.trim()}`);
    if (genLanguages.trim()) lines.push(`Preferred-Languages: ${genLanguages.trim()}`);
    if (genCanonical.trim()) lines.push(`Canonical: ${genCanonical.trim()}`);
    return lines.join('\n');
  }

  function addContact() {
    genContacts = [...genContacts, ''];
  }

  function removeContact(i: number) {
    genContacts = genContacts.filter((_, idx) => idx !== i);
    if (genContacts.length === 0) genContacts = [''];
  }

  function switchTab(tab: Tab) {
    activeTab = tab;
    errorMessage = '';
    urlWarning = '';
  }

  function handleKeydown(event: KeyboardEvent, tab: Tab) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      switchTab(tab);
    }
  }

  function checkUrlWarning() {
    const trimmed = urlInput.trim();
    if (trimmed && !trimmed.startsWith('https://') && (trimmed.startsWith('http://') || trimmed.includes('://'))) {
      urlWarning = 'RFC 9116 requires HTTPS. The URL will be fetched over HTTPS.';
    } else {
      urlWarning = '';
    }
  }

  function handleDragOver(e: DragEvent) {
    e.preventDefault();
    isDragging = true;
  }

  function handleDragLeave() {
    isDragging = false;
  }

  function handleDrop(e: DragEvent) {
    e.preventDefault();
    isDragging = false;
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    if (!file.name.endsWith('.txt') && file.type !== 'text/plain') {
      errorMessage = 'Please drop a .txt file.';
      return;
    }
    if (file.size > 100 * 1024) {
      errorMessage = 'File is too large (max 100 KB).';
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      pasteContent = reader.result as string;
      activeTab = 'paste';
      errorMessage = '';
    };
    reader.onerror = () => {
      errorMessage = 'Could not read the file.';
    };
    reader.readAsText(file);
  }

  function handleValidate() {
    errorMessage = '';
    urlWarning = '';

    if (activeTab === 'paste') {
      if (!pasteContent.trim()) {
        errorMessage = 'Please paste your security.txt content before validating.';
        return;
      }
      dispatch('validate', { mode: 'paste', content: pasteContent, domain: '' });
    } else if (activeTab === 'url') {
      const trimmed = urlInput.trim();
      if (!trimmed) {
        errorMessage = 'Please enter a domain or URL.';
        return;
      }
      if (trimmed.startsWith('http://') || (trimmed.includes('://') && !trimmed.startsWith('https://'))) {
        urlWarning = 'RFC 9116 requires HTTPS. The URL will be fetched over HTTPS.';
      }
      dispatch('validate', { mode: 'url', content: '', domain: trimmed });
    } else {
      if (!generatedText.trim()) {
        errorMessage = 'Please fill in at least the Contact field.';
        return;
      }
      dispatch('validate', { mode: 'generate', content: generatedText, domain: '' });
    }
  }

  async function handleGenCopy() {
    try {
      await navigator.clipboard.writeText(generatedText);
      genCopied = true;
      if (genCopyTimeout) clearTimeout(genCopyTimeout);
      genCopyTimeout = setTimeout(() => { genCopied = false; }, 2000);
    } catch {
      genCopied = false;
    }
  }

  function handleGenDownload() {
    const blob = new Blob([generatedText], { type: 'text/plain' });
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

<div class="input-panel">
  <div class="tabs" role="tablist" aria-label="Input mode">
    {#each tabList as tab (tab.id)}
      <button
        role="tab"
        aria-selected={activeTab === tab.id}
        aria-controls="panel-{tab.id}"
        id="tab-{tab.id}"
        class="tab"
        class:active={activeTab === tab.id}
        tabindex={activeTab === tab.id ? 0 : -1}
        on:click={() => switchTab(tab.id)}
        on:keydown={(e) => handleKeydown(e, tab.id)}
      >
        {tab.label}
      </button>
    {/each}
  </div>

  {#if activeTab === 'paste'}
    <div
      role="tabpanel"
      id="panel-paste"
      aria-labelledby="tab-paste"
      class="panel"
      class:drag-over={isDragging}
      tabindex="0"
      on:dragover={handleDragOver}
      on:dragleave={handleDragLeave}
      on:drop={handleDrop}
    >
      <label for="paste-input" class="sr-only">Paste security.txt content or drop a .txt file</label>
      <textarea
        id="paste-input"
        class="paste-textarea"
        placeholder="Paste your security.txt content or drop a .txt file here..."
        aria-label="security.txt content"
        bind:value={pasteContent}
        rows="10"
      ></textarea>
      {#if isDragging}
        <div class="drop-overlay" aria-hidden="true">
          <span class="drop-label">Drop .txt file here</span>
        </div>
      {/if}
    </div>
  {:else if activeTab === 'url'}
    <div role="tabpanel" id="panel-url" aria-labelledby="tab-url" class="panel">
      <label for="url-input" class="sr-only">Enter domain or URL</label>
      <input
        id="url-input"
        class="url-input"
        type="text"
        placeholder="example.com"
        aria-label="Domain or URL to fetch security.txt from"
        bind:value={urlInput}
        on:input={checkUrlWarning}
        on:keydown={(e) => e.key === 'Enter' && handleValidate()}
      />
      {#if urlWarning}
        <p class="url-warning" role="alert">{urlWarning}</p>
      {/if}
    </div>
  {:else}
    <div role="tabpanel" id="panel-generate" aria-labelledby="tab-generate" class="panel">
      <div class="gen-form">
        <div class="gen-field">
          <span class="gen-label" id="contact-group-label">Contact <span class="required">*</span></span>
          {#each genContacts as contact, i}
            <div class="gen-contact-row">
              <input
                class="gen-input"
                type="text"
                placeholder="mailto:security@example.com"
                aria-label="Contact {i + 1}"
                aria-describedby="contact-group-label"
                bind:value={genContacts[i]}
                on:input={() => { genContacts = genContacts; }}
              />
              {#if genContacts.length > 1}
                <button class="gen-remove-btn" on:click={() => removeContact(i)} aria-label="Remove contact">&times;</button>
              {/if}
            </div>
          {/each}
          <button class="gen-add-btn" on:click={addContact}>+ Add contact</button>
        </div>

        <div class="gen-field">
          <label class="gen-label" for="gen-expires">Expires <span class="required">*</span></label>
          <div class="gen-expires-row">
            <input
              id="gen-expires"
              class="gen-input gen-expires-picker"
              type="datetime-local"
              bind:value={genExpiresLocal}
              on:input={onExpiresLocalChange}
            />
            <span class="gen-expires-rfc">{genExpires || 'Select a date'}</span>
          </div>
        </div>

        <div class="gen-field">
          <label class="gen-label" for="gen-policy">Policy <span class="optional">optional</span></label>
          <input id="gen-policy" class="gen-input" type="text" placeholder="https://example.com/security-policy" bind:value={genPolicy} />
        </div>

        <div class="gen-field">
          <label class="gen-label" for="gen-ack">Acknowledgments <span class="optional">optional</span></label>
          <input id="gen-ack" class="gen-input" type="text" placeholder="https://example.com/hall-of-fame" bind:value={genAcknowledgments} />
        </div>

        <div class="gen-field">
          <label class="gen-label" for="gen-hiring">Hiring <span class="optional">optional</span></label>
          <input id="gen-hiring" class="gen-input" type="text" placeholder="https://example.com/jobs" bind:value={genHiring} />
        </div>

        <div class="gen-field">
          <label class="gen-label" for="gen-csaf">CSAF <span class="optional">optional</span></label>
          <input id="gen-csaf" class="gen-input" type="text" placeholder="https://example.com/.well-known/csaf/provider-metadata.json" bind:value={genCsaf} />
        </div>

        <div class="gen-field">
          <label class="gen-label" for="gen-lang">Preferred-Languages <span class="optional">optional</span></label>
          <input id="gen-lang" class="gen-input" type="text" placeholder="en, fr, de" bind:value={genLanguages} />
        </div>

        <div class="gen-field">
          <label class="gen-label" for="gen-canonical">Canonical <span class="optional">optional</span></label>
          <input id="gen-canonical" class="gen-input" type="text" placeholder="https://example.com/.well-known/security.txt" bind:value={genCanonical} />
        </div>
      </div>

      {#if generatedText}
        <div class="gen-preview">
          <div class="gen-preview-header">
            <span class="gen-preview-title">Preview</span>
            <div class="gen-preview-actions">
              <button class="action-btn" on:click={handleGenCopy}>{genCopied ? 'Copied!' : 'Copy'}</button>
              <button class="action-btn" on:click={handleGenDownload}>Download</button>
            </div>
          </div>
          <pre class="gen-preview-code"><code>{generatedText}</code></pre>
          <div class="pgp-hint">
            <span class="pgp-hint-icon" aria-hidden="true">
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <circle cx="7" cy="7" r="7" fill="var(--color-info)"/>
                <path d="M7 6V10" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>
                <circle cx="7" cy="4" r="0.8" fill="#fff"/>
              </svg>
            </span>
            <div class="pgp-hint-content">
              <span class="pgp-hint-title">PGP signing (optional)</span>
              <p class="pgp-hint-text">RFC 9116 recommends signing your security.txt with PGP. After downloading, run:</p>
              <code class="pgp-hint-cmd">gpg --clearsign security.txt</code>
              <p class="pgp-hint-text">Then deploy the resulting <code>security.txt.asc</code> as your <code>security.txt</code>.</p>
            </div>
          </div>
        </div>
      {/if}
    </div>
  {/if}

  {#if errorMessage}
    <p class="error-message" role="alert">{errorMessage}</p>
  {/if}

  <button
    class="validate-btn"
    on:click={handleValidate}
    aria-label={activeTab === 'generate' ? 'Validate generated security.txt' : 'Validate security.txt'}
  >
    {activeTab === 'generate' ? 'Validate' : 'Validate'}
  </button>
</div>

<style>
  .input-panel {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    padding: 1.25rem;
  }

  .tabs {
    display: flex;
    gap: 0;
    margin-bottom: 1rem;
    border-bottom: 1px solid var(--color-border);
  }

  .tab {
    background: none;
    border: none;
    color: var(--color-text-secondary);
    font-family: var(--font-family);
    font-size: 0.875rem;
    font-weight: 500;
    padding: 0.5rem 1rem;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: color var(--transition), border-color var(--transition);
  }

  .tab:hover { color: var(--color-text); }
  .tab.active { color: var(--color-accent); border-bottom-color: var(--color-accent); }

  .panel { margin-bottom: 1rem; }

  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0;
  }

  .paste-textarea {
    width: 100%; background: var(--color-bg); color: var(--color-text);
    border: 1px solid var(--color-border); border-radius: var(--radius);
    padding: 0.75rem; font-family: var(--font-mono); font-size: 0.875rem;
    line-height: 1.5; resize: vertical; min-height: 160px;
    transition: border-color var(--transition);
  }
  .paste-textarea:focus { border-color: var(--color-accent); outline: none; }
  .paste-textarea::placeholder { color: var(--color-text-secondary); }

  .panel { position: relative; }

  .drag-over .paste-textarea {
    border-color: var(--color-accent);
    opacity: 0.5;
  }

  .drop-overlay {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 212, 170, 0.08);
    border: 2px dashed var(--color-accent);
    border-radius: var(--radius);
    pointer-events: none;
  }

  .drop-label {
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--color-accent);
  }

  .url-input {
    width: 100%; background: var(--color-bg); color: var(--color-text);
    border: 1px solid var(--color-border); border-radius: var(--radius);
    padding: 0.75rem; font-family: var(--font-family); font-size: 0.875rem;
    transition: border-color var(--transition);
  }
  .url-input:focus { border-color: var(--color-accent); outline: none; }
  .url-input::placeholder { color: var(--color-text-secondary); }

  .url-warning { color: var(--color-warning); font-size: 0.8rem; margin-top: 0.5rem; }
  .error-message { color: var(--color-error); font-size: 0.8rem; margin-bottom: 0.75rem; }

  .validate-btn {
    background: var(--color-accent); color: var(--color-bg); border: none;
    border-radius: var(--radius); padding: 0.6rem 1.5rem;
    font-family: var(--font-family); font-size: 0.875rem; font-weight: 600;
    cursor: pointer; transition: background var(--transition);
  }
  .validate-btn:hover { background: var(--color-accent-hover); }

  /* Generator styles */
  .gen-form { display: flex; flex-direction: column; gap: 0.75rem; }

  .gen-field { display: flex; flex-direction: column; gap: 0.3rem; }

  .gen-label {
    font-size: 0.8rem; font-weight: 500; color: var(--color-text-secondary);
  }
  .required { color: var(--color-accent); }
  .optional { color: var(--color-text-secondary); font-weight: 400; font-size: 0.7rem; opacity: 0.7; }

  .gen-input {
    width: 100%; background: var(--color-bg); color: var(--color-text);
    border: 1px solid var(--color-border); border-radius: var(--radius);
    padding: 0.5rem 0.75rem; font-family: var(--font-family); font-size: 0.8rem;
    transition: border-color var(--transition);
  }
  .gen-input:focus { border-color: var(--color-accent); outline: none; }
  .gen-input::placeholder { color: var(--color-text-secondary); }

  .gen-contact-row { display: flex; gap: 0.35rem; align-items: center; }
  .gen-contact-row .gen-input { flex: 1; }

  .gen-expires-row { display: flex; gap: 0.5rem; align-items: center; }
  .gen-expires-picker {
    flex: 0 0 auto; width: auto;
  }

  :global([data-theme="dark"]) .gen-expires-picker { color-scheme: dark; }
  :global([data-theme="light"]) .gen-expires-picker { color-scheme: light; }
  .gen-expires-rfc {
    font-family: var(--font-mono); font-size: 0.75rem;
    color: var(--color-text-secondary); white-space: nowrap;
  }

  .gen-remove-btn {
    background: none; border: none; color: var(--color-error);
    font-size: 1.1rem; cursor: pointer; padding: 0.2rem 0.4rem;
    line-height: 1; opacity: 0.7; transition: opacity var(--transition);
  }
  .gen-remove-btn:hover { opacity: 1; }

  .gen-add-btn {
    background: none; border: none; color: var(--color-accent);
    font-size: 0.8rem; cursor: pointer; padding: 0.2rem 0;
    text-align: left; font-family: var(--font-family);
    transition: opacity var(--transition);
  }
  .gen-add-btn:hover { opacity: 0.8; }

  .gen-preview {
    margin-top: 1rem; background: var(--color-bg);
    border: 1px solid var(--color-border); border-radius: var(--radius);
    padding: 0.75rem;
  }

  .gen-preview-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 0.5rem;
  }

  .gen-preview-title {
    font-size: 0.8rem; font-weight: 600; color: var(--color-text-secondary);
  }

  .gen-preview-actions { display: flex; gap: 0.35rem; }

  .action-btn {
    background: transparent; color: var(--color-accent);
    border: 1px solid var(--color-accent); border-radius: var(--radius);
    padding: 0.2rem 0.6rem; font-family: var(--font-family);
    font-size: 0.75rem; font-weight: 500; cursor: pointer;
    transition: background var(--transition), color var(--transition);
  }
  .action-btn:hover { background: var(--color-accent); color: var(--color-bg); }

  .gen-preview-code {
    font-family: var(--font-mono); font-size: 0.8rem; line-height: 1.6;
    color: var(--color-text); white-space: pre; margin: 0; overflow-x: auto;
  }

  .pgp-hint {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.75rem;
    padding: 0.6rem 0.75rem;
    background: rgba(77, 166, 255, 0.08);
    border: 1px solid rgba(77, 166, 255, 0.2);
    border-radius: var(--radius);
  }

  .pgp-hint-icon {
    display: inline-flex;
    align-items: flex-start;
    flex-shrink: 0;
    padding-top: 0.1rem;
  }

  .pgp-hint-content {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .pgp-hint-title {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--color-info);
  }

  .pgp-hint-text {
    font-size: 0.75rem;
    color: var(--color-text-secondary);
    line-height: 1.5;
    margin: 0;
  }

  .pgp-hint-text code {
    background: var(--color-surface);
    padding: 0.05rem 0.3rem;
    border-radius: 3px;
    font-size: 0.75rem;
  }

  .pgp-hint-cmd {
    display: block;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.35rem 0.6rem;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--color-text);
    user-select: all;
  }
</style>
