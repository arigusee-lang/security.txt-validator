<script lang="ts">
  let open: Record<string, boolean> = {};

  function toggle(id: string) {
    open[id] = !open[id];
  }

  function handleKeydown(event: KeyboardEvent, id: string) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      toggle(id);
    }
  }

  const faqs = [
    {
      id: 'what',
      question: 'What is security.txt?',
      answer: 'A proposed standard (RFC 9116) that lets websites describe their vulnerability disclosure practices. It\'s a plain text file placed on your web server so security researchers know how to report issues.',
    },
    {
      id: 'where',
      question: 'Where should I place it?',
      answer: 'Place it at <code>/.well-known/security.txt</code> on your domain. A fallback at <code>/security.txt</code> is also recognized, but the <code>/.well-known/</code> location is preferred.',
    },
    {
      id: 'fields',
      question: 'What fields are required?',
      answer: 'Two fields are required: <code>Contact</code> (at least one, with a mailto:, https://, or tel: URI) and <code>Expires</code> (exactly one, in RFC 3339 date-time format). All other fields are optional.',
    },
  ];

  function futureDate(): string {
    const d = new Date();
    d.setFullYear(d.getFullYear() + 1);
    return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
  }

  const exampleFile = `Contact: mailto:security@example.com\nExpires: ${futureDate()}`;
</script>

<section class="faq-section" aria-label="Frequently asked questions">
  <h2 class="faq-title">FAQ</h2>

  {#each faqs as faq (faq.id)}
    <div class="faq-item">
      <button
        class="faq-question"
        aria-expanded={!!open[faq.id]}
        aria-controls="faq-answer-{faq.id}"
        on:click={() => toggle(faq.id)}
        on:keydown={(e) => handleKeydown(e, faq.id)}
      >
        <span class="chevron" class:open={open[faq.id]}></span>
        {faq.question}
      </button>
      {#if open[faq.id]}
        <div class="faq-answer" id="faq-answer-{faq.id}">
          <p>{@html faq.answer}</p>
        </div>
      {/if}
    </div>
  {/each}

  <div class="faq-item">
    <button
      class="faq-question"
      aria-expanded={!!open['example']}
      aria-controls="faq-answer-example"
      on:click={() => toggle('example')}
      on:keydown={(e) => handleKeydown(e, 'example')}
    >
      <span class="chevron" class:open={open['example']}></span>
      Example valid minimal file
    </button>
    {#if open['example']}
      <div class="faq-answer" id="faq-answer-example">
        <pre class="example-code"><code>{exampleFile}</code></pre>
      </div>
    {/if}
  </div>

  <p class="rfc-link">
    Full specification: <a href="https://www.rfc-editor.org/rfc/rfc9116" target="_blank" rel="noopener noreferrer">RFC 9116</a>
  </p>
</section>

<style>
  .faq-section {
    border-top: 1px solid var(--color-border);
    padding-top: 1.5rem;
    margin-top: 2rem;
  }

  .faq-title {
    font-size: 1rem;
    font-weight: 600;
    color: var(--color-text);
    margin-bottom: 1rem;
  }

  .faq-item {
    border-bottom: 1px solid var(--color-border);
  }

  .faq-question {
    width: 100%;
    background: none;
    border: none;
    color: var(--color-text);
    font-family: var(--font-family);
    font-size: 0.875rem;
    font-weight: 500;
    padding: 0.75rem 0;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    text-align: left;
    transition: color var(--transition);
  }

  .faq-question:hover {
    color: var(--color-accent);
  }

  .chevron {
    display: inline-block;
    width: 0;
    height: 0;
    border-top: 4px solid transparent;
    border-bottom: 4px solid transparent;
    border-left: 6px solid var(--color-text-secondary);
    transition: transform var(--transition);
    flex-shrink: 0;
  }

  .chevron.open {
    transform: rotate(90deg);
  }

  .faq-answer {
    padding: 0 0 0.75rem 1.5rem;
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    line-height: 1.6;
  }

  .faq-answer :global(code) {
    background: var(--color-bg);
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    font-size: 0.8em;
  }

  .example-code code {
    padding: 0;
    background: none;
    border-radius: 0;
  }

  .example-code {
    background: var(--color-bg);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.75rem;
    font-family: var(--font-mono);
    font-size: 0.8rem;
    line-height: 1.6;
    color: var(--color-text);
    overflow-x: auto;
    margin: 0;
  }

  .rfc-link {
    margin-top: 1rem;
    font-size: 0.8rem;
    color: var(--color-text-secondary);
  }
</style>
