<div class="spinner-container" role="status" aria-label="Loading">
  <div class="spinner"></div>
  <span class="sr-only">Fetching security.txt…</span>
</div>

<style>
  .spinner-container {
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 2rem;
  }

  .spinner {
    width: 32px;
    height: 32px;
    border: 3px solid var(--color-border);
    border-top-color: var(--color-accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
</style>
