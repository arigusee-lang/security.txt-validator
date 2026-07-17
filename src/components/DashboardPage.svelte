<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { currentUser, authLoading } from '../lib/authStore';
  import HistoryTab from './HistoryTab.svelte';
  import BatchScansTab from './BatchScansTab.svelte';
  import SettingsTab from './SettingsTab.svelte';
  import AdminTab from './AdminTab.svelte';
  import MonitoringTab from './MonitoringTab.svelte';

  let user: import('../lib/authStore').AuthUser | null = null;
  let loading = true;

  // Restore tab from URL hash on load
  function getTabFromHash(): string {
    const params = new URLSearchParams(window.location.hash.replace(/^#\/dashboard\??/, ''));
    return params.get('tab') || 'history';
  }
  let activeTab = getTabFromHash();

  const baseTabs = [
    { id: 'history', label: 'History' },
    { id: 'monitoring', label: 'Monitoring' },
    { id: 'batch', label: 'Batch Scans' },
    { id: 'settings', label: 'Settings' },
  ];

  $: tabs = user?.role === 'admin'
    ? [...baseTabs, { id: 'admin', label: 'Admin' }]
    : baseTabs;

  const unsubUser = currentUser.subscribe(v => {
    user = v;
    if (!v && !loading) {
      window.location.hash = '#/';
    }
  });
  const unsubLoading = authLoading.subscribe(v => {
    loading = v;
    if (!v && !user) {
      window.location.hash = '#/';
    }
  });

  function syncTabFromHash() {
    activeTab = getTabFromHash();
  }
  onMount(() => {
    window.addEventListener('hashchange', syncTabFromHash);
    return () => window.removeEventListener('hashchange', syncTabFromHash);
  });
  onDestroy(() => { unsubUser(); unsubLoading(); });

  function selectTab(id: string) {
    activeTab = id;
    window.location.hash = `#/dashboard?tab=${id}`;
  }

  function handleTabKeydown(e: KeyboardEvent, id: string) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      selectTab(id);
    }
  }
</script>

{#if loading}
  <p class="loading-msg">Loading…</p>
{:else if !user}
  <div class="auth-prompt">
    <p>Please <a href="/api/auth/google">sign in</a> to access your dashboard.</p>
  </div>
{:else}
  <div class="dashboard">
    <h1 class="dashboard-title">Dashboard</h1>

    <div class="tabs" role="tablist" aria-label="Dashboard sections">
      {#each tabs as tab}
        <button
          class="tab-btn"
          class:active={activeTab === tab.id}
          role="tab"
          aria-selected={activeTab === tab.id}
          tabindex={activeTab === tab.id ? 0 : -1}
          on:click={() => selectTab(tab.id)}
          on:keydown={(e) => handleTabKeydown(e, tab.id)}
        >
          {tab.label}
        </button>
      {/each}
    </div>

    <div class="tab-content" role="tabpanel">
      {#if activeTab === 'history'}
        <HistoryTab />
      {:else if activeTab === 'batch'}
        <BatchScansTab />
      {:else if activeTab === 'settings'}
        <SettingsTab />
      {:else if activeTab === 'monitoring'}
        <MonitoringTab />
      {:else if activeTab === 'admin'}
        <AdminTab />
      {/if}
    </div>
  </div>
{/if}

<style>
  .loading-msg {
    text-align: center;
    color: var(--color-text-secondary);
    font-size: 0.85rem;
    padding: 2rem 0;
  }

  .auth-prompt {
    text-align: center;
    padding: 3rem 0;
    color: var(--color-text-secondary);
    font-size: 0.9rem;
  }

  .dashboard {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .dashboard-title {
    font-size: 1.3rem;
    font-weight: 700;
    color: var(--color-text);
  }

  .tabs {
    display: flex;
    gap: 0;
    border-bottom: 1px solid var(--color-border);
  }

  .tab-btn {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--color-text-secondary);
    font-size: 0.8rem;
    font-weight: 500;
    padding: 0.5rem 0.75rem;
    cursor: pointer;
    font-family: var(--font-family);
    transition: color var(--transition), border-color var(--transition);
  }

  .tab-btn:hover {
    color: var(--color-text);
  }

  .tab-btn.active {
    color: var(--color-accent);
    border-bottom-color: var(--color-accent);
  }

  .tab-content {
    min-height: 200px;
  }
</style>
