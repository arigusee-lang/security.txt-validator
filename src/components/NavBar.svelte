<script lang="ts">
  export let theme: 'dark' | 'light' = 'dark';
  export let currentPath: string = '/';

  import { createEventDispatcher, onDestroy } from 'svelte';
  import { currentUser, authLoading } from '../lib/authStore';
  import { post } from '../lib/api';

  const dispatch = createEventDispatcher<{ toggleTheme: void }>();

  let user: import('../lib/authStore').AuthUser | null = null;
  let loading = true;
  let dropdownOpen = false;
  let authMenuOpen = false;

  const unsubUser = currentUser.subscribe(v => (user = v));
  const unsubLoading = authLoading.subscribe(v => (loading = v));
  onDestroy(() => { unsubUser(); unsubLoading(); });

  $: menuTabs = user
    ? [
        { id: 'history', label: 'History' },
        { id: 'monitoring', label: 'Monitoring' },
        ...(user.plan === 'premium' || user.plan === 'premium_plus'
          ? [{ id: 'batch', label: 'Batch Scans' }]
          : []),
        { id: 'settings', label: 'Settings' },
        ...(user.role === 'admin' ? [{ id: 'admin', label: 'Admin' }] : []),
      ]
    : [];

  function toggleDropdown() {
    dropdownOpen = !dropdownOpen;
  }

  function closeDropdown() {
    dropdownOpen = false;
  }

  function toggleAuthMenu() {
    authMenuOpen = !authMenuOpen;
  }

  function closeAuthMenu() {
    authMenuOpen = false;
  }

  function handleDropdownKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggleDropdown();
    } else if (e.key === 'Escape') {
      closeDropdown();
    }
  }

  function handleMenuKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      closeDropdown();
    }
  }

  function handleClickOutside(e: MouseEvent) {
    const target = e.target as HTMLElement;
    if (!target.closest('.user-menu')) {
      closeDropdown();
    }
    if (!target.closest('.auth-menu')) {
      closeAuthMenu();
    }
  }

  async function signOut() {
    try {
      await post('/api/auth/logout');
    } catch {
      // ignore
    }
    currentUser.set(null);
    closeDropdown();
    window.location.hash = '#/';
  }
</script>

<svelte:window on:click={handleClickOutside} />

<nav class="navbar" aria-label="Main navigation">
  <div class="nav-left">
    <button class="theme-toggle" on:click={() => dispatch('toggleTheme')} aria-label="Toggle {theme === 'dark' ? 'light' : 'dark'} theme">
      {#if theme === 'dark'}
        <!-- contrast disc: left half filled -->
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="9"/>
          <path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor" stroke="none"/>
        </svg>
      {:else}
        <!-- contrast disc: right half filled -->
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="9"/>
          <path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none"/>
        </svg>
      {/if}
    </button>
    <a class="nav-brand" href="/#/" class:active={currentPath === '/' || currentPath === ''}>
      Domain Security Checker
    </a>
  </div>
  <div class="nav-links">
    <a class="nav-link" href="/#/security-txt" class:active={currentPath === '/security-txt'}>
      security.txt
    </a>

    {#if !loading}
      {#if user}
        <div class="user-menu" role="navigation" aria-label="User menu">
          <button
            class="user-trigger"
            on:click={toggleDropdown}
            on:keydown={handleDropdownKeydown}
            aria-expanded={dropdownOpen}
            aria-haspopup="true"
          >
            {#if user.avatarUrl}
              <img class="avatar" src={user.avatarUrl} alt="" width="24" height="24" referrerpolicy="no-referrer" />
            {:else}
              <span class="avatar-placeholder">{(user.name || user.email)[0].toUpperCase()}</span>
            {/if}
            <span class="user-email">{user.name || user.email}</span>
          </button>

          {#if dropdownOpen}
            <div class="dropdown" role="menu" tabindex="-1" on:keydown={handleMenuKeydown}>
              {#each menuTabs as tab}
                <a class="dropdown-item" href="/#/dashboard?tab={tab.id}" role="menuitem" on:click={closeDropdown}>
                  {tab.label}
                </a>
              {/each}
              <button class="dropdown-item" role="menuitem" on:click={signOut}>
                Sign out
              </button>
            </div>
          {/if}
        </div>
      {:else}
        <div class="auth-menu" role="navigation" aria-label="Sign in options">
          <button class="sign-in-btn" on:click={toggleAuthMenu} aria-expanded={authMenuOpen} aria-haspopup="true">
            Sign in
          </button>
          {#if authMenuOpen}
            <div class="auth-dropdown" role="menu">
              <a class="dropdown-item" href="/api/auth/google" role="menuitem" on:click={closeAuthMenu}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
                Google
              </a>
              <a class="dropdown-item" href="/api/auth/github" role="menuitem" on:click={closeAuthMenu}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
                GitHub
              </a>
            </div>
          {/if}
        </div>
      {/if}
    {/if}
  </div>
</nav>

<style>
  .navbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 0 1rem;
    border-bottom: 1px solid var(--color-border);
    margin-bottom: 1.5rem;
  }

  .nav-left {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  .nav-brand {
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--color-text);
    text-decoration: none;
    transition: color var(--transition);
  }

  .nav-brand:hover {
    color: var(--color-accent);
  }

  .nav-brand.active {
    color: var(--color-accent);
  }

  .nav-links {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .nav-link {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    text-decoration: none;
    padding: 0.25rem 0.5rem;
    border-radius: var(--radius);
    transition: color var(--transition);
  }

  .nav-link:hover {
    color: var(--color-text);
  }

  .nav-link.active {
    color: var(--color-accent);
  }

  .theme-toggle {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    color: var(--color-text-secondary);
    padding: 0.35rem;
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

  /* Auth elements */
  .sign-in-btn {
    font-size: 0.8rem;
    color: var(--color-accent);
    text-decoration: none;
    padding: 0.25rem 0.75rem;
    border: 1px solid var(--color-accent);
    border-radius: var(--radius);
    transition: background var(--transition), color var(--transition);
  }

  .sign-in-btn:hover {
    background: var(--color-accent);
    color: var(--color-bg);
  }

  .auth-menu {
    position: relative;
  }

  .auth-dropdown {
    position: absolute;
    top: calc(100% + 4px);
    right: 0;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    min-width: 140px;
    z-index: 100;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
  }

  .auth-dropdown .dropdown-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .user-menu {
    position: relative;
  }

  .user-trigger {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    color: var(--color-text);
    padding: 0.2rem 0.5rem;
    cursor: pointer;
    font-size: 0.8rem;
    transition: border-color var(--transition);
  }

  .user-trigger:hover {
    border-color: var(--color-accent);
  }

  .avatar {
    width: 24px;
    height: 24px;
    border-radius: 50%;
    object-fit: cover;
  }

  .avatar-placeholder {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--color-accent);
    color: var(--color-bg);
    font-size: 0.7rem;
    font-weight: 600;
  }

  .user-email {
    max-width: 120px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .dropdown {
    position: absolute;
    top: calc(100% + 4px);
    right: 0;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    min-width: 140px;
    z-index: 100;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
  }

  .dropdown-item {
    display: block;
    width: 100%;
    padding: 0.5rem 0.75rem;
    font-size: 0.8rem;
    color: var(--color-text);
    text-decoration: none;
    background: none;
    border: none;
    text-align: left;
    cursor: pointer;
    transition: background var(--transition);
  }

  .dropdown-item:hover {
    background: var(--color-border);
  }
</style>
