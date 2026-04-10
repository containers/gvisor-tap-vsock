<script lang="ts">
  import type { DeniedDomain } from './api'
  import { allowDns } from './api'

  let { domains = $bindable([]) }: { domains: DeniedDomain[] } = $props()

  function wildcardFor(domain: string): string {
    const parts = domain.split('.')
    if (parts.length <= 2) return `*.${domain}`
    return `*.${parts.slice(1).join('.')}`
  }

  async function approve(domain: string) {
    await allowDns(domain)
    domains = domains.filter((d) => d.domain !== domain)
  }

  async function approveWildcard(domain: string) {
    const pattern = wildcardFor(domain)
    await allowDns(pattern)
    const suffix = pattern.slice(1) // ".example.com"
    domains = domains.filter((d) => !d.domain.endsWith(suffix) && d.domain !== domain)
  }
</script>

<div class="bg-white dark:bg-gray-800 rounded-lg shadow">
  <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
    <h2 class="text-lg font-semibold text-gray-900 dark:text-gray-100">DNS Requests</h2>
    <p class="text-sm text-gray-500 dark:text-gray-400">Domains blocked by DNS policy</p>
  </div>

  {#if domains.length === 0}
    <div class="px-4 py-8 text-center text-gray-400 dark:text-gray-500">
      No pending DNS requests
    </div>
  {:else}
    <ul class="divide-y divide-gray-100 dark:divide-gray-700">
      {#each domains as d (d.domain)}
        <li class="px-4 py-3 flex items-center justify-between gap-4">
          <div class="min-w-0 flex-1">
            <p class="font-mono text-sm text-gray-900 dark:text-gray-100 truncate">{d.domain}</p>
            <p class="text-xs text-gray-500 dark:text-gray-400">
              {d.count} request{d.count !== 1 ? 's' : ''} &middot; last seen {d.last_seen}
            </p>
          </div>
          <div class="flex gap-2 shrink-0">
            <button
              onclick={() => approve(d.domain)}
              class="px-3 py-1 text-xs font-medium rounded bg-green-600 text-white hover:bg-green-700 cursor-pointer"
            >
              Allow
            </button>
            <button
              onclick={() => approveWildcard(d.domain)}
              class="px-3 py-1 text-xs font-medium rounded bg-blue-600 text-white hover:bg-blue-700 cursor-pointer"
              title="Allow {wildcardFor(d.domain)}"
            >
              {wildcardFor(d.domain)}
            </button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</div>
