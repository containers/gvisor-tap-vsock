<script lang="ts">
  import type { ConnectionRequest } from './api'
  import { allowNetwork, denyNetwork } from './api'

  let { connections = $bindable([]) }: { connections: ConnectionRequest[] } = $props()

  function statusColor(status: string): string {
    switch (status) {
      case 'pending': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
      case 'approved': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
      case 'denied': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
    }
  }

  function statusDot(status: string): string {
    switch (status) {
      case 'pending': return 'bg-yellow-400 animate-pulse'
      case 'approved': return 'bg-green-400'
      case 'denied': return 'bg-red-400'
      default: return 'bg-gray-400'
    }
  }

  async function approve(c: ConnectionRequest) {
    await allowNetwork(c.protocol, c.ip, c.port)
    updateStatus(c, 'approved')
  }

  async function deny(c: ConnectionRequest) {
    await denyNetwork(c.protocol, c.ip, c.port)
    updateStatus(c, 'denied')
  }

  function updateStatus(c: ConnectionRequest, status: string) {
    connections = connections.map((conn) =>
      conn.protocol === c.protocol && conn.ip === c.ip && conn.port === c.port
        ? { ...conn, status }
        : conn
    )
  }
</script>

<div class="bg-white dark:bg-gray-800 rounded-lg shadow">
  <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
    <h2 class="text-lg font-semibold text-gray-900 dark:text-gray-100">Network Connections</h2>
    <p class="text-sm text-gray-500 dark:text-gray-400">Outbound TCP/UDP connections</p>
  </div>

  {#if connections.length === 0}
    <div class="px-4 py-8 text-center text-gray-400 dark:text-gray-500">
      No network connections tracked
    </div>
  {:else}
    <ul class="divide-y divide-gray-100 dark:divide-gray-700">
      {#each connections as c (`${c.protocol}:${c.ip}:${c.port}`)}
        <li class="px-4 py-3 flex items-center justify-between gap-4">
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <span class="inline-block w-2 h-2 rounded-full {statusDot(c.status)}"></span>
              <span class="font-mono text-sm text-gray-900 dark:text-gray-100">
                {c.protocol.toUpperCase()} {c.ip}:{c.port}
              </span>
              <span class="inline-flex px-2 py-0.5 text-xs font-medium rounded-full {statusColor(c.status)}">
                {c.status}
              </span>
            </div>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5 ml-4">
              {c.count} attempt{c.count !== 1 ? 's' : ''} &middot; last seen {c.last_seen}
            </p>
          </div>
          {#if c.status === 'pending' || c.status === 'denied'}
            <div class="flex gap-2 shrink-0">
              <button
                onclick={() => approve(c)}
                class="px-3 py-1 text-xs font-medium rounded bg-green-600 text-white hover:bg-green-700 cursor-pointer"
              >
                Allow
              </button>
              {#if c.status === 'pending'}
                <button
                  onclick={() => deny(c)}
                  class="px-3 py-1 text-xs font-medium rounded bg-red-600 text-white hover:bg-red-700 cursor-pointer"
                >
                  Deny
                </button>
              {/if}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>
