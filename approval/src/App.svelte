<script lang="ts">
  import { onMount } from 'svelte'
  import DnsList from './lib/DnsList.svelte'
  import NetworkList from './lib/NetworkList.svelte'
  import {
    fetchDnsPending,
    fetchNetworkConnections,
    subscribeSSE,
    type ConnectionRequest,
    type DeniedDomain,
  } from './lib/api'

  let dnsDomains: DeniedDomain[] = $state([])
  let connections: ConnectionRequest[] = $state([])
  let connected = $state(false)

  function upsertConnection(req: ConnectionRequest) {
    const key = `${req.protocol}:${req.ip}:${req.port}`
    const idx = connections.findIndex(
      (c) => `${c.protocol}:${c.ip}:${c.port}` === key
    )
    if (idx >= 0) {
      connections[idx] = req
    } else {
      connections = [req, ...connections]
    }
  }

  function upsertDomain(d: DeniedDomain) {
    const idx = dnsDomains.findIndex((x) => x.domain === d.domain)
    if (idx >= 0) {
      dnsDomains[idx] = d
    } else {
      dnsDomains = [d, ...dnsDomains]
    }
  }

  onMount(() => {
    // Load initial data
    fetchDnsPending().then((d) => (dnsDomains = d || []))
    fetchNetworkConnections().then((c) => (connections = c || []))

    // Subscribe to real-time updates
    const unsubscribe = subscribeSSE({
      onConnected() {
        connected = true
      },
      onInit(conns) {
        connections = conns || []
      },
      onNetworkPending(req) {
        upsertConnection(req)
      },
      onNetworkDenied(req) {
        upsertConnection(req)
      },
      onNetworkApproved(req) {
        upsertConnection(req)
      },
      onDnsDenied(d) {
        upsertDomain(d)
      },
      onDnsAllowed(data) {
        // Remove matching domains from the denied list
        const pattern = data.domain
        if (pattern.startsWith('*.')) {
          const suffix = pattern.slice(1)
          dnsDomains = dnsDomains.filter(
            (d) => !d.domain.endsWith(suffix) && d.domain !== pattern
          )
        } else {
          dnsDomains = dnsDomains.filter((d) => d.domain !== pattern)
        }
      },
    })

    return unsubscribe
  })
</script>

<div class="min-h-screen bg-gray-50 dark:bg-gray-900">
  <header class="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
    <div class="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-gray-900 dark:text-gray-100">Network Policy</h1>
        <p class="text-sm text-gray-500 dark:text-gray-400">gvproxy secure mode</p>
      </div>
      <div class="flex items-center gap-2">
        <span class="inline-block w-2 h-2 rounded-full {connected ? 'bg-green-400' : 'bg-red-400'}"></span>
        <span class="text-xs text-gray-500 dark:text-gray-400">{connected ? 'Connected' : 'Connecting...'}</span>
      </div>
    </div>
  </header>

  <main class="max-w-4xl mx-auto px-4 py-6 space-y-6">
    <DnsList bind:domains={dnsDomains} />
    <NetworkList bind:connections={connections} />
  </main>
</div>
