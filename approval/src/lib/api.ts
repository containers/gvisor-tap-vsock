export interface ConnectionRequest {
  protocol: string
  ip: string
  port: number
  count: number
  status: string // "pending" | "denied" | "approved"
  time: string
  last_seen: string
}

export interface DeniedDomain {
  domain: string
  count: number
  first_seen: string
  last_seen: string
}

const BASE = '/api'

export async function fetchNetworkConnections(): Promise<ConnectionRequest[]> {
  const res = await fetch(`${BASE}/network/connections`)
  return res.json()
}

export async function fetchNetworkPending(): Promise<ConnectionRequest[]> {
  const res = await fetch(`${BASE}/network/pending`)
  return res.json()
}

export async function fetchDnsPending(): Promise<DeniedDomain[]> {
  const res = await fetch(`${BASE}/dns/pending`)
  return res.json()
}

export async function fetchDnsAllowed(): Promise<string[]> {
  const res = await fetch(`${BASE}/dns/allowed`)
  return res.json()
}

export async function allowNetwork(protocol: string, ip: string, port: number): Promise<void> {
  await fetch(`${BASE}/network/allow`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ protocol, ip, port }),
  })
}

export async function denyNetwork(protocol: string, ip: string, port: number): Promise<void> {
  await fetch(`${BASE}/network/deny`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ protocol, ip, port }),
  })
}

export async function allowDns(domain: string): Promise<void> {
  await fetch(`${BASE}/dns/allow`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  })
}

export type SSEHandler = {
  onInit?: (connections: ConnectionRequest[]) => void
  onNetworkPending?: (req: ConnectionRequest) => void
  onNetworkDenied?: (req: ConnectionRequest) => void
  onNetworkApproved?: (req: ConnectionRequest) => void
  onDnsDenied?: (domain: DeniedDomain) => void
  onDnsAllowed?: (data: { domain: string }) => void
}

export function subscribeSSE(handlers: SSEHandler & { onConnected?: () => void }): () => void {
  const url = `${BASE}/network/events`
  console.log('[SSE] connecting to', url)
  const es = new EventSource(url)

  es.onopen = () => {
    console.log('[SSE] connection opened')
    handlers.onConnected?.()
  }

  es.onerror = (e) => {
    console.warn('[SSE] error, readyState:', es.readyState, e)
  }

  es.addEventListener('init', (e) => {
    console.log('[SSE] init event received:', e.data)
    const data = JSON.parse(e.data) as ConnectionRequest[]
    handlers.onInit?.(data)
  })

  es.addEventListener('network_pending', (e) => {
    console.log('[SSE] network_pending:', e.data)
    handlers.onNetworkPending?.(JSON.parse(e.data))
  })

  es.addEventListener('network_denied', (e) => {
    console.log('[SSE] network_denied:', e.data)
    handlers.onNetworkDenied?.(JSON.parse(e.data))
  })

  es.addEventListener('network_approved', (e) => {
    console.log('[SSE] network_approved:', e.data)
    handlers.onNetworkApproved?.(JSON.parse(e.data))
  })

  es.addEventListener('dns_denied', (e) => {
    console.log('[SSE] dns_denied:', e.data)
    handlers.onDnsDenied?.(JSON.parse(e.data))
  })

  es.addEventListener('dns_allowed', (e) => {
    console.log('[SSE] dns_allowed:', e.data)
    handlers.onDnsAllowed?.(JSON.parse(e.data))
  })

  return () => {
    console.log('[SSE] closing connection')
    es.close()
  }
}
