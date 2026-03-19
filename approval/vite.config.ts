import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { Agent } from 'node:http'
import { connect } from 'node:net'

const SOCKET_PATH = process.env.GVPROXY_SOCKET || '/tmp/gvproxy-services.sock'

export default defineConfig({
  plugins: [
    svelte(),
    tailwindcss(),
    {
      name: 'sse-proxy',
      configureServer(server) {
        // Handle SSE with a raw TCP socket to avoid http.request buffering
        server.middlewares.use('/api/network/events', (_req, res) => {
          console.log('[sse-proxy] new SSE connection')

          const socket = connect(SOCKET_PATH)

          socket.on('connect', () => {
            console.log('[sse-proxy] connected to Unix socket')
            // Send raw HTTP request
            socket.write(
              'GET /services/network/events HTTP/1.1\r\n' +
              'Host: localhost\r\n' +
              'Accept: text/event-stream\r\n' +
              'Connection: keep-alive\r\n' +
              '\r\n'
            )
          })

          let headersParsed = false
          let buffer = ''

          socket.on('data', (chunk: Buffer) => {
            if (!headersParsed) {
              buffer += chunk.toString()
              const headerEnd = buffer.indexOf('\r\n\r\n')
              if (headerEnd === -1) return

              // Parse status line to check for errors
              const headerSection = buffer.substring(0, headerEnd)
              console.log('[sse-proxy] response headers:', headerSection.split('\r\n')[0])

              // Set SSE headers on browser response
              res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
              })

              headersParsed = true
              // Forward any body data that came with the headers
              const body = buffer.substring(headerEnd + 4)
              if (body.length > 0) {
                console.log('[sse-proxy] forwarding initial body:', body.length, 'bytes')
                res.write(body)
              }
              buffer = ''
            } else {
              // Handle chunked transfer encoding - Go sends chunked by default
              const data = chunk.toString()
              // Strip chunk size lines (hex number followed by \r\n)
              const cleaned = data.replace(/^[0-9a-fA-F]+\r\n/gm, '').replace(/\r\n$/g, '\n')
              if (cleaned.trim().length > 0) {
                console.log('[sse-proxy] forwarding:', cleaned.trim().substring(0, 80))
              }
              res.write(cleaned)
            }
          })

          socket.on('error', (err) => {
            console.error('[sse-proxy] socket error:', err.message)
            res.end()
          })

          socket.on('close', () => {
            console.log('[sse-proxy] socket closed')
            res.end()
          })

          // Clean up when browser disconnects
          _req.on('close', () => {
            console.log('[sse-proxy] browser disconnected')
            socket.destroy()
          })
        })
      },
    },
  ],
  server: {
    proxy: {
      '/api': {
        target: `http://localhost`,
        rewrite: (path) => path.replace(/^\/api/, '/services'),
        agent: new Agent({ socketPath: SOCKET_PATH } as any),
      },
    },
  },
})
