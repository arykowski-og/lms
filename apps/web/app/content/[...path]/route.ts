import { NextRequest, NextResponse } from 'next/server'
import { getBackendUrl } from '@services/config/config'

// Same-origin proxy for media/content (`/content/...`). Mirrors the
// `/api/v1/[...path]` proxy so that media requests stay same-origin and carry
// the session cookie: a cross-origin <img> cannot send credentials
// (SameSite=Lax), so block media on a *private* course would 401 and break.
// Routing through here lets the backend authenticate the viewer's session and
// serve the file. Read-only — media is uploaded via /api/v1/blocks/*.
export const maxDuration = 300 // allow large video/audio range streams
export const dynamic = 'force-dynamic'
export const fetchCache = 'force-no-store'

const SKIP_REQUEST_HEADERS = new Set(['host', 'connection', 'keep-alive', 'transfer-encoding'])
// Node.js fetch auto-decompresses, so strip content-encoding to avoid the
// browser double-decompressing an already-decompressed body.
const SKIP_RESPONSE_HEADERS = new Set(['connection', 'keep-alive', 'transfer-encoding', 'content-encoding'])

async function proxyToBackend(request: NextRequest): Promise<Response> {
  const path = request.nextUrl.pathname
  const search = request.nextUrl.search
  const backendUrl = `${getBackendUrl().replace(/\/+$/, '')}${path}${search}`

  const headers = new Headers()
  request.headers.forEach((value, key) => {
    if (!SKIP_REQUEST_HEADERS.has(key.toLowerCase())) {
      headers.set(key, value)
    }
  })

  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), 290_000)

  try {
    const backendResponse = await fetch(backendUrl, {
      method: request.method,
      headers,
      signal: controller.signal,
    })
    clearTimeout(timeoutId)

    // Forward all backend headers. content-length must be preserved for
    // uncompressed bodies (including 206 range responses for video/audio
    // seeking); strip it only when the backend sent a compressed body, which
    // Node.js has already decompressed so the byte count no longer matches.
    const wasCompressed = backendResponse.headers.has('content-encoding')
    const responseHeaders = new Headers()
    backendResponse.headers.forEach((value, key) => {
      const lkey = key.toLowerCase()
      if (SKIP_RESPONSE_HEADERS.has(lkey)) return
      if (lkey === 'content-length' && wasCompressed) return
      responseHeaders.append(key, value)
    })

    // Stream the body directly — no buffering (preserves range streams).
    return new Response(backendResponse.body, {
      status: backendResponse.status,
      statusText: backendResponse.statusText,
      headers: responseHeaders,
    })
  } catch (error: any) {
    clearTimeout(timeoutId)
    if (error.name === 'AbortError') {
      return NextResponse.json({ error: 'Request timeout' }, { status: 504 })
    }
    console.error(`Failed to proxy ${backendUrl}:`, error.message || error)
    return NextResponse.json({ error: 'Backend unavailable' }, { status: 502 })
  }
}

export async function GET(request: NextRequest) {
  return proxyToBackend(request)
}

export async function HEAD(request: NextRequest) {
  return proxyToBackend(request)
}
