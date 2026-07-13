const { withSentryConfig } = require("@sentry/nextjs");

// API origin for the same-origin media reverse-proxy (see rewrites() below).
// On split frontend/backend deploys (web on enablement-*, API on
// enablement-api) the browser must only ever talk to the web origin so that
// `content/...` media requests are same-origin and carry the session cookie —
// a cross-site <img> cannot send credentials (SameSite=Lax). Trailing slash is
// stripped so the rewrite destination is well-formed.
const LEARNHOUSE_BACKEND_URL = (process.env.NEXT_PUBLIC_LEARNHOUSE_BACKEND_URL || '').replace(/\/+$/, '')

/** @type {import('common.next').NextConfig} */
const nextConfig = {
  // Vercel/Next's default trailing-slash normalization 308-redirects
  // /api/v1/courses/ -> /api/v1/courses BEFORE it reaches our [...path]
  // proxy route. The backend registers collection endpoints (e.g.
  // POST /api/v1/courses/) WITH the trailing slash, so that redirect strips
  // the slash the backend needs; the backend's own redirect_slashes then
  // redirects again, and the proxy's outbound fetch() fails following that
  // second hop (surfaced to users as a 502 "Backend unavailable" on course
  // creation). Skip Next's redirect so /api/v1/* paths reach the proxy —
  // and therefore the backend — exactly as the client sent them.
  skipTrailingSlashRedirect: true,
  async rewrites() {
    const rewrites = [
      {
        source: '/umami/script.js',
        destination: `https://eu.umami.is/script.js`,
      },
      {
        source: '/umami/api/send',
        destination: `https://eu.umami.is/api/send`,
      },
    ]
    // Reverse-proxy media/content same-origin to the API. Edge-level rewrite
    // (more robust than an App Router route handler) — preserves Range requests
    // for video/audio seeking and forwards cookies for private-course media.
    // Only when the backend is a distinct origin (skipped on same-host/local
    // deploys, where getMediaUrl() already points media straight at the API).
    if (LEARNHOUSE_BACKEND_URL) {
      rewrites.push({
        source: '/content/:path*',
        destination: `${LEARNHOUSE_BACKEND_URL}/content/:path*`,
      })
    }
    return rewrites
  },
  async headers() {
    const shellOrigin = process.env.PSP_SHELL_ORIGIN || ''
    const frameAncestors = shellOrigin
      ? `frame-ancestors 'self' ${shellOrigin}`
      : "frame-ancestors 'self'"
    return [
      {
        source: '/embed/:orgslug/course/:courseuuid/activity/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'ALLOWALL' },
          { key: 'Content-Security-Policy', value: 'frame-ancestors *' },
        ],
      },
      // PSP embed: allow the configured shell origin to frame the token-exchange
      // landing page and the dashboard. CSP frame-ancestors only (no
      // X-Frame-Options, which can't express an allowlist and would conflict).
      {
        source: '/auth/token-exchange',
        headers: [{ key: 'Content-Security-Policy', value: frameAncestors }],
      },
      {
        source: '/orgs/:orgslug/dash/:path*',
        headers: [{ key: 'Content-Security-Policy', value: frameAncestors }],
      },
      {
        source: '/orgs/:orgslug/dash',
        headers: [{ key: 'Content-Security-Policy', value: frameAncestors }],
      },
      {
        source: '/home',
        headers: [{ key: 'Content-Security-Policy', value: frameAncestors }],
      },
    ]
  },
  reactStrictMode: false,
  output: 'standalone',
  images: {
    remotePatterns: [
      {
        protocol: 'http',
        hostname: '**',
      },
      {
        protocol: 'https',
        hostname: '**',
      },
    ],
  },
  experimental: {
    optimizePackageImports: [
      '@phosphor-icons/react',
      'framer-motion',
      'lucide-react',
      '@emoji-mart/react',
      '@emoji-mart/data',
      'dayjs',
      'highlight.js',
      'recharts',
      '@radix-ui/react-icons',
      '@hello-pangea/dnd',
      'react-i18next',
      '@tiptap/core',
      '@tiptap/react',
      '@tiptap/starter-kit',
      '@tiptap/extension-table',
      '@tiptap/extension-table-cell',
      '@tiptap/extension-table-header',
      '@tiptap/extension-table-row',
      '@tiptap/extension-youtube',
      '@tiptap/extension-link',
      '@tiptap/extension-placeholder',
      '@tiptap/extension-code-block-lowlight',
      '@tiptap/extension-heading',
      '@tiptap/extension-bullet-list',
      '@tiptap/extension-ordered-list',
      '@tiptap/extension-list-item',
      '@tiptap/extension-collaboration',
      '@tiptap/extension-collaboration-caret',
      '@uiw/react-codemirror',
      'lowlight',
      'katex',
      'react-katex',
    ],
  },
  // Ensure consistent build IDs across multiple pods in Kubernetes
  generateBuildId: async () => {
    return process.env.BUILD_ID || 'learnhouse-production'
  },
}

// Generate runtime config for development, and for Vercel builds (where the
// container entrypoint that normally writes runtime-config.js never runs, so
// the client would otherwise fall back to localhost).
if (process.env.NODE_ENV === 'development' || process.env.VERCEL) {
  const fs = require('fs')
  const path = require('path')
  const runtimeConfig = {}

  Object.keys(process.env).forEach((key) => {
    if (key.startsWith('NEXT_PUBLIC_')) {
      runtimeConfig[key] = process.env[key]
    }
  })

  const publicDir = path.join(__dirname, 'public')
  if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir, { recursive: true })

  fs.writeFileSync(
    path.join(publicDir, 'runtime-config.js'),
    `window.__RUNTIME_CONFIG__ = ${JSON.stringify(runtimeConfig)};`,
    'utf8'
  )
}

// Always wrap with Sentry — DSN is resolved at runtime, not build time
module.exports = withSentryConfig(nextConfig, {
  org: process.env.SENTRY_ORG,
  project: process.env.SENTRY_PROJECT,
  silent: true,
  disableLogger: true,
  tunnelRoute: "/monitoring",
  sourcemaps: {
    disable: !process.env.SENTRY_ORG || !process.env.SENTRY_PROJECT,
  },
  bundleSizeOptimizations: {
    excludeDebugStatements: true,
    excludeReplayIframe: true,
    excludeReplayShadowDom: true,
  },
});
