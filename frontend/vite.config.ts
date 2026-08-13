import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

/**
 * Vite dev injects inline scripts and loads /@vite/client (uses eval/Function).
 * Chrome extensions and some security tools add a strict CSP that blocks those,
 * causing a blank page. This plugin strips them so dev works without unsafe-inline/eval.
 */
function cspFriendlyDev(): Plugin {
  return {
    name: 'csp-friendly-dev',
    apply: 'serve',
    transformIndexHtml: {
      order: 'post',
      handler(html) {
        return html
          .replace(
            /<script type="module">\s*import \{ injectIntoGlobalHook \} from "\/@react-refresh";[\s\S]*?<\/script>\s*/g,
            '',
          )
          .replace(
            /<script type="module" src="\/@vite\/client"><\/script>\s*/g,
            '',
          )
      },
    },
  }
}

const API_PORT = process.env.VITE_API_PORT ?? '8000'

export default defineConfig({
  plugins: [react(), cspFriendlyDev()],
  server: {
    port: 5173,
    strictPort: false,
    // Proxy API calls through Vite so the browser never hits cross-origin CORS issues
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${API_PORT}`,
        changeOrigin: true,
      },
    },
    hmr: false,
  },
  preview: {
    port: 5173,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${API_PORT}`,
        changeOrigin: true,
      },
    },
    hmr: false,
  },          


})
