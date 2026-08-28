import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The UI is served under "/" by the Go API. A relative base keeps asset paths
// correct regardless of where the app is mounted.
export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    outDir: 'dist',
  },
  server: {
    // In dev, proxy /api to the running Go API so the browser can call it
    // without CORS friction.
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
