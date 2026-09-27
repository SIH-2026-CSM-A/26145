import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: { chunkSizeWarningLimit: 1200 }, // three.js; bundled so the UI needs no network
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: process.env.API || 'http://localhost:8000',
        changeOrigin: true,
      }
    }
  }
})