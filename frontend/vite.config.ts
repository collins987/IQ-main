import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      // Admin dashboard APIs live under /api/admin/dashboard on the backend.
      // We must NOT strip the leading /api here, otherwise requests like
      // /api/admin/dashboard/health become /admin/dashboard/health and 404.
      '/api/admin/dashboard': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path,
      },

      // WebSocket stream for live dashboard events
      '/api/admin/dashboard/ws': {
        target: 'ws://localhost:8000',
        ws: true,
        changeOrigin: true,
        rewrite: (path) => path,
      },

      // All other backend APIs (e.g. /api/auth/login) keep the original
      // behavior: strip the /api prefix so FastAPI sees /auth/login, etc.
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },

      // Generic WS prefix if needed elsewhere
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
});
