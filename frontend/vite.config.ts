import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        // Порт бэкенда бывает занят чем-то еще: SEKVYR_API дает запустить
        // панель рядом, не правя конфиг.
        target: process.env.SEKVYR_API || 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
