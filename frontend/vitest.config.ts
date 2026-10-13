/* Тесты интерфейса.
 *
 * Бэкенд держат две с половиной сотни тестов, а верстку и поведение страниц до
 * сих пор проверяли руками в браузере. Сюда идет то, что ломается молча: разбор
 * версий, отметки времени, сравнение значений, поведение поля с поиском.
 *
 * Отдельным файлом, а не блоком в vite.config.ts: сборку панели типы vitest не
 * касаются, и тянуть их в нее незачем.
 */

import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['src/test-setup.ts'],
  },
})
