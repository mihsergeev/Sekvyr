import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import './App.css'
import './index.css'
import { DialogProvider } from './Dialogs'
import { I18nProvider } from './i18n'

// Темная тема действует по умолчанию. Явный выбор применяем до рендера.
if (localStorage.getItem('sekvyr_theme') === 'light') {
  document.documentElement.setAttribute('data-theme', 'light')
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <I18nProvider>
      <DialogProvider>
        <App />
      </DialogProvider>
    </I18nProvider>
  </StrictMode>,
)
