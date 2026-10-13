import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import './App.css'
import './index.css'
import { DialogProvider } from './Dialogs'
import { I18nProvider } from './i18n'

// Тему применяем ДО рендера, иначе панель успевает мигнуть темной и
// перекраситься. По умолчанию темная - под нее сделан бренд.
// Без своего выбора панель открывается так же, как система: темная панель на
// светлом рабочем столе (и наоборот) - первое, что бросается в глаза.
const savedTheme = localStorage.getItem('sekvyr_theme')
const systemLight =
  savedTheme === null && window.matchMedia('(prefers-color-scheme: light)').matches

if (savedTheme === 'light' || systemLight) {
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
