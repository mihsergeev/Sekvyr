/* Одиннадцатый проход: порог подтверждения в настройках проекта. */

import { act, render, screen } from '@testing-library/react'
import { useState, type ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { AuthProvider, toAuth } from './auth'
import { DialogProvider } from './Dialogs'
import { I18nProvider } from './i18n'
import { ProjectSettingsModal } from './ProjectSettingsModal'

async function settle(n = 10) {
  for (let i = 0; i < n; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 10))
    })
  }
}

function wrap(node: ReactNode) {
  return render(
    <I18nProvider>
      <DialogProvider>{node}</DialogProvider>
    </I18nProvider>,
  )
}

const OWNER = { username: 'alice', role: 'owner', level: 40, role_title: 'Владелец', totp_enabled: false } as api.Me

beforeEach(() => {
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} }
  window.matchMedia ??= ((q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  localStorage.removeItem('sekvyr_token')
  localStorage.removeItem('sekvyr_idle_minutes')
  localStorage.removeItem('sekvyr_active_at')
  document.body.innerHTML = ''
})

describe('порог подтверждения в настройках проекта', () => {
  function Settings({ level }: { level: number }) {
    const [project] = useState(
      { id: 1, slug: 'shop', title: '', e2e: false, approval_min_level: level, required_keys: '', stale_after_days: 365, group_name: '', group_slug: '', manage: true } as unknown as api.Project,
    )
    return (
      <AuthProvider value={toAuth(OWNER)}>
        <ProjectSettingsModal project={project} onClose={() => {}} onSaved={() => {}} onDeleted={() => {}} />
      </AuthProvider>
    )
  }

  beforeEach(() => {
    vi.spyOn(api, 'listProjects').mockResolvedValue([])
    vi.spyOn(api, 'listEnvironments').mockResolvedValue([])
  })

  it('40 выбирается и показывается как есть', async () => {
    wrap(<Settings level={40} />)
    await settle(2)
    const select = screen.getByRole('combobox', { name: /Подтверждение изменений/ }) as HTMLSelectElement
    expect(select.value).toBe('40')
    expect(select.selectedOptions[0].textContent).toBe('правки разработчиков и ответственных')
  })

  it('порог, выставленный через API, не выдается за "не требуется"', async () => {
    wrap(<Settings level={20} />)
    await settle(2)
    const select = screen.getByRole('combobox', { name: /Подтверждение изменений/ }) as HTMLSelectElement
    expect(select.value).toBe('20')
    expect(select.selectedOptions[0].textContent).toMatch(/наблюдателей/)
  })
})
