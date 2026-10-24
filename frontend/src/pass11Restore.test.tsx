/* Одиннадцатый проход: удаленный ключ возвращается кнопкой "Вернуть". */

import { act, fireEvent, render, screen, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { DialogProvider, useDialogs } from './Dialogs'
import { I18nProvider } from './i18n'
import { ProjectPage } from './ProjectPage'

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

function row(name: string, version: number, extra: Partial<api.SecretRow> = {}): api.SecretRow {
  return {
    name, path: '/', version, updated_by: 'a', updated_at: '', multiline: false, note: '', expires_at: '',
    ...extra,
  } as api.SecretRow
}

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

describe('удаленный ключ можно вернуть', () => {
  it('после удаления кнопка "Вернуть" откатывает к версии до удаления', async () => {
    vi.spyOn(api, 'listProjects').mockResolvedValue([
      { id: 1, slug: 'shop', title: '', e2e: false, approval_min_level: 0, required_keys: '', stale_after_days: 365, group_name: '', group_slug: '', manage: true } as unknown as api.Project,
    ])
    vi.spyOn(api, 'listEnvironments').mockResolvedValue([
      { id: 11, project_id: 1, name: 'prod', title: '', key_generation: 1, parent_id: null, parent_name: '', secret_count: 1, own_count: 1 } as unknown as api.Environment,
    ])
    vi.spyOn(api, 'listSecrets').mockResolvedValue([row('DB_URL', 4)])
    vi.spyOn(api, 'myPermissions').mockResolvedValue({ list: true, read: true, write: true, delete: true, rotate: true, approve: true } as api.Permissions)
    vi.spyOn(api, 'listPending').mockResolvedValue([])
    vi.spyOn(api, 'missingKeys').mockResolvedValue([])
    vi.spyOn(api, 'listMutes').mockResolvedValue([])
    vi.spyOn(api, 'lintEnv').mockResolvedValue([])
    vi.spyOn(api, 'listMachines').mockResolvedValue([])
    const del = vi.spyOn(api, 'deleteSecret').mockResolvedValue(undefined)
    const back = vi.spyOn(api, 'rollbackSecret').mockResolvedValue(row('DB_URL', 6))
    wrap(
      <ProjectPage group="" slug="shop" envName="prod" onEnvChosen={() => {}} onMoved={() => {}} onDeleted={() => {}} />,
    )
    await settle(20)
    const menus = screen.getAllByRole('button', { name: 'Меню' })
    fireEvent.click(menus[menus.length - 1])
    fireEvent.click(screen.getByRole('button', { name: 'Удалить' }))
    await settle(2)
    const dialog = screen.getByRole('alertdialog')
    expect(within(dialog).getByText(/кнопкой "Вернуть"/)).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Удалить' }))
    await settle()
    expect(del).toHaveBeenCalledWith(11, 'DB_URL', '/')
    expect(screen.getByText('DB_URL: ключ удален')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Вернуть' }))
    await settle()
    expect(back).toHaveBeenCalledWith(11, 'DB_URL', '/', 4)
  })

  it('кнопка при сообщении работает и убирает сообщение', async () => {
    const run = vi.fn()
    function Probe() {
      const { toast } = useDialogs()
      return <button onClick={() => toast('готово', { label: 'Вернуть', run })}>go</button>
    }
    wrap(<Probe />)
    fireEvent.click(screen.getByText('go'))
    fireEvent.click(screen.getByRole('button', { name: 'Вернуть' }))
    expect(run).toHaveBeenCalled()
    expect(screen.queryByText('готово')).toBeNull()
  })
})
