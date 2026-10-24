/* Одиннадцатый проход: отзыв права, снятие запрета и удаление участника
 * группы спрашивают. */

import { act, fireEvent, render, screen, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { AccessPage } from './AccessPage'
import { DialogProvider } from './Dialogs'
import { I18nProvider } from './i18n'

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

describe('доступ: подтверждения', () => {
  function policy(id: number, name: string, effect: string): api.PolicyRow {
    return {
      id, subject_type: 'user', subject_id: id, subject_name: name, project_id: 1, project_slug: 'shop',
      environment_id: null, environment_name: '', path_prefix: '/', actions: ['read'], effect,
      expires_at: '', require_2fa: false, created_by: 'alice', expired: false,
    }
  }

  beforeEach(() => {
    vi.spyOn(api, 'listPolicies').mockResolvedValue([policy(1, 'bob', 'deny'), policy(2, 'carol', 'allow')])
    vi.spyOn(api, 'listGroups').mockResolvedValue([{ id: 7, name: 'ops', members: ['bob'] }])
    vi.spyOn(api, 'listUsers').mockResolvedValue([
      { id: 5, username: 'bob', role: 'developer', role_title: '', disabled: false, totp_enabled: false, allow_ips: '', created_at: '' } as api.PanelUser,
    ])
    vi.spyOn(api, 'listProjects').mockResolvedValue([])
    vi.spyOn(api, 'listMachines').mockResolvedValue([])
  })

  async function openMenuOf(name: string) {
    const rowEl = screen.getByText(name).closest('.access-row') as HTMLElement
    fireEvent.click(within(rowEl).getByRole('button', { name: 'Меню' }))
    await settle(1)
  }

  it('запрет снимается кнопкой "Снять запрет" и только после вопроса', async () => {
    const del = vi.spyOn(api, 'deletePolicy').mockResolvedValue(undefined)
    wrap(<AccessPage onOpenServer={() => {}} />)
    await settle()
    await openMenuOf('bob')
    fireEvent.click(screen.getByRole('button', { name: 'Снять запрет' }))
    await settle(2)
    const dialog = screen.getByRole('alertdialog')
    expect(within(dialog).getByText(/доступ откроется/)).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Отмена' }))
    await settle(2)
    expect(del).not.toHaveBeenCalled()
  })

  it('отзыв права спрашивает', async () => {
    const del = vi.spyOn(api, 'deletePolicy').mockResolvedValue(undefined)
    wrap(<AccessPage onOpenServer={() => {}} />)
    await settle()
    await openMenuOf('carol')
    fireEvent.click(screen.getByRole('button', { name: 'Отозвать' }))
    await settle(2)
    const dialog = screen.getByRole('alertdialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Отозвать' }))
    await settle()
    expect(del).toHaveBeenCalledWith(2)
  })

  it('участник убирается из группы только после вопроса', async () => {
    const remove = vi.spyOn(api, 'removeGroupMember').mockResolvedValue(undefined)
    wrap(<AccessPage onOpenServer={() => {}} />)
    await settle()
    fireEvent.click(screen.getByRole('button', { name: 'bob ✕' }))
    await settle(2)
    expect(remove).not.toHaveBeenCalled()
    const dialog = screen.getByRole('alertdialog')
    expect(within(dialog).getByText('Убрать bob из группы ops?')).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Убрать' }))
    await settle()
    expect(remove).toHaveBeenCalledWith(7, 5)
  })
})
