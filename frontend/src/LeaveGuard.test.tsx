import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import App from './App'
import { DialogProvider } from './Dialogs'
import { I18nProvider } from './i18n'
import { leaveGuard } from './leave'

async function settle(n = 10) {
  for (let i = 0; i < n; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 10))
    })
  }
}

function mount() {
  render(
    <I18nProvider>
      <DialogProvider>
        <App />
      </DialogProvider>
    </I18nProvider>,
  )
}

async function showSecrets() {
  await settle()
  const dots = screen.getAllByRole('button', { name: 'Меню' }).find((b) => b.textContent?.includes('⋯'))!
  fireEvent.click(dots)
  fireEvent.click(screen.getByText('Сменить корневой ключ'))
  await settle(2)
  fireEvent.click(screen.getByRole('button', { name: 'Сменить' }))
  await settle()
  expect(screen.getByText('Запишите это сейчас')).toBeTruthy()
}

beforeEach(() => {
  window.matchMedia ??= ((q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} }
  vi.stubGlobal('fetch', () => Promise.reject(new Error('offline')))
  localStorage.setItem('sekvyr_token', 'tok')
  vi.spyOn(api, 'me').mockResolvedValue({
    username: 'alice',
    role: 'owner',
    level: 40,
    role_title: 'Владелец',
    totp_enabled: false,
  } as api.Me)
  vi.spyOn(api, 'getHealth').mockResolvedValue({ status: 'ok', version: '1', sealed: false, timezone: 'UTC' })
  vi.spyOn(api, 'getBranding').mockRejectedValue(new Error('x'))
  vi.spyOn(api, 'vaultStatus').mockResolvedValue({
    initialized: true,
    sealed: false,
    mode: 'shares',
    shares: 2,
    threshold: 2,
    pending_shares: 0,
    root_generation: 1,
    auto_unseal_intent: false,
    root_key_configured: false,
    key_file_path: '',
    key_file_present: false,
  })
  vi.spyOn(api, 'vaultRotateRoot').mockResolvedValue({
    root_generation: 2,
    rewrapped_keys: 0,
    shares: ['SEKVYR-1-aaa', 'SEKVYR-2-bbb'],
    root_key: '',
  })
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

describe('leave guard', () => {
  it('переход на тот же раздел не снимает защиту, пока доли на экране', async () => {
    window.history.replaceState(null, '', '/vault')
    mount()
    await showSecrets()
    expect(leaveGuard()).not.toBeNull()

    fireEvent.click(screen.getAllByRole('button', { name: 'Меню' }).find((b) => b.textContent?.includes('⚙'))!)
    fireEvent.click(screen.getByRole('button', { name: 'Сейф' }))
    await settle(2)
    expect(screen.getByText('Уйти, не записав?')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Уйти' }))
    await settle(3)

    // Доли по-прежнему на экране, и защита ухода на месте.
    expect(screen.getByText('Запишите это сейчас')).toBeTruthy()
    expect(leaveGuard()).not.toBeNull()
  })

  it('выход с долями на экране спрашивает до выхода, а не над экраном входа', async () => {
    window.history.replaceState(null, '', '/vault')
    mount()
    await showSecrets()
    fireEvent.click(screen.getAllByRole('button', { name: 'Меню' }).find((b) => b.textContent?.includes('⚙'))!)
    fireEvent.click(screen.getByText('Выйти'))
    await settle(3)
    // Вопрос - пока доли еще на экране: "Отмена" оставляет их.
    expect(screen.getByText('Уйти, не записав?')).toBeTruthy()
    expect(screen.getByText('Запишите это сейчас')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Уйти' }))
    await settle(3)
    expect(screen.queryByText('Уйти, не записав?')).toBeNull()
    expect(screen.queryByText('Запишите это сейчас')).toBeNull()
    expect(leaveGuard()).toBeNull()
  })

  it('назад и "уйти" не оставляют лишней записи сейфа в истории', async () => {
    window.history.replaceState(null, '', '/audit')
    window.history.pushState(null, '', '/vault')
    const startLen = window.history.length
    mount()
    await showSecrets()
    await act(async () => {
      window.history.back()
      await new Promise((r) => setTimeout(r, 50))
    })
    await settle(2)
    expect(screen.getByText('Уйти, не записав?')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Уйти' }))
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50))
    })
    await settle(3)
    // Ушли на журнал шагом назад: записей в истории не прибавилось, и
    // следующее "назад" не вернет на сейф.
    expect(window.location.pathname).toBe('/audit')
    expect(window.history.length).toBe(startLen)
  })
})
