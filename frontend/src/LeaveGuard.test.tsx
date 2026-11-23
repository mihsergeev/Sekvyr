import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import App from './App'
import * as clipboard from './clipboard'
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
  const status = vi.mocked(api.vaultStatus)
  status.mockResolvedValueOnce({ ...(await status()), initialized: false, sealed: true })
  vi.spyOn(api, 'vaultPrepareInit').mockResolvedValue({
    mode: 'shares',
    shares: ['SEKVYR-1-aaa', 'SEKVYR-2-bbb', 'SEKVYR-3-ccc', 'SEKVYR-4-ddd', 'SEKVYR-5-eee'],
    root_key: '',
    warning: 'Test shares',
    proof: 'test-proof',
  })
  mount()
  fireEvent.click(await screen.findByRole('button', { name: 'Подготовить ключ или доли' }))
  expect(await screen.findByText('Запишите это сейчас')).toBeTruthy()
}

async function prepareRotation() {
  await screen.findByRole('button', { name: 'Запереть' })
  const dots = screen.getAllByRole('button', { name: 'Меню' }).find((b) => b.textContent?.includes('⋯'))!
  fireEvent.click(dots)
  fireEvent.click(screen.getByRole('button', { name: 'Сменить корневой ключ' }))
  expect(await screen.findByText('Сохраните новый ключ или доли')).toBeTruthy()
  return dots
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
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

describe('двухшаговое создание сейфа', () => {
  it.each(['shares', 'env'] as const)('сохраняет комплект до записи и повторяет тот же запрос (%s)', async (mode) => {
    window.history.replaceState(null, '', '/vault')
    const status = vi.mocked(api.vaultStatus)
    const original = await status()
    status.mockResolvedValue({ ...original, initialized: false, sealed: true, root_generation: 0 })
    const options = { mode, shares: 5, threshold: 3, auto_unseal: false }
    const prepared = mode === 'shares'
      ? { shares: ['TEST-A', 'TEST-B', 'TEST-C', 'TEST-D', 'TEST-E'], root_key: '', proof: 'test-proof' }
      : { shares: [], root_key: 'test-root', proof: 'test-proof' }
    let loseResponse!: (reason: Error) => void
    const pending = new Promise<Response>((_, reject) => { loseResponse = reject })
    const requests: { url: string; body: unknown }[] = []
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      requests.push({ url, body: JSON.parse(String(init.body)) })
      if (url === '/api/vault/init/prepare') return Response.json({ mode, ...prepared, warning: 'Test warning' })
      expect(url).toBe('/api/vault/init')
      if (requests.length === 2) {
        // Создание успело сохраниться, а панель уже перезапустилась запертой.
        status.mockResolvedValue({ ...original, initialized: true, sealed: true, mode })
        return pending
      }
      return Response.json({ mode, shares: [], root_key: '', warning: '' })
    })
    mount()
    const prepare = await screen.findByRole('button', { name: 'Подготовить ключ или доли' })
    if (mode === 'env') fireEvent.change(screen.getByLabelText('Режим ключа'), { target: { value: 'single' } })
    fireEvent.click(prepare)
    const visibleMaterial = prepared.root_key || prepared.shares[0]
    expect(await screen.findByText(visibleMaterial)).toBeTruthy()
    const submit = screen.getByRole('button', { name: 'Подтвердить создание' })
    expect(submit).toHaveProperty('disabled', true)
    expect(requests).toEqual([{ url: '/api/vault/init/prepare', body: options }])
    expect(screen.queryByText(prepared.proof)).toBeNull()
    expect(JSON.stringify(Object.values(localStorage))).not.toContain(visibleMaterial)

    fireEvent.click(screen.getByRole('checkbox', { name: 'Я сохранил новый ключ или все новые доли' }))
    fireEvent.click(submit)
    expect(requests[1]).toEqual({ url: '/api/vault/init', body: { ...options, prepared } })
    await expect(leaveGuard()!()).resolves.toBe(false)
    await act(async () => { loseResponse(new TypeError('connection reset')) })
    expect(screen.getByText(/Результат создания неизвестен/)).toBeTruthy()
    expect(screen.getByText(visibleMaterial)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Подготовить ключ или доли' })).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Повторить подтверждение' }))
    expect(await screen.findByText('Сейф создан. Для отпирания используйте сохраненный комплект.')).toBeTruthy()
    expect(requests[2]).toEqual(requests[1])
    expect(screen.queryByText(visibleMaterial)).toBeNull()
    expect(screen.getByText('заперта: значения не выдаются')).toBeTruthy()
    expect(leaveGuard()).toBeNull()
  })
})

describe('двухшаговая смена ключа', () => {
  it('показывает и копирует ключ, отмена не отправляет запрос смены', async () => {
    window.history.replaceState(null, '', '/vault')
    const preparation = { root_generation: 1, proof: 'test-proof', root_key: 'test-root-material', shares: [] }
    const fetch = vi.fn(async (_url: string, _options: RequestInit) => Response.json(preparation))
    vi.stubGlobal('fetch', fetch)
    const copy = vi.spyOn(clipboard, 'copyToClipboard').mockResolvedValue(true)
    mount()
    const dots = await prepareRotation()
    expect(screen.getByText(preparation.root_key)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Сменить' })).toHaveProperty('disabled', true)
    expect(screen.getByRole('button', { name: 'Запереть' })).toHaveProperty('disabled', true)
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Скопировать' })) })
    expect(copy).toHaveBeenCalledExactlyOnceWith(preparation.root_key)
    expect(screen.queryByText(preparation.proof)).toBeNull()
    expect(JSON.stringify(Object.values(localStorage))).not.toContain(preparation.root_key)
    fireEvent.click(screen.getByRole('button', { name: 'Отменить подготовку' }))
    expect(screen.queryByText(preparation.root_key)).toBeNull()
    expect(dots).toHaveProperty('disabled', false)
    expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/vault/rotate-root/prepare', expect.objectContaining({ method: 'POST' }))
    expect(fetch.mock.calls[0][1]).not.toHaveProperty('body')
  })

  it.each([false, true])('после потери ответа повторяет тот же запрос с сохраненными долями (заперта: %s)', async (sealed) => {
    window.history.replaceState(null, '', '/vault')
    const preparation = { root_generation: 1, proof: 'test-proof', root_key: '', shares: ['SEKVYR-1-aaa', 'SEKVYR-2-bbb'] }
    let loseResponse!: (reason: Error) => void
    const lostResponse = new Promise<Response>((_, reject) => { loseResponse = reject })
    const commits: unknown[] = []
    const status = vi.mocked(api.vaultStatus)
    const initialStatus = await status()
    const copy = vi.spyOn(clipboard, 'copyToClipboard').mockResolvedValue(true)
    vi.stubGlobal('fetch', async (url: string, options: RequestInit) => {
      if (url.endsWith('/prepare')) return Response.json(preparation)
      expect(url).toBe('/api/vault/rotate-root')
      expect(options.method).toBe('POST')
      commits.push(JSON.parse(String(options.body)))
      if (commits.length === 1) {
        status.mockResolvedValue({ ...initialStatus, sealed, root_generation: 2 })
        return lostResponse
      }
      return Response.json({ root_generation: 2, rewrapped_keys: 0, shares: [], root_key: '' })
    })
    mount()
    const dots = await prepareRotation()
    const submit = screen.getByRole('button', { name: 'Сменить' })
    expect(submit).toHaveProperty('disabled', true)
    expect(commits).toEqual([])
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Скопировать долю 2' })) })
    expect(copy).toHaveBeenCalledExactlyOnceWith(preparation.shares[1])
    fireEvent.click(screen.getByRole('checkbox', { name: 'Я сохранил новый ключ или все новые доли' }))
    fireEvent.click(submit)
    expect(commits).toEqual([preparation])
    expect(leaveGuard()).not.toBeNull()
    await expect(leaveGuard()!()).resolves.toBe(false)
    expect(dots).toHaveProperty('disabled', true)
    expect(screen.getByRole('button', { name: 'Запереть' })).toHaveProperty('disabled', true)

    await act(async () => { loseResponse(new TypeError('connection reset')) })
    expect(screen.getByText(/Результат смены неизвестен/)).toBeTruthy()
    expect(screen.getByText('Панель сообщает поколение ключа 2.')).toBeTruthy()
    expect(screen.getByText('SEKVYR-1-aaa')).toBeTruthy()
    expect(screen.getByText('SEKVYR-2-bbb')).toBeTruthy()
    if (sealed) expect(screen.getByText('заперта: значения не выдаются')).toBeTruthy()
    else expect(dots).toHaveProperty('disabled', true)
    fireEvent.click(screen.getByRole('button', { name: 'Повторить подтверждение' }))
    expect(await screen.findByText(/Корневой ключ сменён/)).toBeTruthy()
    expect(commits).toEqual([preparation, preparation])
    expect(screen.queryByText('SEKVYR-1-aaa')).toBeNull()
    expect(screen.queryByText('SEKVYR-2-bbb')).toBeNull()
    if (!sealed) expect(dots).toHaveProperty('disabled', false)
    expect(leaveGuard()).toBeNull()
  })
})

describe('leave guard', () => {
  it('переход на тот же раздел не снимает защиту, пока доли на экране', async () => {
    window.history.replaceState(null, '', '/vault')
    await showSecrets()
    expect(leaveGuard()).not.toBeNull()

    fireEvent.click(screen.getAllByRole('button', { name: 'Меню' }).find((b) => b.textContent?.includes('⚙'))!)
    fireEvent.click(screen.getByRole('button', { name: 'Сейф' }))
    await settle(2)
    expect(screen.getByText('Уйти до создания сейфа?')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Уйти' }))
    await settle(3)

    // Доли по-прежнему на экране, и защита ухода на месте.
    expect(screen.getByText('Запишите это сейчас')).toBeTruthy()
    expect(leaveGuard()).not.toBeNull()
  })

  it('выход с долями на экране спрашивает до выхода, а не над экраном входа', async () => {
    window.history.replaceState(null, '', '/vault')
    await showSecrets()
    fireEvent.click(screen.getAllByRole('button', { name: 'Меню' }).find((b) => b.textContent?.includes('⚙'))!)
    fireEvent.click(screen.getByText('Выйти'))
    await settle(3)
    // Вопрос - пока доли еще на экране: "Отмена" оставляет их.
    expect(screen.getByText('Уйти до создания сейфа?')).toBeTruthy()
    expect(screen.getByText('Запишите это сейчас')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Уйти' }))
    await settle(3)
    expect(screen.queryByText('Уйти до создания сейфа?')).toBeNull()
    expect(screen.queryByText('Запишите это сейчас')).toBeNull()
    expect(leaveGuard()).toBeNull()
  })

  it('назад и "уйти" не оставляют лишней записи сейфа в истории', async () => {
    window.history.replaceState(null, '', '/audit')
    window.history.pushState(null, '', '/vault')
    const startLen = window.history.length
    await showSecrets()
    await act(async () => {
      window.history.back()
      await new Promise((r) => setTimeout(r, 50))
    })
    await settle(2)
    expect(screen.getByText('Уйти до создания сейфа?')).toBeTruthy()
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

describe('состояние сейфа', () => {
  it('не переносит запоздавший статус покинутого сейфа в шапку другой страницы', async () => {
    window.history.replaceState(null, '', '/vault')
    const status = vi.mocked(api.vaultStatus)
    const original = await status()
    let respond!: (value: api.VaultStatus) => void
    status.mockReturnValueOnce(new Promise((resolve) => { respond = resolve }))
    mount()
    await screen.findByRole('button', { name: 'Проекты' })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Проекты' }))
    })
    await act(async () => { respond({ ...original, sealed: true }) })
    expect(window.location.pathname).toBe('/')
    expect(screen.queryByText('Панель заперта: чтобы читать значения, введите корневой ключ.')).toBeNull()
  })

  it.each([true, false])('отличает существующий файл от рабочего ключа (%s)', async (configured) => {
    window.history.replaceState(null, '', '/vault')
    vi.mocked(api.vaultStatus).mockResolvedValue({
      initialized: true,
      sealed: true,
      mode: 'env',
      shares: 0,
      threshold: 0,
      pending_shares: 0,
      root_generation: 2,
      auto_unseal_intent: true,
      root_key_configured: configured,
      key_file_path: '/example/vault.key',
      key_file_present: true,
    })
    mount()
    expect(await screen.findByText('/example/vault.key')).toBeTruthy()
    if (configured) {
      expect(screen.getByText('один ключ, панель поднимается сама')).toBeTruthy()
      expect(screen.getByText(/панель поднимается сама, но root на хосте открывает все значения/)).toBeTruthy()
    } else {
      expect(screen.getByText('один ключ, вводится вручную')).toBeTruthy()
      expect(screen.getByText(/Файл не подходит к текущему поколению ключа/)).toBeTruthy()
      expect(screen.queryByText(/панель поднимается сама, но root на хосте открывает все значения/)).toBeNull()
      const dots = screen.getAllByRole('button', { name: 'Меню' }).find((b) => b.textContent?.includes('⋯'))!
      const forget = vi.spyOn(api, 'vaultForgetKey').mockResolvedValue({ path: '/example/vault.key', present: false, detail: 'Ключ удалён' })
      fireEvent.click(dots)
      fireEvent.click(screen.getByRole('button', { name: 'Забыть ключ на сервере' }))
      const submit = await screen.findByRole('button', { name: 'Забыть' })
      await act(async () => { fireEvent.click(submit) })
      expect(forget).toHaveBeenCalledOnce()
    }
    expect(screen.getByLabelText('Доля или корневой ключ')).toHaveProperty('type', 'password')
  })

  it('запоздавший health не затирает подтвержденное состояние сейфа и не вызывает новую загрузку', async () => {
    window.history.replaceState(null, '', '/vault')
    let respond!: (value: api.Health) => void
    vi.mocked(api.getHealth).mockReturnValueOnce(new Promise((resolve) => { respond = resolve }))
    const status = vi.mocked(api.vaultStatus)
    status.mockResolvedValue({ ...(await status()), sealed: true })
    status.mockClear()
    mount()
    const banner = 'Панель заперта: чтобы читать значения, введите корневой ключ.'
    expect(await screen.findByText(banner)).toBeTruthy()
    await act(async () => { respond({ status: 'ok', version: '1', sealed: false, timezone: 'UTC' }) })
    expect(screen.getByText(banner)).toBeTruthy()
    expect(status).toHaveBeenCalledOnce()
  })
})
