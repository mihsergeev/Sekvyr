/* Одиннадцатый проход: вкладки делят сессию, панель без связи не выглядит
 * истекшей сессией. */

import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import App from './App'
import { DialogProvider } from './Dialogs'
import * as e2e from './e2e'
import { EnvironmentPage } from './EnvironmentPage'
import { I18nProvider } from './i18n'
import { LoginPage } from './LoginPage'
import { PasswordModal } from './PasswordModal'
import { TwoFactorModal } from './TwoFactorModal'

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

function changeTokenFromAnotherTab(token: string | null) {
  const oldValue = api.getToken()
  if (token === null) localStorage.removeItem('sekvyr_token')
  else localStorage.setItem('sekvyr_token', token)
  window.dispatchEvent(new StorageEvent('storage', { key: 'sekvyr_token', oldValue, newValue: token }))
}

beforeEach(() => {
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} }
  window.matchMedia ??= ((q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia
})

describe('замок проекта с шифрованием в браузере', () => {
  it.each(['показать значение', 'Скопировать значение'])(
    'не выдает значение после запирания: %s',
    async (action) => {
      api.setToken('test-token')
      e2e.rememberKey(3, new Uint8Array([1]))
      vi.stubGlobal('fetch', async (url: string) => Response.json(
        url.endsWith('/permissions') ? { list: true, read: true } : [],
      ))
      const row = {
        name: 'TEST_VALUE', path: '/', version: 1, updated_by: '', updated_at: '',
        multiline: false, note: '', expires_at: '',
      }
      vi.spyOn(api, 'listSecrets').mockResolvedValue([row])
      vi.spyOn(api, 'readSecret').mockResolvedValue({ ...row, value: 'encrypted-fixture' })
      let finishDecrypt!: (value: string) => void
      const decrypt = vi.spyOn(e2e, 'openValue').mockReturnValueOnce(
        new Promise((resolve) => { finishDecrypt = resolve }),
      )
      const writeText = vi.fn().mockResolvedValue(undefined)
      vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } })
      wrap(<EnvironmentPage envId={2} projectId={3} e2e />)

      fireEvent.click(await screen.findByTitle(action))
      await waitFor(() => expect(decrypt).toHaveBeenCalledOnce())
      fireEvent.click(screen.getByRole('button', { name: 'Запереть' }))
      expect(e2e.keyFor(3)).toBeNull()
      await act(async () => { finishDecrypt('decrypted-fixture') })

      expect(screen.queryByText('decrypted-fixture')).toBeNull()
      expect(screen.queryByDisplayValue('decrypted-fixture')).toBeNull()
      expect(writeText).not.toHaveBeenCalled()
      expect(screen.getByRole('button', { name: 'Ввести пароль проекта' })).toBeTruthy()
    },
  )
})

it('после ухода из обычного окружения поздний ответ не копирует значение', async () => {
  api.setToken('test-token')
  vi.stubGlobal('fetch', async (url: string) => Response.json(
    url.endsWith('/permissions') ? { list: true, read: true } : [],
  ))
  const row: api.SecretRow = {
    name: 'TEST_VALUE', path: '/', version: 1, updated_by: '', updated_at: '',
    multiline: false, note: '', expires_at: '',
  }
  vi.spyOn(api, 'listSecrets').mockResolvedValue([row])
  let respond!: (value: api.SecretValue) => void
  const read = vi.spyOn(api, 'readSecret').mockReturnValue(new Promise((resolve) => { respond = resolve }))
  const writeText = vi.fn().mockResolvedValue(undefined)
  vi.stubGlobal('navigator', Object.assign(Object.create(navigator), { clipboard: { writeText } }))
  const view = wrap(<EnvironmentPage envId={2} projectId={3} />)
  fireEvent.click(await screen.findByTitle('Скопировать значение'))
  expect(read).toHaveBeenCalledWith(2, row.name, row.path)
  view.unmount()

  await act(async () => { respond({ ...row, value: 'secret-fixture' }) })
  expect(writeText).not.toHaveBeenCalled()
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  e2e.forgetAllKeys()
  localStorage.removeItem('sekvyr_token')
  localStorage.removeItem('sekvyr_idle_minutes')
  localStorage.removeItem('sekvyr_active_at')
  document.body.innerHTML = ''
})

describe('нет связи с панелью', () => {
  it('сетевой отказ - понятный текст и status 0, а не Failed to fetch', async () => {
    vi.stubGlobal('fetch', () => Promise.reject(new TypeError('Failed to fetch')))
    const err = await api.listProjects().catch((e) => e)
    expect(err).toBeInstanceOf(api.ApiError)
    expect(err.status).toBe(0)
    expect(err.message).toBe('Нет связи с панелью: проверьте сеть и повторите')
  })

  it('пустой 502 от прокси - "панель не отвечает", а не "Ошибка HTTP 502"', async () => {
    vi.stubGlobal('fetch', async () => new Response('', { status: 502 }))
    const err = await api.listProjects().catch((e) => e)
    expect(err.message).toBe('Панель не отвечает (HTTP 502): повторите чуть позже')
  })

  it('недоступная при загрузке панель - не экран входа, токен цел', async () => {
    localStorage.setItem('sekvyr_token', 'tok')
    vi.stubGlobal('fetch', () => Promise.reject(new Error('offline')))
    vi.spyOn(api, 'getBranding').mockRejectedValue(new Error('x'))
    const me = vi.spyOn(api, 'me').mockRejectedValue(new api.ApiError('Нет связи с панелью: проверьте сеть и повторите', 0))
    vi.spyOn(api, 'getHealth').mockResolvedValue({ status: 'ok', version: '1', sealed: false, timezone: 'UTC' })
    wrap(<App />)
    await settle()
    expect(screen.getByText('Нет связи с панелью')).toBeTruthy()
    expect(screen.queryByText('Вход в панель')).toBeNull()
    expect(localStorage.getItem('sekvyr_token')).toBe('tok')
    me.mockResolvedValue(OWNER)
    fireEvent.click(screen.getByRole('button', { name: 'Повторить' }))
    await settle()
    expect(screen.queryByText('Нет связи с панелью')).toBeNull()
  })
})

describe('вкладки делят сессию', () => {
  it('запоздалый вход не заменяет сессию соседней вкладки', async () => {
    const onLogin = vi.fn()
    vi.spyOn(api, 'login').mockImplementation(async () => {
      changeTokenFromAnotherTab('other-session')
      return { access_token: 'late-login' }
    })
    wrap(<LoginPage onLogin={onLogin} branding={null} />)
    fireEvent.change(screen.getByLabelText('Логин'), { target: { value: 'alice' } })
    fireEvent.change(screen.getByLabelText('Пароль'), { target: { value: 'fixture-password' } })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Войти' })) })
    expect(api.getToken()).toBe('other-session')
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('ответ о смене пароля не закрывает новую сессию', async () => {
    api.setToken('old-session')
    const onChanged = vi.fn()
    vi.spyOn(api, 'changeOwnPassword').mockImplementation(async () => {
      changeTokenFromAnotherTab('other-session')
    })
    wrap(<PasswordModal onClose={() => {}} onChanged={onChanged} />)
    fireEvent.change(screen.getByLabelText('Текущий пароль'), { target: { value: 'fixture-password' } })
    fireEvent.change(screen.getByLabelText('Новый пароль'), { target: { value: 'new-fixture-password' } })
    fireEvent.change(screen.getByLabelText('Пароль ещё раз'), { target: { value: 'new-fixture-password' } })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Сохранить' })) })
    expect(onChanged).not.toHaveBeenCalled()
  })

  it.each([false, true])('ответ о смене 2FA не восстанавливает старую сессию (%s)', async (enabled) => {
    api.setToken('old-session')
    const onChanged = vi.fn()
    vi.spyOn(api, 'totpStart').mockResolvedValue({ secret: 'fixture', otpauth_url: 'otpauth://totp/fixture' })
    vi.spyOn(api, enabled ? 'totpDisable' : 'totpEnable').mockImplementation(async () => {
      changeTokenFromAnotherTab(null)
      return { access_token: 'late-refresh' }
    })
    wrap(<TwoFactorModal enabled={enabled} onClose={() => {}} onChanged={onChanged} />)
    fireEvent.change(screen.getByLabelText('Пароль'), { target: { value: 'fixture-password' } })
    fireEvent.change(screen.getByLabelText('Код из приложения'), { target: { value: '123456' } })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: enabled ? 'Выключить' : 'Включить' }))
    })
    expect(api.getToken()).toBeNull()
    expect(onChanged).not.toHaveBeenCalled()
  })

  function mountApp() {
    localStorage.setItem('sekvyr_token', 'tok')
    vi.stubGlobal('fetch', () => Promise.reject(new Error('offline')))
    vi.spyOn(api, 'getBranding').mockRejectedValue(new Error('x'))
    vi.spyOn(api, 'getHealth').mockResolvedValue({ status: 'ok', version: '1', sealed: false, timezone: 'UTC' })
    return vi.spyOn(api, 'me').mockResolvedValue(OWNER)
  }

  it('выход в соседней вкладке: здесь вход и ключи e2e забыты', async () => {
    mountApp()
    wrap(<App />)
    await settle()
    expect(screen.queryByText('Вход в панель')).toBeNull()
    const forget = vi.spyOn(e2e, 'forgetAllKeys')
    localStorage.removeItem('sekvyr_token')
    act(() => {
      window.dispatchEvent(new StorageEvent('storage', { key: 'sekvyr_token', newValue: null }))
    })
    await settle()
    expect(forget).toHaveBeenCalled()
    expect(screen.getByText('Вход в панель')).toBeTruthy()
  })

  it('вход в соседней вкладке подхватывается с экрана входа', async () => {
    const me = mountApp()
    localStorage.removeItem('sekvyr_token')
    wrap(<App />)
    await settle()
    expect(screen.getByText('Вход в панель')).toBeTruthy()
    localStorage.setItem('sekvyr_token', 'tok2')
    act(() => {
      window.dispatchEvent(new StorageEvent('storage', { key: 'sekvyr_token', newValue: 'tok2' }))
    })
    await settle()
    expect(me).toHaveBeenCalled()
    expect(screen.queryByText('Вход в панель')).toBeNull()
  })

  it.each([200, 401])('игнорирует ответ %i старой сессии после смены токена', async (status) => {
    api.setToken('old-session')
    let respond!: (response: Response) => void
    const pending = new Promise<Response>((resolve) => { respond = resolve })
    const oldMe = vi.fn(() => pending)
    vi.stubGlobal('fetch', async (url: string, options: RequestInit) => {
      if (url !== '/api/auth/me') return Response.json([])
      if (new Headers(options.headers).get('Authorization') === 'Bearer old-session') return oldMe()
      return Response.json(OWNER)
    })
    wrap(<App />)
    expect(oldMe).toHaveBeenCalledOnce()

    act(() => {
      changeTokenFromAnotherTab(status === 200 ? null : 'new-session')
    })
    await settle()
    await act(async () => {
      respond(Response.json(status === 200 ? OWNER : { detail: 'expired' }, { status }))
    })
    if (status === 200) {
      expect(screen.getByText('Вход в панель')).toBeTruthy()
      expect(api.getToken()).toBeNull()
    } else {
      expect(screen.queryByText('Вход в панель')).toBeNull()
      expect(api.getToken()).toBe('new-session')
    }
  })

  it.each(['bob', 'alice'])('скрывает прежние права до проверки новой сессии (%s)', async (username) => {
    const me = mountApp()
    wrap(<App />)
    await settle()
    expect(screen.getByRole('button', { name: 'Доступ' })).toBeTruthy()
    e2e.rememberKey(1, new Uint8Array([1]))

    let respond!: (value: api.Me) => void
    me.mockReturnValueOnce(new Promise((resolve) => { respond = resolve }))
    act(() => changeTokenFromAnotherTab('viewer-token'))
    expect(screen.queryByRole('button', { name: 'Доступ' })).toBeNull()
    expect(e2e.keyFor(1)).toBeNull()

    await act(async () => {
      respond({ ...OWNER, username, role: 'viewer', level: 10, role_title: 'Наблюдатель' })
    })
    expect(screen.queryByRole('button', { name: 'Доступ' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Меню' }))
    expect(screen.getByText(`${username} · Наблюдатель`)).toBeTruthy()
  })

  it('завершившаяся после смены сессии расшифровка не возвращает ключ в память', async () => {
    api.setToken('old-token')
    vi.stubGlobal('fetch', async (url: string) => Response.json(url.endsWith('/permissions') ? { read: true } : []))
    let respond!: (key: e2e.Bytes) => void
    const unlock = vi.spyOn(e2e, 'unlockProjectKey').mockReturnValueOnce(new Promise((resolve) => { respond = resolve }))
    const view = wrap(<EnvironmentPage envId={2} projectId={3} e2e />)
    fireEvent.click(await screen.findByRole('button', { name: 'Ввести пароль проекта' }))
    const password = await screen.findByLabelText(/Пароль проекта/, { selector: 'input' })
    fireEvent.change(password, { target: { value: 'synthetic-password' } })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Открыть' }))
    })
    expect(unlock).toHaveBeenCalledOnce()

    api.setToken(null)
    e2e.forgetAllKeys()
    view.unmount()
    api.setToken('new-token')
    await act(async () => { respond(new Uint8Array([1])) })
    expect(e2e.keyFor(3)).toBeNull()
  })

  it('актуальный 401 завершает загрузку и открывает экран входа', async () => {
    api.setToken('expired-session')
    vi.stubGlobal('fetch', async (url: string) => url === '/api/auth/me'
      ? Response.json({ detail: 'expired' }, { status: 401 })
      : Response.json({}))
    wrap(<App />)
    await settle()
    expect(screen.getByText('Вход в панель')).toBeTruthy()
    expect(api.getToken()).toBeNull()
  })

  it('фоновая вкладка не выходит по бездействию, пока работают в соседней', async () => {
    vi.useFakeTimers()
    mountApp()
    localStorage.setItem('sekvyr_idle_minutes', '1')
    wrap(<App />)
    const tick = async (ms: number) => {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(ms)
      })
    }
    await tick(200)
    expect(screen.queryByText('Вход в панель')).toBeNull()
    // Соседняя вкладка отмечает действие каждые полминуты.
    for (let i = 0; i < 4; i++) {
      await tick(30_000)
      localStorage.setItem('sekvyr_active_at', String(Date.now()))
    }
    expect(screen.queryByText('Вход в панель')).toBeNull()
    // Там тоже перестали: через минуту выход.
    await tick(91_000)
    expect(screen.getByText('Вход в панель')).toBeTruthy()
  })
})
