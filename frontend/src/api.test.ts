/* Конец сессии посреди работы: токен истек, пароль сменили в другой вкладке,
 * учетку отключили. Каждая страница раньше показывала свою ошибку, а страница
 * проекта и вовсе "Проекта нет". Теперь приложение слышит событие и показывает
 * вход.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { SESSION_GONE, api, getToken, setToken } from './api'

function answer(status: number, body: unknown) {
  return vi.fn(async () => new Response(JSON.stringify(body), { status }))
}

afterEach(() => {
  vi.unstubAllGlobals()
  setToken(null)
})

describe('api: отвергнутый токен', () => {
  it('снимает токен и сообщает приложению', async () => {
    setToken('old-token')
    vi.stubGlobal('fetch', answer(401, { detail: 'Недействительный или отсутствующий токен' }))
    const gone = vi.fn()
    window.addEventListener(SESSION_GONE, gone)
    await expect(api('/api/projects')).rejects.toThrow()
    window.removeEventListener(SESSION_GONE, gone)
    expect(getToken()).toBeNull()
    expect(gone).toHaveBeenCalledTimes(1)
  })

  it('отказ по правам сессию не трогает', async () => {
    setToken('live-token')
    vi.stubGlobal('fetch', answer(403, { detail: 'Требуются права владельца панели' }))
    const gone = vi.fn()
    window.addEventListener(SESSION_GONE, gone)
    await expect(api('/api/users')).rejects.toThrow()
    window.removeEventListener(SESSION_GONE, gone)
    expect(getToken()).toBe('live-token')
    expect(gone).not.toHaveBeenCalled()
  })

  it('неверный пароль при входе - не конец сессии', async () => {
    vi.stubGlobal('fetch', answer(401, { detail: 'Неверный логин или пароль' }))
    const gone = vi.fn()
    window.addEventListener(SESSION_GONE, gone)
    await expect(api('/api/auth/login', { method: 'POST' })).rejects.toThrow()
    window.removeEventListener(SESSION_GONE, gone)
    expect(gone).not.toHaveBeenCalled()
  })
})
