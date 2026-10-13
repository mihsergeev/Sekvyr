/* История ключа: права в папке ключа и версии из закрытой папки.
 *
 * Права на корень у того, кому выдана одна папка, нет, а читать и откатывать
 * ключ в своей папке он может. Версия, записанная, пока ключ лежал в закрытой
 * папке, не раскрывается и не откатывается: сервер помечает ее closed.
 */

import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { DialogProvider } from './Dialogs'
import { HistoryModal } from './SecretModals'

async function settle(n = 6) {
  for (let i = 0; i < n; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 10))
    })
  }
}

const NONE = { list: false, read: false, write: false, delete: false, rotate: false, approve: false } as api.Permissions
const ALL = { list: true, read: true, write: true, delete: true, rotate: true, approve: true } as api.Permissions

const row = (path: string) =>
  ({ name: 'DB_URL', path, version: 3, updated_by: 'a', updated_at: '', multiline: false, note: '', expires_at: '' }) as unknown as api.SecretRow

const ver = (version: number, path: string, current = false, extra: Partial<api.SecretVersion> = {}) =>
  ({
    version,
    name: 'DB_URL',
    path,
    deleted: false,
    author: 'a',
    comment: '',
    created_at: `2026-01-0${version}T00:00:00Z`,
    current,
    ...extra,
  }) as api.SecretVersion

const rollbackButtons = () =>
  Array.from(document.querySelectorAll('.hist-row button')).filter((b) => b.textContent === 'Вернуть')
const rows = () => Array.from(document.querySelectorAll('.hist-main')) as HTMLElement[]

function mount(path: string) {
  render(
    <DialogProvider>
      <HistoryModal envId={11} secret={row(path)} onClose={() => {}} onChanged={() => {}} />
    </DialogProvider>,
  )
}

afterEach(() => {
  vi.restoreAllMocks()
  document.body.innerHTML = ''
})

describe('история ключа и права', () => {
  it('право только на папку ключа дает раскрыть и вернуть', async () => {
    vi.spyOn(api, 'myPermissions').mockImplementation(async (_e: number, path = '/') => (path === '/db' ? ALL : NONE))
    vi.spyOn(api, 'secretHistory').mockResolvedValue([ver(2, '/db', true), ver(1, '/db')])
    vi.spyOn(api, 'readSecretVersion').mockImplementation(async (_e, _n, _p, v) => ({ value: 'v' + v }) as api.SecretValue)
    mount('/db')
    await settle()
    expect(rollbackButtons().length).toBe(1)
    fireEvent.click(rows()[1])
    await settle()
    expect(screen.queryByText('Значения читать нельзя, видно только события.')).toBeNull()
  })

  it('версия из закрытой папки не раскрывается и не возвращается', async () => {
    vi.spyOn(api, 'myPermissions').mockResolvedValue(ALL)
    vi.spyOn(api, 'secretHistory').mockResolvedValue([
      ver(3, '/', true),
      ver(2, '/', false, { comment: 'переименован из закрытой папки' }),
      ver(1, '/', false, { closed: true }),
    ])
    const read = vi
      .spyOn(api, 'readSecretVersion')
      .mockImplementation(async (_e, _n, _p, v) => ({ value: 'value-' + v }) as api.SecretValue)
    mount('/')
    await settle()
    // Вернуть можно только v2: v3 текущая, v1 закрыта.
    expect(rollbackButtons().length).toBe(1)

    // v2 раскрывается: сравнивается с пустым, закрытую v1 не запрашиваем.
    fireEvent.click(rows()[1])
    await settle()
    expect(screen.queryByText('Загружаем…')).toBeNull()
    expect(read.mock.calls.map((c) => c[3])).toEqual([2])

    // v1 - честная надпись, без запроса и без ошибки.
    fireEvent.click(rows()[2])
    await settle()
    expect(screen.getByText('Значение этой версии лежало в папке, где у вас нет права читать.')).toBeTruthy()
    expect(read.mock.calls.map((c) => c[3])).toEqual([2])
    expect(document.querySelector('.form-error')).toBeNull()
  })

  it('до ответа о правах и при его ошибке кнопок нет', async () => {
    let release: (p: api.Permissions) => void = () => {}
    vi.spyOn(api, 'myPermissions').mockImplementation(() => new Promise((r) => (release = r)))
    vi.spyOn(api, 'secretHistory').mockResolvedValue([ver(2, '/secret', true), ver(1, '/secret')])
    mount('/secret')
    await settle()
    expect(rollbackButtons().length).toBe(0)
    await act(async () => release({ ...ALL, write: false }))
    await settle()
    expect(rollbackButtons().length).toBe(0)
  })

  it('ошибка запроса прав - кнопок нет', async () => {
    vi.spyOn(api, 'myPermissions').mockRejectedValue(new Error('offline'))
    vi.spyOn(api, 'secretHistory').mockResolvedValue([ver(2, '/secret', true), ver(1, '/secret')])
    mount('/secret')
    await settle()
    expect(rollbackButtons().length).toBe(0)
  })

  it('строка, раскрытая до ответа о правах, догружается после него', async () => {
    let release: (p: api.Permissions) => void = () => {}
    vi.spyOn(api, 'myPermissions').mockImplementation(() => new Promise((r) => (release = r)))
    vi.spyOn(api, 'secretHistory').mockResolvedValue([ver(2, '/', true), ver(1, '/')])
    const read = vi
      .spyOn(api, 'readSecretVersion')
      .mockImplementation(async (_e, _n, _p, v) => ({ value: 'v' + v }) as api.SecretValue)
    mount('/')
    await settle()
    fireEvent.click(rows()[0])
    await settle()
    await act(async () => release(ALL))
    await settle(20)
    expect(read).toHaveBeenCalled()
    expect(screen.queryByText('Загружаем…')).toBeNull()
  })

  it('ошибка запроса прав видна как ошибка', async () => {
    vi.spyOn(api, 'myPermissions').mockRejectedValue(new Error('сеть недоступна'))
    vi.spyOn(api, 'secretHistory').mockResolvedValue([ver(2, '/secret', true), ver(1, '/secret')])
    mount('/secret')
    await settle()
    expect(document.querySelector('.form-error')?.textContent).toContain('сеть недоступна')
  })
})

describe('все значения при отказе', () => {
  it('только причина, без "ключей нет" и без выгрузки', async () => {
    const { BulkEditModal } = await import('./SecretModals')
    vi.spyOn(api, 'readAllValues').mockRejectedValue(
      new api.ApiError('В окружении есть папки, где у вас нет права', 403),
    )
    render(
      <DialogProvider>
        <BulkEditModal envId={3} subject="shop · prod" filename="prod.env" canWrite={false} onClose={() => {}} onChanged={() => {}} />
      </DialogProvider>,
    )
    await settle()
    expect(screen.queryByText('Ключей пока нет')).toBeNull()
    expect(screen.queryByText('Скачать файл')).toBeNull()
    expect(screen.queryByText('Скопировать')).toBeNull()
    expect(document.querySelector('.form-error')?.textContent).toContain('нет права')
  })
})
