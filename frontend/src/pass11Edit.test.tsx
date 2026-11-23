/* Одиннадцатый проход: правка не ложится молча поверх чужой, окно без
 * загруженного значения не сохраняет пустое, набранное не теряется от
 * Escape и перехода, значения и буфер не держат секрет вечно. */

import { act, fireEvent, render, screen, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { AuthProvider, toAuth } from './auth'
import { copyToClipboard, forgetLater } from './clipboard'
import { DialogProvider } from './Dialogs'
import * as e2e from './e2e'
import { I18nProvider } from './i18n'
import { ProjectSettingsModal } from './ProjectSettingsModal'
import { holdLeave, leaveGuard, setLeaveGuard } from './leave'
import { BulkEditModal, HIDE_AFTER_MS, SecretEditor } from './SecretModals'

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

function clash(current: number) {
  return new api.ApiError('Ключ изменили, пока вы его правили: ваша правка не записана', 409, {
    detail: 'Ключ изменили, пока вы его правили: ваша правка не записана',
    conflict: 'version',
    current_version: current,
  })
}

beforeEach(() => {
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} }
  window.matchMedia ??= ((q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia
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

describe('ответ о конфликте версий', () => {
  it('конфликт версий читается из тела ответа', async () => {
    vi.stubGlobal('fetch', async () =>
      new Response(JSON.stringify({ detail: 'x', conflict: 'version', current_version: 7 }), { status: 409 }),
    )
    const err = await api.putSecret(1, { name: 'A', path: '/', value: 'v', expected_version: 6 }).catch((e) => e)
    expect(api.versionConflict(err)).toEqual({ current: 7 })
    expect(api.versionConflict(new api.ApiError('x', 409))).toBeNull()
  })
})

describe('уход с набранным', () => {
  it('окно поверх строки с черновиком спрашивает один раз, доли сейфа отдельно', async () => {
    const asked: string[] = []
    const guard = (name: string) => async () => {
      asked.push(name)
      return true
    }
    const offRow = holdLeave(guard('row'))
    const offModal = holdLeave(guard('modal'))
    setLeaveGuard(guard('vault'))
    expect(await leaveGuard()!()).toBe(true)
    expect(asked).toEqual(['modal', 'vault'])
    offModal()
    offRow()
    setLeaveGuard(null)
    expect(leaveGuard()).toBeNull()
  })
})

describe('окно правки значения', () => {
  it('загрузка не удалась: пустое не сохранить, пока ничего не ввели', async () => {
    const save = vi.fn().mockResolvedValue(undefined)
    wrap(
      <SecretEditor
        secret={row('DB', 3)}
        read={() => Promise.reject(new Error('сеть'))}
        onClose={() => {}}
        onSaved={() => {}}
        save={save}
      />,
    )
    await settle()
    expect(screen.getByText(/Текущее значение не загрузилось/)).toBeTruthy()
    const button = screen.getByRole('button', { name: 'Сохранить' }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    fireEvent.change(screen.getByRole('textbox', { name: 'Значение' }), { target: { value: 'new' } })
    expect(button.disabled).toBe(false)
  })

  it('только запись: прямо сказано, что значение не видно и заменится', async () => {
    const save = vi.fn().mockResolvedValue(undefined)
    wrap(<SecretEditor secret={row('DB', 3)} onClose={() => {}} onSaved={() => {}} save={save} />)
    await settle(2)
    expect(screen.getByText(/Текущее значение не показывается: читать его вам нельзя/)).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Сохранить' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(screen.getByRole('textbox', { name: 'Значение' }), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await settle(2)
    // Сверяется версия из списка: прочитать свежую нельзя.
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ value: 'x', expected_version: 3 }))
  })

  it('ключ успели изменить: разница и осознанная перезапись', async () => {
    const read = vi
      .fn()
      .mockResolvedValueOnce({ value: 'old', version: 3 })
      .mockResolvedValueOnce({ value: 'theirs', version: 4 })
    const save = vi.fn().mockRejectedValueOnce(clash(4)).mockResolvedValueOnce(undefined)
    const saved = vi.fn()
    wrap(<SecretEditor secret={row('DB', 3)} read={read} onClose={() => {}} onSaved={saved} save={save} />)
    await settle()
    fireEvent.change(screen.getByRole('textbox', { name: 'Значение' }), { target: { value: 'mine' } })
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await settle()
    expect(save.mock.calls[0][0].expected_version).toBe(3)
    expect(saved).not.toHaveBeenCalled()
    expect(screen.getByText('Ключ изменили, пока вы его правили: ваша правка не записана')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Показать разницу' }))
    expect(screen.getByText('- theirs')).toBeTruthy()
    expect(screen.getByText('+ mine')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Перезаписать' }))
    await settle()
    expect(save.mock.calls[1][0]).toEqual(expect.objectContaining({ value: 'mine', expected_version: 4 }))
    expect(saved).toHaveBeenCalled()
  })

  it('унаследованный ключ правится от версии 0', async () => {
    const save = vi.fn().mockResolvedValue(undefined)
    wrap(
      <SecretEditor
        secret={row('DB', 9, { inherited_from: 'prod' } as Partial<api.SecretRow>)}
        read={async () => ({ value: 'parent', version: 9 })}
        onClose={() => {}}
        onSaved={() => {}}
        save={save}
      />,
    )
    await settle()
    fireEvent.change(screen.getByRole('textbox', { name: 'Значение' }), { target: { value: 'own' } })
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await settle(2)
    expect(save.mock.calls[0][0].expected_version).toBe(0)
  })

  it('Escape и переход с набранным спрашивают, без правок закрывают сразу', async () => {
    const closed = vi.fn()
    wrap(
      <SecretEditor
        secret={row('DB', 1)}
        read={async () => ({ value: 'v', version: 1 })}
        onClose={closed}
        onSaved={() => {}}
        save={vi.fn()}
      />,
    )
    await settle()
    expect(leaveGuard()).toBeNull()
    fireEvent.change(screen.getByRole('textbox', { name: 'Значение' }), { target: { value: 'v2' } })
    expect(leaveGuard()).not.toBeNull()
    fireEvent.keyDown(window, { key: 'Escape' })
    await settle(2)
    expect(closed).not.toHaveBeenCalled()
    const dialog = screen.getByRole('alertdialog')
    expect(within(dialog).getByText('Закрыть без сохранения?')).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Закрыть' }))
    await settle(2)
    expect(closed).toHaveBeenCalledTimes(1)
  })

  it('настройки проекта: Escape с измененным спрашивает', async () => {
    vi.spyOn(api, 'listProjects').mockResolvedValue([])
    vi.spyOn(api, 'listEnvironments').mockResolvedValue([])
    const project = {
      id: 1, slug: 'shop', title: '', e2e: false, approval_min_level: 0, required_keys: '',
      stale_after_days: 365, group_name: '', group_slug: '', manage: true,
    } as unknown as api.Project
    const closed = vi.fn()
    wrap(
      <AuthProvider value={toAuth({ username: 'alice', role: 'owner', level: 40, role_title: '', totp_enabled: false } as api.Me)}>
        <ProjectSettingsModal project={project} onClose={closed} onSaved={() => {}} onDeleted={() => {}} />
      </AuthProvider>,
    )
    await settle(2)
    fireEvent.change(screen.getByPlaceholderText('DB_DSN APP_ENV SENTRY_DSN'), { target: { value: 'DB_URL' } })
    fireEvent.keyDown(window, { key: 'Escape' })
    await settle(2)
    expect(closed).not.toHaveBeenCalled()
    expect(within(screen.getByRole('alertdialog')).getByText('Закрыть без сохранения?')).toBeTruthy()
  })

  it('без правок Escape закрывает без вопроса', async () => {
    const closed = vi.fn()
    wrap(
      <SecretEditor
        secret={row('DB', 1)}
        read={async () => ({ value: 'v', version: 1 })}
        onClose={closed}
        onSaved={() => {}}
        save={vi.fn()}
      />,
    )
    await settle()
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(closed).toHaveBeenCalledTimes(1)
  })
})

describe('окно всех значений', () => {
  const values: api.SecretValueRow[] = [
    { name: 'A', path: '/', version: 1, value: 'a' },
    { name: 'B', path: '/', version: 2, value: 'b' },
  ]

  it.each(['Скачать файл', 'Скопировать'])('закрытое окно не выгружает отложенный ответ: %s', async (label) => {
    vi.spyOn(api, 'readAllValues').mockResolvedValue(values)
    let respond!: (result: { text: string }) => void
    const request = vi.spyOn(api, 'exportEnv').mockReturnValue(new Promise((resolve) => { respond = resolve }))
    const createObjectURL = vi.fn().mockReturnValue('blob:fixture')
    vi.stubGlobal('URL', Object.assign(class extends URL {}, { createObjectURL, revokeObjectURL: vi.fn() }))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', Object.assign(Object.create(navigator), { clipboard: { writeText } }))
    const view = wrap(<BulkEditModal envId={3} subject="shop · prod" filename="p.env" canWrite={false} onClose={() => view.unmount()} onChanged={() => {}} />)
    expect(await screen.findByDisplayValue('a')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: label }))
    expect(request).toHaveBeenCalledWith(3)
    fireEvent.click(screen.getByRole('button', { name: 'Закрыть' }))

    await act(async () => { respond({ text: 'A=secret-fixture' }) })
    expect(createObjectURL).not.toHaveBeenCalled()
    expect(click).not.toHaveBeenCalled()
    expect(writeText).not.toHaveBeenCalled()
  })

  it('чужая правка в одном ключе не мешает остальным, перезапись осознанная', async () => {
    vi.spyOn(api, 'readAllValues').mockResolvedValue(values)
    const put = vi.spyOn(api, 'putSecret').mockImplementation(async (_env, body) => {
      if (body.name === 'A' && body.expected_version === 1) throw clash(5)
      return { ...row(body.name, 9), pending: false }
    })
    vi.spyOn(api, 'readSecret').mockResolvedValue({ ...row('A', 5), value: 'a-theirs' } as api.SecretValue)
    wrap(<BulkEditModal envId={3} subject="shop · prod" filename="p.env" canWrite onClose={() => {}} onChanged={() => {}} />)
    await settle()
    const fields = screen.getAllByRole('textbox') as HTMLInputElement[]
    fireEvent.change(fields[0], { target: { value: 'a-mine' } })
    fireEvent.change(fields[1], { target: { value: 'b-mine' } })
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить (2)' }))
    await settle()
    expect(put).toHaveBeenCalledWith(3, expect.objectContaining({ name: 'A', expected_version: 1 }))
    expect(put).toHaveBeenCalledWith(3, expect.objectContaining({ name: 'B', expected_version: 2, value: 'b-mine' }))
    expect(screen.getByText(/Эти ключи изменили, пока вы правили/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Показать разницу' }))
    expect(screen.getByText('- a-theirs')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Перезаписать своими' }))
    await settle()
    expect(put).toHaveBeenLastCalledWith(3, expect.objectContaining({ name: 'A', value: 'a-mine', expected_version: 5 }))
    expect(screen.queryByText(/Эти ключи изменили, пока вы правили/)).toBeNull()
  })

  it('значения скрываются по таймеру, начатая правка держит окно', async () => {
    vi.useFakeTimers()
    vi.spyOn(api, 'readAllValues').mockResolvedValue(values)
    wrap(<BulkEditModal envId={3} subject="" filename="p.env" canWrite onClose={() => {}} onChanged={() => {}} />)
    const tick = async (ms: number) => {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(ms)
      })
    }
    await tick(50)
    expect(screen.getAllByRole('textbox')).toHaveLength(2)
    fireEvent.change(screen.getAllByRole('textbox')[0], { target: { value: 'typing' } })
    await tick(HIDE_AFTER_MS + 1000)
    expect(screen.getAllByRole('textbox')).toHaveLength(2)
    fireEvent.change(screen.getAllByRole('textbox')[0], { target: { value: 'a' } })
    await tick(HIDE_AFTER_MS + 1000)
    expect(screen.queryAllByRole('textbox')).toHaveLength(0)
    expect(screen.getByText(/Значения скрыты/)).toBeTruthy()
  })
})

describe('выдача ключа проекта машине', () => {
  it('привязывает обертку к ключу машины, под который она сделана', async () => {
    vi.spyOn(api, 'listProjects').mockResolvedValue([])
    vi.spyOn(api, 'listEnvironments').mockResolvedValue([])
    const machine = { machine_id: 7, name: 'fixture', has_key: true, has_wrap: false }
    vi.spyOn(api, 'listE2eMachines').mockResolvedValue([machine])
    vi.spyOn(api, 'machinePublicKey').mockResolvedValue({ public_key: 'node-public-key' })
    const issue = vi.spyOn(api, 'wrapE2eForMachine').mockResolvedValue({ ...machine, has_wrap: true })
    const sealed = { ephemeral_public: 'fixture-public', nonce: 'fixture-nonce', wrapped_key: 'fixture-wrap' }
    const wrapKey = vi.spyOn(e2e, 'wrapForMachine').mockResolvedValue(sealed)
    const key = new Uint8Array([1, 2, 3])
    e2e.rememberKey(1, key)
    const project = {
      id: 1, slug: 'shop', title: '', e2e: true, approval_min_level: 0, required_keys: '',
      stale_after_days: 365, group_name: '', group_slug: '', manage: true,
    } as api.Project
    const auth = toAuth({ username: 'alice', role: 'owner', level: 40, role_title: '', totp_enabled: false })
    wrap(
      <AuthProvider value={auth}>
        <ProjectSettingsModal project={project} onClose={() => {}} onSaved={() => {}} onDeleted={() => {}} />
      </AuthProvider>,
    )
    const grant = await screen.findByRole('button', { name: 'Выдать ключ' })
    await act(async () => { fireEvent.click(grant) })
    await settle()
    expect(wrapKey).toHaveBeenCalledWith(key, 'node-public-key')
    expect(issue).toHaveBeenCalledWith(1, { machine_id: 7, expected_public_key: 'node-public-key', ...sealed })
  })
})

describe('настройки проекта и отложенные ответы', () => {
  function open(e2eEnabled: boolean) {
    vi.spyOn(api, 'listProjects').mockResolvedValue([])
    vi.spyOn(api, 'listEnvironments').mockResolvedValue([])
    const project = {
      id: 1, slug: 'shop', title: '', e2e: e2eEnabled, approval_min_level: 0, required_keys: '',
      stale_after_days: 365, group_name: '', group_slug: '', manage: true,
    } as api.Project
    const auth = toAuth({ username: 'alice', role: 'owner', level: 40, role_title: '', totp_enabled: false })
    const view = wrap(
      <AuthProvider value={auth}>
        <ProjectSettingsModal project={project} onClose={() => view.unmount()} onSaved={() => {}} onDeleted={() => {}} />
      </AuthProvider>,
    )
    return view
  }

  it('закрытое окно не скачивает отложенную выгрузку проекта', async () => {
    let respond!: (result: { text: string; skipped: string[] }) => void
    const request = vi.spyOn(api, 'exportProject').mockReturnValue(new Promise((resolve) => { respond = resolve }))
    const createObjectURL = vi.fn().mockReturnValue('blob:fixture')
    vi.stubGlobal('URL', Object.assign(class extends URL {}, { createObjectURL, revokeObjectURL: vi.fn() }))
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    await act(async () => { open(false) })
    fireEvent.click(screen.getByRole('button', { name: 'Скачать проект' }))
    expect(request).toHaveBeenCalledWith(1)
    fireEvent.click(screen.getByRole('button', { name: 'Отмена' }))

    await act(async () => { respond({ text: 'A=secret-fixture', skipped: [] }) })
    expect(createObjectURL).not.toHaveBeenCalled()
  })

  it.each(['открыт', 'заперт', 'закрыто окно'])(
    'отложенная выдача ключа машины: %s',
    async (status) => {
      const machine = { machine_id: 7, name: 'fixture', has_key: true, has_wrap: false }
      vi.spyOn(api, 'listE2eMachines').mockResolvedValue([machine])
      vi.spyOn(api, 'machinePublicKey').mockResolvedValue({ public_key: 'node-public-key' })
      const issue = vi.spyOn(api, 'wrapE2eForMachine').mockResolvedValue({ ...machine, has_wrap: true })
      type Sealed = Awaited<ReturnType<typeof e2e.wrapForMachine>>
      let finish!: (sealed: Sealed) => void
      const wrapKey = vi.spyOn(e2e, 'wrapForMachine').mockReturnValue(new Promise((resolve) => { finish = resolve }))
      const key = new Uint8Array([1, 2, 3])
      e2e.rememberKey(1, key)
      open(true)
      const grant = await screen.findByRole('button', { name: 'Выдать ключ' })
      await act(async () => { fireEvent.click(grant) })
      expect(wrapKey).toHaveBeenCalledWith(key, 'node-public-key')
      if (status === 'заперт') e2e.forgetKey(1)
      if (status === 'закрыто окно') fireEvent.click(screen.getByRole('button', { name: 'Отмена' }))

      const sealed = { ephemeral_public: 'fixture-public', nonce: 'fixture-nonce', wrapped_key: 'fixture-wrap' }
      await act(async () => { finish(sealed) })
      if (status === 'открыт') {
        expect(issue).toHaveBeenCalledWith(1, { machine_id: 7, expected_public_key: 'node-public-key', ...sealed })
      } else {
        expect(issue).not.toHaveBeenCalled()
      }
    },
  )
})

describe('буфер обмена чистится', () => {
  let writeText: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.useFakeTimers()
    writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', Object.assign(Object.create(navigator), {
      clipboard: { writeText, readText: vi.fn().mockResolvedValue('other') },
    }))
    vi.spyOn(document, 'hasFocus').mockReturnValue(true)
  })

  it('через время, если вкладку не покидали', async () => {
    forgetLater('s3cret', 1000)
    await vi.advanceTimersByTimeAsync(1100)
    expect(writeText).toHaveBeenCalledWith('')
  })

  it('вкладку покидали - буфер уже не наш, не трогаем', async () => {
    forgetLater('s3cret', 1000)
    window.dispatchEvent(new Event('blur'))
    await vi.advanceTimersByTimeAsync(1100)
    expect(writeText).not.toHaveBeenCalled()
  })

  it('в вкладке скопировали другое - не трогаем', async () => {
    forgetLater('s3cret', 1000)
    document.dispatchEvent(new Event('copy'))
    await vi.advanceTimersByTimeAsync(1100)
    expect(writeText).not.toHaveBeenCalled()
  })

  it('ожидание разрешения старого таймера не стирает более новую копию', async () => {
    let finish!: (permission: { state: string }) => void
    const query = vi.fn().mockReturnValue(new Promise((resolve) => { finish = resolve }))
    Object.defineProperty(navigator, 'permissions', { configurable: true, value: { query } })
    forgetLater('previous', 1000)
    await vi.advanceTimersByTimeAsync(1100)
    expect(query).toHaveBeenCalledOnce()
    forgetLater('current', 1000)
    finish({ state: 'denied' })
    await vi.advanceTimersByTimeAsync(0)
    expect(writeText).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1100)
    expect(writeText.mock.calls).toEqual([['']])
  })

  it('после закрытия окна отказ clipboard API не запускает запасное копирование', async () => {
    let deny!: (error: Error) => void
    writeText.mockReturnValueOnce(new Promise((_, reject) => { deny = reject }))
    const select = vi.spyOn(HTMLTextAreaElement.prototype, 'select')
    let current = true
    const copying = copyToClipboard('secret-fixture', () => current)
    current = false
    deny(new Error('clipboard denied'))

    expect(await copying).toBe(false)
    expect(select).not.toHaveBeenCalled()
  })
})
