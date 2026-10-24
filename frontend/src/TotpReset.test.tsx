/* Человек потерял телефон: второй фактор с его учетки снимает владелец.
 *
 * Кнопка только у владельца и только у учетки со включенным вторым фактором,
 * а снятие идет через окно подтверждения: без второго фактора учетка держится
 * на одном пароле.
 */

import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { AuthProvider, toAuth } from './auth'
import { DialogProvider } from './Dialogs'
import { UsersPage } from './UsersPage'

async function settle(n = 6) {
  for (let i = 0; i < n; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0))
    })
  }
}

const owner = toAuth({ username: 'o', role: 'owner', level: 40, role_title: '', totp_enabled: false })
const maintainer = toAuth({
  username: 'm',
  role: 'maintainer',
  level: 30,
  role_title: '',
  totp_enabled: false,
})

function person(id: number, username: string, role: api.Role, totp = false): api.PanelUser {
  return {
    id,
    username,
    role,
    role_title: '',
    disabled: false,
    totp_enabled: totp,
    allow_ips: '',
    created_at: '2026-01-01T00:00:00Z',
  }
}

function mountUsers(auth: ReturnType<typeof toAuth>) {
  render(
    <AuthProvider value={auth}>
      <DialogProvider>
        <UsersPage />
      </DialogProvider>
    </AuthProvider>,
  )
}

function openMenu() {
  fireEvent.click(screen.getAllByLabelText('Меню')[0])
}

afterEach(() => {
  vi.restoreAllMocks()
  document.body.innerHTML = ''
})

describe('второй фактор чужой учетки', () => {
  it('владелец снимает его через окно подтверждения', async () => {
    vi.spyOn(api, 'listUsers').mockResolvedValue([person(3, 'dev', 'developer', true)])
    const reset = vi.spyOn(api, 'resetUserTotp').mockResolvedValue(person(3, 'dev', 'developer'))
    mountUsers(owner)
    await settle()
    openMenu()
    fireEvent.click(screen.getByText('Снять второй фактор'))
    await settle()
    expect(screen.getByRole('alertdialog').textContent).toContain('dev')
    fireEvent.click(screen.getAllByText('Снять второй фактор').at(-1)!)
    await settle()
    expect(reset).toHaveBeenCalledWith(3)
  })

  it('ответственному кнопки нет: это только для владельца', async () => {
    vi.spyOn(api, 'listUsers').mockResolvedValue([person(3, 'dev', 'developer', true)])
    mountUsers(maintainer)
    await settle()
    openMenu()
    expect(screen.queryByText('Снять второй фактор')).toBeNull()
  })
})
