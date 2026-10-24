/* Люди уходят, их серверы остаются.
 *
 * Доступ сервера держится на том, кто его завел и выдал права: отключили
 * человека - сервер встает. Страница учеток предупреждает об этом до того, как
 * нажали "отключить", страница сервера говорит, что он встал, и дает забрать
 * его на себя.
 */

import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { AuthProvider, toAuth } from './auth'
import { DialogProvider } from './Dialogs'
import { ServerPage } from './ServerPage'
import { UsersPage } from './UsersPage'

async function settle(n = 6) {
  for (let i = 0; i < n; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0))
    })
  }
}

const owner = toAuth({ username: 'o', role: 'owner', level: 40, role_title: '', totp_enabled: false })

function person(id: number, username: string, role: api.Role): api.PanelUser {
  return {
    id,
    username,
    role,
    role_title: '',
    disabled: false,
    totp_enabled: false,
    allow_ips: '',
    created_at: '2026-01-01T00:00:00Z',
  }
}

function server(extra: Partial<api.Machine> = {}): api.Machine {
  return {
    id: 5,
    name: 'web-1',
    client_id: 'cid5',
    cluster: '',
    k8s_namespace: '',
    k8s_service_account: '',
    description: '',
    allow_ips: '',
    expires_at: '',
    disabled: false,
    agent_version: '1.0.0',
    applied: '',
    last_seen_at: '',
    last_ip: '',
    country: '',
    os: '',
    local_ip: '',
    created_by: 'lead',
    environments: [],
    apps: [],
    stalled: false,
    ...extra,
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

function mountServer(auth: ReturnType<typeof toAuth>) {
  render(
    <AuthProvider value={auth}>
      <DialogProvider>
        <ServerPage name="web-1" id={5} onBack={() => {}} onGo={() => {}} />
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

describe('отключение учетки', () => {
  it('предупреждает, сколько серверов и кластеров встанет и сколько правок снимется', async () => {
    vi.spyOn(api, 'listUsers').mockResolvedValue([person(2, 'lead', 'maintainer')])
    vi.spyOn(api, 'userDependents').mockResolvedValue({ machines: 2, clusters: 1, proposals: 3 })
    const update = vi.spyOn(api, 'updateUser').mockResolvedValue({
      ...person(2, 'lead', 'maintainer'),
      machines_stopped: 2,
      clusters_stopped: 1,
      proposals_withdrawn: 3,
    })
    mountUsers(owner)
    await settle()
    openMenu()
    fireEvent.click(screen.getByText('Отключить'))
    await settle()
    const dialog = screen.getByRole('alertdialog')
    expect(dialog.textContent).toContain('серверов 2, кластеров 1')
    expect(dialog.textContent).toContain('будут сняты: 3')
    fireEvent.click(screen.getAllByText('Отключить').at(-1)!)
    await settle()
    expect(update).toHaveBeenCalledWith(2, { disabled: true })
  })

  it('у разработчика серверов нет, но ожидающие правки снимаются', async () => {
    vi.spyOn(api, 'listUsers').mockResolvedValue([person(3, 'dev', 'developer')])
    vi.spyOn(api, 'userDependents').mockResolvedValue({ machines: 0, clusters: 0, proposals: 1 })
    mountUsers(owner)
    await settle()
    openMenu()
    fireEvent.click(screen.getByText('Отключить'))
    await settle()
    const dialog = screen.getByRole('alertdialog')
    expect(dialog.textContent).not.toContain('серверов')
    expect(dialog.textContent).toContain('будут сняты: 1')
  })
})

describe('сервер, чей доступ встал', () => {
  function stub(machine: api.Machine) {
    vi.spyOn(api, 'agentLatest').mockResolvedValue('1.0.0')
    vi.spyOn(api, 'listProjects').mockResolvedValue([])
    vi.spyOn(api, 'listMachines').mockResolvedValue([machine])
    vi.spyOn(api, 'listPolicies').mockResolvedValue([])
  }

  it('говорит, что встал, и дает забрать на себя', async () => {
    stub(server({ stalled: true }))
    const adopt = vi.spyOn(api, 'adoptMachine').mockResolvedValue(server({ created_by: 'o' }))
    mountServer(owner)
    await settle()
    expect(document.body.textContent).toContain('Часть выданного не действует')
    openMenu()
    fireEvent.click(screen.getByText('Забрать на себя'))
    await settle()
    fireEvent.click(screen.getByText('Забрать'))
    await settle()
    expect(adopt).toHaveBeenCalledWith(5)
  })

  it('под кластера забирается вместе с кластером', async () => {
    stub(server({ cluster: 'prod-k8s', k8s_namespace: 'web', k8s_service_account: 'app' }))
    vi.spyOn(api, 'listClusters').mockResolvedValue([
      { id: 9, name: 'prod-k8s', issuer: 'i', audience: 'sekvyr', disabled: false, identities: 1 },
    ] as api.Cluster[])
    const adopt = vi.spyOn(api, 'adoptCluster').mockResolvedValue({} as api.Cluster)
    mountServer(owner)
    await settle()
    expect(document.body.textContent).not.toContain('Часть выданного не действует')
    openMenu()
    fireEvent.click(screen.getByText('Забрать кластер на себя'))
    await settle()
    fireEvent.click(screen.getByText('Забрать'))
    await settle()
    expect(adopt).toHaveBeenCalledWith(9)
  })

  it('свой исправный сервер забирать незачем', async () => {
    stub(server({ created_by: 'o' }))
    mountServer(owner)
    await settle()
    openMenu()
    expect(screen.queryByText('Забрать на себя')).toBeNull()
  })
})
