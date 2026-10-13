/* Страница сервера: что ему выдано и что он забирает.
 *
 * Три ошибки, которые здесь были: одноименные серверы (переподключенный с тем
 * же hostname) открывали первый из них, право на web/prod цеплялось к
 * приложению admin-web/prod, а ответственному, которому список прав не отдают,
 * все приложения помечались "права нет".
 */

import { act, render } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { AuthProvider, toAuth } from './auth'
import { ServerPage } from './ServerPage'

const now = new Date().toISOString()

function machine(id: number, name: string, apps: string[], environments = apps): api.Machine {
  return {
    id,
    name,
    client_id: `cid${id}`,
    cluster: '',
    k8s_namespace: '',
    k8s_service_account: '',
    description: '',
    allow_ips: '',
    expires_at: '',
    disabled: false,
    agent_version: '1.0.0',
    applied: '',
    last_seen_at: now,
    last_ip: `10.0.0.${id}`,
    country: '',
    os: '',
    local_ip: '',
    created_by: 'a',
    environments,
    apps: apps.map((environment) => ({
      environment,
      path: `/run/sekvyr/${environment.replace(/\//g, '-')}.env`,
      applied: 'keys 3',
      last_seen_at: now,
    })),
  } as api.Machine
}

function policy(id: number, machineId: number, projectId: number, slug: string, env: string): api.PolicyRow {
  return {
    id,
    subject_type: 'machine',
    subject_id: machineId,
    subject_name: '',
    project_id: projectId,
    project_slug: slug,
    environment_id: env ? id * 10 : null,
    environment_name: env,
    path_prefix: '/',
    actions: ['list', 'read'],
    effect: 'allow',
    expires_at: '',
    require_2fa: false,
    created_by: 'a',
    expired: false,
  }
}

const PROJECTS = [
  { id: 1, slug: 'admin-web', group_slug: '', group_name: '' },
  { id: 2, slug: 'web', group_slug: '', group_name: '' },
  { id: 3, slug: 'web', group_slug: 'globex', group_name: 'Globex' },
] as api.Project[]

const owner = toAuth({ username: 'o', role: 'owner', level: 40, role_title: '', totp_enabled: false })
const maintainer = toAuth({
  username: 'm',
  role: 'maintainer',
  level: 30,
  role_title: '',
  totp_enabled: false,
})

async function show(auth: ReturnType<typeof toAuth>, props: { name: string; id?: number }) {
  render(
    <AuthProvider value={auth}>
      <ServerPage {...props} onBack={() => {}} onGo={() => {}} />
    </AuthProvider>,
  )
  for (let i = 0; i < 5; i++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
  }
}

function cards(): string[] {
  return Array.from(document.querySelectorAll('.conn')).map((n) => n.textContent ?? '')
}

afterEach(() => {
  vi.restoreAllMocks()
  document.body.innerHTML = ''
})

function stub(machines: api.Machine[], policies: api.PolicyRow[] | 'denied') {
  vi.spyOn(api, 'agentLatest').mockResolvedValue('1.0.0')
  vi.spyOn(api, 'listProjects').mockResolvedValue(PROJECTS)
  vi.spyOn(api, 'listMachines').mockResolvedValue(machines)
  vi.spyOn(api, 'listPolicies').mockImplementation(async () => {
    if (policies === 'denied') throw new api.ApiError('Требуются права владельца панели', 403)
    return policies
  })
}

describe('ServerPage', () => {
  it('одноименные серверы различаются по номеру', async () => {
    stub([machine(6, 'dup', []), machine(7, 'dup', [])], [])
    await show(owner, { name: 'dup', id: 7 })
    expect(document.body.textContent).toContain('10.0.0.7')
    expect(document.body.textContent).not.toContain('10.0.0.6')
  })

  it('право сверяется с приложением по полному имени', async () => {
    stub(
      [machine(5, 'node', ['admin-web/prod', 'web/prod', 'globex/web/prod'])],
      [policy(100, 5, 2, 'web', 'prod'), policy(101, 5, 1, 'admin-web', 'prod')],
    )
    await show(owner, { name: 'node', id: 5 })
    const rows = cards()
    const web = rows.find((r) => r.startsWith('web/prod'))
    expect(web).toContain('/run/sekvyr/web-prod.env')
    const admin = rows.find((r) => r.startsWith('admin-web/prod'))
    expect(admin).toContain('/run/sekvyr/admin-web-prod.env')
    // Одноименный проект другой группы права не получал: у него честное
    // "права нет", а у двух выданных - нет.
    const orphans = rows.filter((r) => r.includes('права нет'))
    expect(orphans).toHaveLength(1)
    expect(orphans[0]).toContain('globex/web/prod')
  })

  it('право на весь проект не делает приложение сиротой', async () => {
    stub([machine(5, 'node', ['web/prod', 'web/stage'])], [policy(100, 5, 2, 'web', '')])
    await show(owner, { name: 'node', id: 5 })
    expect(document.body.textContent).not.toContain('права нет')
    expect(document.body.textContent).toContain('по праву на весь проект')
  })

  it('ответственный без списка прав видит выданное, а не "права нет"', async () => {
    stub([machine(5, 'node', ['web/prod'], ['web/prod', 'web/stage'])], 'denied')
    await show(maintainer, { name: 'node', id: 5 })
    const rows = cards()
    expect(rows).toHaveLength(2)
    expect(document.body.textContent).not.toContain('права нет')
    expect(document.body.textContent).not.toContain('Ничего не подключено')
    expect(rows.find((r) => r.startsWith('web/stage'))).toContain('не используется')
  })
})
