import { act, fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { ProjectPage } from './ProjectPage'

const later = <T,>(value: T, ms: number) =>
  new Promise<T>((resolve) => setTimeout(() => resolve(value), ms))

function project(id: number, slug: string): api.Project {
  return {
    id, slug, title: '', e2e: false, approval_min_level: 0, required_keys: '',
    stale_after_days: 365, group_name: '', group_slug: '', manage: true,
  } as unknown as api.Project
}
function env(id: number, projectId: number, name: string): api.Environment {
  return {
    id, project_id: projectId, name, title: '', key_generation: 1, parent_id: null,
    parent_name: '', secret_count: 1, own_count: 1,
  } as unknown as api.Environment
}
function secret(name: string): api.SecretRow {
  return { name, path: '/', version: 1, updated_by: 'a', updated_at: '', multiline: false, note: '', expires_at: '' } as unknown as api.SecretRow
}

type At = { slug: string; env?: string; query?: string }
let go: (at: At) => void = () => {}

function Harness({ start }: { start: At }) {
  const [at, setAt] = useState<At>(start)
  go = setAt
  return (
    <ProjectPage
      key={at.slug}
      group=""
      slug={at.slug}
      envName={at.env}
      initialQuery={at.query}
      // как App: смена окружения уходит без query
      onEnvChosen={(name) => setAt((was) => ({ slug: was.slug, env: name }))}
      onMoved={() => {}}
      onDeleted={() => {}}
    />
  )
}

async function settle() {
  for (let i = 0; i < 20; i++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20))
    })
  }
}
const filterBox = () => screen.getByPlaceholderText(/поиск по ключам/) as HTMLInputElement

afterEach(() => {
  vi.restoreAllMocks()
  document.body.innerHTML = ''
})

describe('поиск переживает смену окружения', () => {
  beforeEach(() => {
    ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} }
    vi.spyOn(api, 'listProjects').mockImplementation(() => later([project(1, 'shop')], 10))
    vi.spyOn(api, 'listEnvironments').mockImplementation(() => later([env(11, 1, 'prod'), env(12, 1, 'stage')], 10))
    vi.spyOn(api, 'listSecrets').mockImplementation(() => later([secret('DB_URL')], 10))
    vi.spyOn(api, 'myPermissions').mockResolvedValue({ list: true, read: true, write: true, delete: true, rotate: true, approve: true } as api.Permissions)
    vi.spyOn(api, 'listPending').mockResolvedValue([])
    vi.spyOn(api, 'missingKeys').mockResolvedValue([])
    vi.spyOn(api, 'listMutes').mockResolvedValue([])
    vi.spyOn(api, 'lintEnv').mockResolvedValue([])
    vi.spyOn(api, 'listMachines').mockResolvedValue([])
  })

  it('набранный руками поиск переживает смену (контроль)', async () => {
    render(<Harness start={{ slug: 'shop', env: 'stage' }} />)
    await settle()
    fireEvent.change(filterBox(), { target: { value: 'DB_' } })
    act(() => go({ slug: 'shop', env: 'prod' }))
    await settle()
    expect(filterBox().value).toBe('DB_')
  })

  it('пришел по ссылке с ?q=, сменил окружение - поиск остался', async () => {
    render(<Harness start={{ slug: 'shop', env: 'stage', query: 'DB_' }} />)
    await settle()
    expect(filterBox().value).toBe('DB_')
    act(() => go({ slug: 'shop', env: 'prod' }))
    await settle()
    expect(filterBox().value).toBe('DB_')
  })
})
