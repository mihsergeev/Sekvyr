/* Переход между проектами и окружениями.
 *
 * Палитра, "назад" и ссылки меняют адрес у уже открытой страницы проекта. Пока
 * новый проект грузился, окружение выбиралось по списку старого: из
 * shop/stage в billing/dev?q=REDIS_URL человек попадал на billing/prod без
 * поиска и правил прод, думая, что это dev.
 */

import { act, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { ProjectPage } from './ProjectPage'

const later = <T,>(value: T, ms: number) =>
  new Promise<T>((resolve) => setTimeout(() => resolve(value), ms))

function project(id: number, slug: string): api.Project {
  return {
    id,
    slug,
    title: '',
    e2e: false,
    approval_min_level: 0,
    required_keys: '',
    stale_after_days: 365,
    group_name: '',
    group_slug: '',
  } as unknown as api.Project
}

function env(id: number, projectId: number, name: string): api.Environment {
  return {
    id,
    project_id: projectId,
    name,
    title: '',
    key_generation: 1,
    parent_id: null,
    parent_name: '',
    secret_count: 1,
    own_count: 1,
  } as unknown as api.Environment
}

function secret(name: string): api.SecretRow {
  return {
    name,
    path: '/',
    version: 1,
    updated_by: 'a',
    updated_at: '',
    multiline: false,
    note: '',
    expires_at: '',
  } as unknown as api.SecretRow
}

const ENVS: Record<number, api.Environment[]> = {
  1: [env(11, 1, 'prod'), env(12, 1, 'stage')],
  2: [env(21, 2, 'prod'), env(22, 2, 'dev')],
}
const SECRETS: Record<number, api.SecretRow[]> = {
  11: [secret('SHOP_PROD_KEY')],
  12: [secret('SHOP_STAGE_KEY')],
  21: [secret('BILLING_PROD_KEY'), secret('REDIS_URL')],
  22: [secret('BILLING_DEV_KEY'), secret('REDIS_URL')],
}

type At = { slug: string; env?: string; query?: string }
let go: (at: At) => void = () => {}

function Harness({ start }: { start: At }) {
  const [at, setAt] = useState<At>(start)
  go = setAt
  return (
    <>
      <output data-testid="at">{`${at.slug}/${at.env ?? ''}?q=${at.query ?? ''}`}</output>
      {/* Без key, хотя App и держит свой экземпляр на проект: страница сама не
          должна выбирать окружение по списку прежнего проекта. */}
      <ProjectPage
        group=""
        slug={at.slug}
        envName={at.env}
        initialQuery={at.query}
        onEnvChosen={(name) => setAt((was) => ({ slug: was.slug, env: name }))}
        onMoved={() => {}}
        onDeleted={() => {}}
      />
    </>
  )
}

async function settle() {
  for (let i = 0; i < 20; i++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20))
    })
  }
}

function filterBox(): HTMLInputElement {
  return screen.getByPlaceholderText(/поиск по ключам/) as HTMLInputElement
}

afterEach(() => {
  vi.restoreAllMocks()
  document.body.innerHTML = ''
})

describe('ProjectPage', () => {
  beforeEach(() => {
    ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver ??= class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
    vi.spyOn(api, 'listProjects').mockImplementation(() =>
      later([project(1, 'shop'), project(2, 'billing')], 30),
    )
    vi.spyOn(api, 'listEnvironments').mockImplementation((id: number) => later(ENVS[id], 30))
    vi.spyOn(api, 'listSecrets').mockImplementation((id: number) => later(SECRETS[id] ?? [], 10))
    vi.spyOn(api, 'myPermissions').mockResolvedValue({
      list: true,
      read: true,
      write: true,
      delete: true,
      rotate: true,
      approve: true,
    } as unknown as api.Permissions)
    vi.spyOn(api, 'listPending').mockResolvedValue([])
    vi.spyOn(api, 'missingKeys').mockResolvedValue([])
    vi.spyOn(api, 'listMutes').mockResolvedValue([])
    vi.spyOn(api, 'lintEnv').mockResolvedValue([])
    vi.spyOn(api, 'listMachines').mockResolvedValue([])
  })

  it('переход в другой проект открывает запрошенное окружение с поиском', async () => {
    render(<Harness start={{ slug: 'shop', env: 'stage' }} />)
    await settle()
    expect(screen.getByText('SHOP_STAGE_KEY')).toBeTruthy()

    act(() => go({ slug: 'billing', env: 'dev', query: 'REDIS_URL' }))
    await settle()
    expect(screen.getByTestId('at').textContent).toBe('billing/dev?q=REDIS_URL')
    expect(filterBox().value).toBe('REDIS_URL')
  })

  it('поиск из адреса доходит до уже открытого окружения', async () => {
    render(<Harness start={{ slug: 'shop', env: 'stage' }} />)
    await settle()
    act(() => go({ slug: 'shop', env: 'stage', query: 'SHOP' }))
    await settle()
    expect(filterBox().value).toBe('SHOP')
  })
})
