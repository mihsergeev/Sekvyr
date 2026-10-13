import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { MigratePage } from './MigratePage'

async function settle(n = 5) {
  for (let i = 0; i < n; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 10))
    })
  }
}

afterEach(() => {
  vi.restoreAllMocks()
  document.body.innerHTML = ''
})

describe('MigratePage', () => {
  it('правка окружения во время запроса предпросмотра отбрасывает ответ', async () => {
    vi.spyOn(api, 'listAllEnvironments').mockResolvedValue([
      { id: 1, name: 'stage', project_slug: 'shop', group_slug: '' } as unknown as api.EnvBrief,
      { id: 2, name: 'prod', project_slug: 'shop', group_slug: '' } as unknown as api.EnvBrief,
    ])
    let answer: (v: api.MigratePreview) => void = () => {}
    vi.spyOn(api, 'previewMigration').mockImplementation(
      () => new Promise((r) => (answer = r)),
    )
    const apply = vi
      .spyOn(api, 'applyMigration')
      .mockResolvedValue({ created: 0, updated: 1, skipped: [] } as unknown as Awaited<ReturnType<typeof api.applyMigration>>)

    render(<MigratePage />)
    await settle()
    fireEvent.change(screen.getByPlaceholderText('https://app.infisical.com'), {
      target: { value: 'https://x' },
    })
    fireEvent.click(screen.getByText('Посмотреть, что будет'))
    // пока запрос идет, человек меняет окружение назначения на prod
    const select = screen.getAllByRole('combobox').find((s) => (s as HTMLSelectElement).options[0]?.text === 'shop/stage') as HTMLSelectElement
    fireEvent.change(select, { target: { value: '2' } })
    await act(async () => {
      answer({ rows: [], total: 1, create: 0, update: 1, same: 0, note: '' } as unknown as api.MigratePreview)
    })
    await settle()
    const preview = screen.queryByText('Шаг 3. Что изменится')
    if (preview) {
      fireEvent.click(screen.getByText('Перенести'))
      await settle()
    }
    expect(preview).toBeNull()
    expect(apply).not.toHaveBeenCalled()
  })
})
