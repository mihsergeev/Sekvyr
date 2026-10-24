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

function environments() {
  vi.spyOn(api, 'listAllEnvironments').mockResolvedValue([
    { id: 1, name: 'prod', project_slug: 'shop', group_slug: '' } as unknown as api.EnvBrief,
  ])
}

describe('MigratePage, одиннадцатый проход', () => {
  it('браузер не подставляет сохраненные пароли в реквизиты источника', async () => {
    environments()
    render(<MigratePage />)
    await settle()
    const id = screen.getByText('Идентификатор машинной личности').querySelector('input')
    const secret = screen.getByText('Секрет машинной личности').querySelector('input')
    expect(id?.getAttribute('autocomplete')).toBe('off')
    expect(secret?.getAttribute('autocomplete')).toBe('new-password')

    const source = screen
      .getAllByRole('combobox')
      .find((s) => (s as HTMLSelectElement).options[0]?.value === 'infisical') as HTMLSelectElement
    fireEvent.change(source, { target: { value: 'vault' } })
    const token = screen.getByText('Токен Vault').querySelector('input')
    expect(token?.getAttribute('autocomplete')).toBe('new-password')
  })

  it('пропускаемые ключи видны с причиной, запись вслепую - отдельно', async () => {
    environments()
    vi.spyOn(api, 'previewMigration').mockResolvedValue({
      total: 3,
      create: 1,
      update: 0,
      same: 0,
      write: 1,
      skip: 1,
      note: '',
      rows: [
        { path: '/', name: 'FINE', action: 'создать', reason: '', size: 4 },
        { path: '/', name: 'BAD NAME', action: 'пропустить', reason: 'недопустимое имя', size: 0 },
        { path: '/private', name: 'BLIND', action: 'записать', reason: '', size: 3 },
      ],
    })
    render(<MigratePage />)
    await settle()
    fireEvent.change(screen.getByPlaceholderText('https://app.infisical.com'), {
      target: { value: 'https://x' },
    })
    fireEvent.click(screen.getByText('Посмотреть, что будет'))
    await settle()

    expect(screen.getByText('недопустимое имя')).toBeTruthy()
    expect(screen.getByText('пропустить')).toBeTruthy()
    const blind = screen.getByText('записать')
    expect(blind.getAttribute('title')).toContain('не видно')
    const summary = screen.getByText(/создать 1/)
    expect(summary.textContent).toContain('записать 1')
    expect(summary.textContent).toContain('пропустить 1')
    // Без перезаписи ключ, записанный вслепую, мог уже быть: подсказка про
    // существующие значения нужна и здесь.
    expect(screen.getByText(/Существующие значения останутся как есть/)).toBeTruthy()
  })
})
