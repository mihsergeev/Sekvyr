/* Десятый проход: выгрузка журнала и зона панели. */

import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { AuditPage } from './AuditPage'
import { setTimeZone, timeZone } from './time'

async function settle(n = 10) {
  for (let i = 0; i < n; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 10))
    })
  }
}

afterEach(() => {
  vi.restoreAllMocks()
  document.body.innerHTML = ''
  setTimeZone('UTC')
})

function entry(id: number, ts: string): api.AuditEntry {
  return { id, ts, actor: 'agent', action: 'machine_read', target: `t${id}`, detail: '', ip: '203.0.113.1' }
}

describe('выгрузка журнала', () => {
  it('новые записи во время выгрузки не дают повторов и не съедают старые', async () => {
    let journal: api.AuditEntry[] = []
    for (let id = 1200; id >= 1; id--) journal.push(entry(id, new Date(Date.UTC(2026, 9, 1) + id * 60_000).toISOString()))
    let downloadCalls = 0
    vi.spyOn(api, 'listAudit').mockImplementation(async (o = {}) => {
      const offset = o.offset ?? 0
      const limit = o.limit ?? 100
      if (limit === 500) {
        downloadCalls++
        if (downloadCalls === 2) {
          // Пока шла первая страница, агенты прочитали значения: три новые
          // записи сверху сдвинули страницы.
          journal = [entry(1203, '2026-10-13T00:00:03Z'), entry(1202, '2026-10-13T00:00:02Z'), entry(1201, '2026-10-13T00:00:01Z'), ...journal]
        }
      }
      return { total: journal.length, entries: journal.slice(offset, offset + limit) }
    })
    let blob: Blob | null = null
    URL.createObjectURL = vi.fn((b: Blob) => {
      blob = b
      return 'blob:x'
    }) as never
    URL.revokeObjectURL = vi.fn()
    HTMLAnchorElement.prototype.click = vi.fn()

    render(<AuditPage />)
    await settle()
    fireEvent.click(screen.getByText('Скачать файл'))
    await settle(20)
    expect(blob).not.toBeNull()
    const text = await (blob as unknown as Blob).text()
    const lines = text.split('\r\n')
    expect(lines[0]).toContain('UTC')
    const targets = lines.slice(1).map((line) => line.split(';')[5])
    expect(targets.filter((t, i) => targets.indexOf(t) !== i)).toEqual([])
    // Самая старая запись в файле есть.
    expect(targets).toContain('"t1"')
  })
})

describe('зона панели', () => {
  it('неизвестное имя зоны - UTC, а не зона браузера под чужой подписью', () => {
    setTimeZone('Europe/Moskow')
    expect(timeZone()).toBe('UTC')
    setTimeZone('Europe/Moscow')
    expect(timeZone()).toBe('Europe/Moscow')
  })
})

describe('выгрузка журнала после роста', () => {
  it('журнал вырос, пока страница висела: в файле все записи, без ложной пометки', async () => {
    const make = (n: number) => {
      const out: api.AuditEntry[] = []
      for (let id = n; id >= 1; id--) out.push(entry(id, new Date(Date.UTC(2026, 9, 1) + id * 60_000).toISOString()))
      return out
    }
    let journal = make(1000)
    vi.spyOn(api, 'listAudit').mockImplementation(async (o = {}) => {
      const offset = o.offset ?? 0
      const limit = o.limit ?? 100
      return { total: journal.length, entries: journal.slice(offset, offset + limit) }
    })
    let blob: Blob | null = null
    URL.createObjectURL = vi.fn((b: Blob) => {
      blob = b
      return 'blob:x'
    }) as never
    URL.revokeObjectURL = vi.fn()
    HTMLAnchorElement.prototype.click = vi.fn()
    render(<AuditPage />)
    await settle()
    journal = make(1300)
    fireEvent.click(screen.getByText('Скачать файл'))
    await settle(20)
    const lines = (await (blob as unknown as Blob).text()).split('\r\n').slice(1)
    expect(lines.length).toBe(1300)
    expect(lines.some((line) => line.includes('"t1"'))).toBe(true)
    expect(document.body.textContent).not.toContain('В файл попали')
  })
})
