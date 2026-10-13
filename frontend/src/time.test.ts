/* Время в панели: по нему решают, жив ли сервер и давно ли трогали значение.
 *
 * Ошибка тут не видна глазами - она видна тем, что зеленая точка стоит у
 * сервера, который замолчал вчера.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { endOfDay, formatDate, formatDay, hoursSince, setTimeZone, staleClass } from './time'

function agoIso(hours: number): string {
  return new Date(Date.now() - hours * 3_600_000).toISOString()
}

afterEach(() => {
  vi.useRealTimers()
})

describe('staleClass', () => {
  it('молчит про свежую отметку', () => {
    expect(staleClass(agoIso(0.2))).toBe('')
  })

  it('час молчания — уже повод посмотреть', () => {
    expect(staleClass(agoIso(2))).toBe('stale-warn')
  })

  it('сутки — почти наверняка забытый сервер', () => {
    expect(staleClass(agoIso(30))).toBe('stale-old')
  })

  it('пустую отметку не красит', () => {
    // "Еще не приходил" - это не "пропал": у машины, которую только завели,
    // отметки нет вовсе.
    expect(staleClass('')).toBe('')
    expect(staleClass('не дата')).toBe('')
  })
})

describe('hoursSince', () => {
  it('считает часы', () => {
    expect(Math.round(hoursSince(agoIso(5)) ?? 0)).toBe(5)
  })

  it('на пустой отметке отдаёт null, а не ноль', () => {
    // Ноль означал бы "только что", и сервер без единого отчета выглядел бы
    // живым.
    expect(hoursSince('')).toBeNull()
  })
})

describe('даты, которые выбирает человек', () => {
  afterEach(() => {
    setTimeZone('UTC')
  })

  it('конец дня считается в зоне панели и показывается тем же днем', () => {
    setTimeZone('Europe/Moscow')
    const end = endOfDay('2026-09-30')
    expect(end).toBe('2026-09-30T20:59:59.000Z')
    expect(formatDate(end)).toBe('30.09.2026')
  })

  it('западнее Гринвича и в день перевода часов', () => {
    setTimeZone('America/New_York')
    expect(endOfDay('2026-03-08')).toBe('2026-03-09T03:59:59.000Z')
    expect(formatDate(endOfDay('2026-11-01'))).toBe('01.11.2026')
  })

  it('срок ключа показывается выбранным днем в любой зоне', () => {
    setTimeZone('America/New_York')
    expect(formatDay('2027-03-01T00:00:00+00:00')).toBe('01.03.2027')
    expect(formatDate('2027-03-01T00:00:00+00:00')).toBe('28.02.2027')
  })
})
