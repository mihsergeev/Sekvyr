/* Закладки: то, что человек сам поднял на главную.
 *
 * Все живет в localStorage, поэтому проверяем и то, что происходит, когда
 * хранилище отвечает мусором или не отвечает вовсе: в приватном окне это
 * обычное дело, а падать из-за списка закладок панель не должна.
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { pinned, pins, togglePin } from './pins'

describe('закладки', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('закрепляет и снимает', () => {
    expect(pinned('acme', 'api', 'prod')).toBe(false)
    expect(togglePin('acme', 'api', 'prod')).toBe(true)
    expect(pinned('acme', 'api', 'prod')).toBe(true)
    expect(pins()).toHaveLength(1)
    expect(togglePin('acme', 'api', 'prod')).toBe(false)
    expect(pins()).toEqual([])
  })

  it('различает окружения одного проекта', () => {
    togglePin('acme', 'api', 'prod')
    expect(pinned('acme', 'api', 'stage')).toBe(false)
  })

  it('переживает мусор в хранилище', () => {
    localStorage.setItem('sekvyr_pins', 'не json')
    expect(pins()).toEqual([])
    localStorage.setItem('sekvyr_pins', '{"не":"массив"}')
    expect(pins()).toEqual([])
  })
})
