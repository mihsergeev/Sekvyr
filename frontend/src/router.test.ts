/* Адреса страниц: ссылку присылают в чат, открывают через месяц, обрезают при
 * копировании. Разбор не должен ни падать, ни открывать не то.
 */

import { describe, expect, it } from 'vitest'
import { parseLocation, viewToPath } from './router'

describe('адрес сервера', () => {
  it('несет номер: имя не уникально', () => {
    const path = viewToPath({ kind: 'server', name: 'web-1', id: 7 })
    expect(path).toBe('/servers/web-1?id=7')
    const [pathname, search] = path.split('?')
    expect(parseLocation(pathname, `?${search}`)).toEqual({ kind: 'server', name: 'web-1', id: 7 })
  })

  it('старая ссылка без номера открывается по имени', () => {
    expect(parseLocation('/servers/web-1', '')).toEqual({ kind: 'server', name: 'web-1' })
  })

  it('имя личности в кластере с косой чертой остается одним куском', () => {
    const path = viewToPath({ kind: 'server', name: 'prod/billing', id: 3 })
    expect(path).toBe('/servers/prod%2Fbilling?id=3')
    expect(parseLocation('/servers/prod%2Fbilling', '?id=3')).toEqual({
      kind: 'server',
      name: 'prod/billing',
      id: 3,
    })
  })

  it('мусор вместо номера не принимается за номер', () => {
    expect(parseLocation('/servers/web-1', '?id=abc')).toEqual({ kind: 'server', name: 'web-1' })
    expect(parseLocation('/servers/web-1', '?id=-2')).toEqual({ kind: 'server', name: 'web-1' })
  })
})

describe('битый адрес', () => {
  it('обрезанный % не роняет приложение', () => {
    expect(() => parseLocation('/p/-/shop/prod%E0%A4%A', '')).not.toThrow()
    expect(parseLocation('/p/-/shop/prod%', '')).toEqual({
      kind: 'env',
      group: '',
      slug: 'shop',
      env: 'prod%',
      query: undefined,
    })
  })
})
