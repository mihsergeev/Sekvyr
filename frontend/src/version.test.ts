/* Сравнение версий агента: та же логика, что в самом агенте.
 *
 * Ошибка здесь стоит дорого в обе стороны: панель либо молчит о том, что агент
 * отстал, либо показывает "устарел" тому, кто уже на свежей версии.
 */

import { describe, expect, it } from 'vitest'
import { newerVersion } from './version'

describe('newerVersion', () => {
  it('видит обычное обновление', () => {
    expect(newerVersion('0.27.0', '0.26.0')).toBe(true)
    expect(newerVersion('0.26.0', '0.27.0')).toBe(false)
    expect(newerVersion('0.26.0', '0.26.0')).toBe(false)
  })

  it('сравнивает числами, а не строками', () => {
    // Как строки "0.9.0" больше "0.10.0" - ровно та ошибка, ради которой это и
    // написано отдельной функцией.
    expect(newerVersion('0.10.0', '0.9.0')).toBe(true)
    expect(newerVersion('0.9.0', '0.10.0')).toBe(false)
    expect(newerVersion('1.0.0', '0.99.99')).toBe(true)
  })

  it('терпит разную длину', () => {
    expect(newerVersion('0.26', '0.26.0')).toBe(false)
    expect(newerVersion('0.26.1', '0.26')).toBe(true)
  })

  it('непонятную версию считает не новее', () => {
    expect(newerVersion('dev', '0.26.0')).toBe(false)
    expect(newerVersion('0.26.0', 'dev')).toBe(false)
    expect(newerVersion('', '0.26.0')).toBe(false)
    expect(newerVersion('0.26.0-rc1', '0.26.0')).toBe(false)
  })
})
