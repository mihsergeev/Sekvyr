/* Сравнение версий значения: его читают, когда разбираются, что сломалось.
 *
 * Здесь важна не красота вывода, а честность: строка, которая не менялась, не
 * должна показываться измененной, иначе разбор инцидента уходит в ложный след.
 */

import { describe, expect, it } from 'vitest'
import { diffCounts, lineDiff } from './diff'

describe('lineDiff', () => {
  it('одинаковое показывает без изменений', () => {
    const lines = lineDiff('a\nb', 'a\nb')
    expect(lines.every((l) => l.sign === ' ')).toBe(true)
    expect(diffCounts(lines)).toEqual({ added: 0, removed: 0 })
  })

  it('видит добавленную строку', () => {
    const lines = lineDiff('a\nb', 'a\nb\nc')
    expect(diffCounts(lines)).toEqual({ added: 1, removed: 0 })
    expect(lines.filter((l) => l.sign === '+').map((l) => l.text)).toEqual(['c'])
  })

  it('видит удалённую строку', () => {
    const lines = lineDiff('a\nb\nc', 'a\nc')
    expect(diffCounts(lines)).toEqual({ added: 0, removed: 1 })
    expect(lines.filter((l) => l.sign === '-').map((l) => l.text)).toEqual(['b'])
  })

  it('правку строки показывает как минус и плюс', () => {
    const lines = lineDiff('APP_ENV=stage', 'APP_ENV=production')
    expect(diffCounts(lines)).toEqual({ added: 1, removed: 1 })
  })

  it('пустое значение не превращает в строку', () => {
    // Пустая строка - это ноль строк, а не одна пустая: иначе "было пусто"
    // выглядело бы как удаление строки.
    expect(lineDiff('', '')).toEqual([])
    expect(diffCounts(lineDiff('', 'a'))).toEqual({ added: 1, removed: 0 })
  })
})
