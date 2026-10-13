import { describe, expect, it } from 'vitest'
import { csvText } from './csv'

describe('csvText', () => {
  it('не дает ячейке стать формулой', () => {
    expect(csvText('=HYPERLINK("http://evil/","open")')).toBe('\'=HYPERLINK("http://evil/","open")')
    for (const start of ['+', '-', '@', '\t', '\r']) {
      expect(csvText(`${start}1+1`)).toBe(`'${start}1+1`)
    }
  })

  it('обычный текст не трогает', () => {
    expect(csvText('admin')).toBe('admin')
    expect(csvText('12:shop/prod:DB_PASSWORD')).toBe('12:shop/prod:DB_PASSWORD')
    expect(csvText('')).toBe('')
    expect(csvText(undefined)).toBe('')
  })
})
