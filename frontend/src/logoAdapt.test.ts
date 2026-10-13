/* Подстройка логотипа под тему: что перекрашивается, а что остается как было.
 *
 * Живой случай - логотип одной из компаний: почти черная надпись и синий знак. На
 * темной шапке надпись пропадала, а белая плашка под ней выглядела наклейкой.
 */

import { describe, expect, it } from 'vitest'
import { adaptRgb, adaptSvg, formatColor, parseColor, readability, type RGB } from './logoAdapt'

const rgb = (value: string): RGB => parseColor(value)!.rgb

describe('цвет под тему', () => {
  it('чёрная надпись на тёмной теме становится почти цветом текста панели', () => {
    const to = adaptRgb(rgb('#1d1d1b'), 'dark')!
    expect(readability(to, 'dark')).toBeGreaterThan(12)
    // Нейтральная осталась нейтральной: без цветного оттенка.
    expect(Math.max(...to) - Math.min(...to)).toBeLessThan(8)
  })

  it('тёмно-серое светлеет меньше чёрного: иерархия тонов сохраняется', () => {
    const black = adaptRgb(rgb('#000000'), 'dark')!
    const gray = adaptRgb(rgb('#3a3a3a'), 'dark')!
    expect(black[0]).toBeGreaterThan(gray[0])
  })

  it('на светлой теме тёмную надпись не трогаем', () => {
    expect(adaptRgb(rgb('#1d1d1b'), 'light')).toBeNull()
  })

  it('белая надпись на светлой теме темнеет', () => {
    const to = adaptRgb([255, 255, 255], 'light')!
    expect(readability(to, 'light')).toBeGreaterThan(12)
  })

  it('фирменный синий на тёмной теме светлеет ровно до читаемого и остаётся синим', () => {
    const to = adaptRgb(rgb('#2b4acb'), 'dark')!
    expect(readability(to, 'dark')).toBeGreaterThanOrEqual(3.3)
    expect(readability(to, 'dark')).toBeLessThan(3.6)
    expect(to[2]).toBeGreaterThan(to[0])
    expect(to[2]).toBeGreaterThan(to[1])
  })

  it('читаемый цвет не трогаем', () => {
    expect(adaptRgb(rgb('#18e36e'), 'dark')).toBeNull()
  })
})

describe('разбор цвета', () => {
  it('понимает hex, rgb, rgba, hsl и имена', () => {
    expect(parseColor('#abc')).toEqual({ rgb: [0xaa, 0xbb, 0xcc], alpha: 1 })
    expect(parseColor('#112233')).toEqual({ rgb: [0x11, 0x22, 0x33], alpha: 1 })
    expect(parseColor('rgb(10, 20, 30)')).toEqual({ rgb: [10, 20, 30], alpha: 1 })
    expect(parseColor('rgba(0,0,0,0.5)')).toEqual({ rgb: [0, 0, 0], alpha: 0.5 })
    expect(parseColor('hsl(0, 0%, 0%)')).toEqual({ rgb: [0, 0, 0], alpha: 1 })
    expect(parseColor('Black')).toEqual({ rgb: [0, 0, 0], alpha: 1 })
  })

  it('не цвет — не трогаем', () => {
    expect(parseColor('none')).toBeNull()
    expect(parseColor('url(#grad)')).toBeNull()
    expect(parseColor('currentColor')).toBeNull()
  })

  it('пишет обратно hex, а с прозрачностью — rgba', () => {
    expect(formatColor([17, 34, 51])).toBe('#112233')
    expect(formatColor([0, 0, 0], 0.5)).toBe('rgba(0, 0, 0, 0.5)')
  })
})

const LOGO =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 20">' +
  '<text fill="#1d1d1b">acme</text><rect fill="#2b4acb" width="10" height="10"/></svg>'

describe('SVG', () => {
  it('на тёмной теме перекрашивает надпись и подтягивает знак', () => {
    const got = adaptSvg(LOGO, 'dark')
    expect(typeof got).toBe('object')
    const out = (got as { out: string }).out
    expect(out).not.toContain('#1d1d1b')
    expect(out).not.toContain('#2b4acb')
  })

  it('на светлой теме перекрашивать нечего', () => {
    expect(adaptSvg(LOGO, 'light')).toBe('ok')
  })

  it('фигура без заливки чёрная по умолчанию — ей тоже нужен цвет', () => {
    const bare = '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h10v10z"/></svg>'
    const got = adaptSvg(bare, 'dark') as { out: string }
    expect(got.out).toMatch(/<svg[^>]*fill="#/)
  })

  it('цвета в стилях правит, а background-color за цвет не принимает', () => {
    const styled =
      '<svg xmlns="http://www.w3.org/2000/svg" fill="#18e36e">' +
      '<style>.t{fill:#000;background-color:#000}</style><path class="t"/></svg>'
    const got = adaptSvg(styled, 'dark') as { out: string }
    expect(got.out).not.toContain('fill:#000;')
    expect(got.out).toContain('background-color:#000')
  })

  it('маску не трогает: её цвет задаёт форму', () => {
    const masked =
      '<svg xmlns="http://www.w3.org/2000/svg" fill="#18e36e">' +
      '<mask id="m"><rect fill="#000"/></mask><path mask="url(#m)"/></svg>'
    expect(adaptSvg(masked, 'dark')).toBe('ok')
  })

  it('SVG с вложенной картинкой не перекрашивает вовсе', () => {
    const embedded =
      '<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,AAAA"/>' +
      '<text fill="#000">x</text></svg>'
    expect(adaptSvg(embedded, 'dark')).toBe('skip')
  })

  it('битая разметка — не SVG', () => {
    expect(adaptSvg('<svg><g></svg>', 'dark')).toBe('skip')
  })
})
