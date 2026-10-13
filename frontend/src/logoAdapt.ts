/* Свой логотип "как родной" на обеих темах.
 *
 * Логотип рисуют под один фон, обычно белый. На темной теме его темная надпись
 * тонет, а светлая плашка под ней выглядит наклейкой. Поэтому цвета, которые на
 * фоне темы читаются плохо, подтягиваем: нейтральные (надпись, контур) - в тон
 * тексту панели, фирменные - тот же оттенок и насыщенность, светлота ровно до
 * читаемости. Остальное не трогаем: темный логотип на светлой теме остается как
 * был, синий знак остается синим.
 *
 * Картинку со своим фоном и объемную (фото, градиенты) не перекрашиваем - это её
 * испортит; для них остается плашка. Все считается в браузере при показе: файл
 * хранится один, и перекраска не отстает от него, когда логотип заменят.
 *
 * Тот же подход, что в Kervax: панели одного автора подстраивают логотип
 * одинаково. Разбор цвета здесь свой, без canvas, - чтобы его проверяли тесты.
 */

export type LogoTheme = 'dark' | 'light'
export type LogoMode = 'auto' | 'always' | 'never'
/** url - картинка (свой адрес или data:), svg - её текст, если это SVG и он известен. */
export type LogoSource = { url: string; svg?: string | null }
export type LogoView = { src: string; plate: boolean; adapted: boolean }
export type RGB = [number, number, number]

// Фоны, на которых логотип показывается в каждой теме: страница (--bg) и карточка
// входа (--bg-card). Читаемость проверяем по худшему из двух. Шапка светлой темы
// темная и показывает вариант для темной темы.
const BGS: Record<LogoTheme, RGB[]> = {
  dark: [
    [0x0f, 0x11, 0x17],
    [0x17, 0x1a, 0x23],
  ],
  light: [
    [0xec, 0xee, 0xf2],
    [0xff, 0xff, 0xff],
  ],
}
// Текст панели (--text): в его тон уходят нейтральные цвета логотипа.
const TEXT: Record<LogoTheme, RGB> = { dark: [0xf1, 0xf5, 0xf9], light: [0x0d, 0x12, 0x1a] }
// Ниже этого цвет на фоне темы читается плохо.
const MIN_CONTRAST = 3
// До этого подтягиваем фирменный цвет: с запасом, чтобы не встать ровно на порог.
const TARGET = 3.3

const channel = (c: number) => {
  const v = c / 255
  return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
}

/** Относительная яркость по WCAG. */
export const luminance = ([r, g, b]: RGB) => 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)

/** Контраст двух цветов по WCAG: от 1 до 21. */
export function contrast(a: RGB, b: RGB): number {
  const la = luminance(a)
  const lb = luminance(b)
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
}

/** Контраст с худшим из фонов темы. */
export const readability = (c: RGB, theme: LogoTheme) =>
  Math.min(...BGS[theme].map((bg) => contrast(c, bg)))

function toHsl([r, g, b]: RGB): [number, number, number] {
  const rn = r / 255
  const gn = g / 255
  const bn = b / 255
  const max = Math.max(rn, gn, bn)
  const min = Math.min(rn, gn, bn)
  const l = (max + min) / 2
  if (max === min) return [0, 0, l]
  const d = max - min
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min)
  const h =
    max === rn ? (gn - bn) / d + (gn < bn ? 6 : 0) : max === gn ? (bn - rn) / d + 2 : (rn - gn) / d + 4
  return [h / 6, s, l]
}

function fromHsl(h: number, s: number, l: number): RGB {
  if (s === 0) {
    const v = Math.round(l * 255)
    return [v, v, v]
  }
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s
  const p = 2 * l - q
  const part = (t: number) => {
    let x = t
    if (x < 0) x += 1
    if (x > 1) x -= 1
    if (x < 1 / 6) return p + (q - p) * 6 * x
    if (x < 1 / 2) return q
    if (x < 2 / 3) return p + (q - p) * (2 / 3 - x) * 6
    return p
  }
  return [Math.round(part(h + 1 / 3) * 255), Math.round(part(h) * 255), Math.round(part(h - 1 / 3) * 255)]
}

/** Новый цвет для темы или null, если этот и так читается. */
export function adaptRgb(c: RGB, theme: LogoTheme): RGB | null {
  if (readability(c, theme) >= MIN_CONTRAST) return null
  const [h, s, l] = toHsl(c)
  const chroma = (Math.max(...c) - Math.min(...c)) / 255
  if (chroma < 0.15) {
    // Нейтральный - надпись или контур: в тон тексту панели. Иерархию тонов
    // сохраняем: черное станет самым светлым, темно-серое - чуть приглушеннее.
    const text = toHsl(TEXT[theme])[2]
    const next = theme === 'dark' ? text - l * 0.35 : text + (1 - l) * 0.35
    return fromHsl(h, s, Math.min(1, Math.max(0, next)))
  }
  // Фирменный: оттенок и насыщенность те же, светлоту двигаем ровно до читаемости.
  let near = l
  let far = theme === 'dark' ? 1 : 0
  for (let i = 0; i < 18; i++) {
    const mid = (near + far) / 2
    if (readability(fromHsl(h, s, mid), theme) >= TARGET) far = mid
    else near = mid
  }
  return fromHsl(h, s, far)
}

// --- цвета в разметке ---

const NAMED: Record<string, RGB> = {
  black: [0, 0, 0],
  white: [255, 255, 255],
  gray: [128, 128, 128],
  grey: [128, 128, 128],
  dimgray: [105, 105, 105],
  dimgrey: [105, 105, 105],
  darkgray: [169, 169, 169],
  darkgrey: [169, 169, 169],
  silver: [192, 192, 192],
  lightgray: [211, 211, 211],
  lightgrey: [211, 211, 211],
  whitesmoke: [245, 245, 245],
  navy: [0, 0, 128],
  darkblue: [0, 0, 139],
  midnightblue: [25, 25, 112],
  blue: [0, 0, 255],
  red: [255, 0, 0],
  darkred: [139, 0, 0],
  maroon: [128, 0, 0],
  purple: [128, 0, 128],
  green: [0, 128, 0],
  darkgreen: [0, 100, 0],
  lime: [0, 255, 0],
  olive: [128, 128, 0],
  yellow: [255, 255, 0],
  orange: [255, 165, 0],
  teal: [0, 128, 128],
  aqua: [0, 255, 255],
  cyan: [0, 255, 255],
  fuchsia: [255, 0, 255],
  magenta: [255, 0, 255],
}

export type Parsed = { rgb: RGB; alpha: number }

function hslToRgbColor(h: number, s: number, l: number): RGB {
  return fromHsl((((h % 360) + 360) % 360) / 360, s, l)
}

/** Цвет из разметки. Все, что не цвет (none, url(#...), currentColor), - null. */
export function parseColor(raw: string): Parsed | null {
  const value = raw.trim().replace(/\s*!important$/i, '').toLowerCase()
  if (NAMED[value]) return { rgb: NAMED[value], alpha: 1 }
  const hex = value.match(/^#([0-9a-f]{3,8})$/)
  if (hex) {
    let digits = hex[1]
    if (digits.length === 3 || digits.length === 4) {
      digits = digits
        .split('')
        .map((d) => d + d)
        .join('')
    }
    if (digits.length !== 6 && digits.length !== 8) return null
    const n = (i: number) => parseInt(digits.slice(i, i + 2), 16)
    return { rgb: [n(0), n(2), n(4)], alpha: digits.length === 8 ? n(6) / 255 : 1 }
  }
  const fn = value.match(/^(rgba?|hsla?)\(([^)]*)\)$/)
  if (!fn) return null
  const parts = fn[2].split(/[\s,/]+/).filter(Boolean)
  if (parts.length < 3) return null
  const a = parts[3]
  const alpha = a === undefined ? 1 : a.endsWith('%') ? parseFloat(a) / 100 : parseFloat(a)
  if (Number.isNaN(alpha)) return null
  if (fn[1].startsWith('rgb')) {
    const part = (p: string) =>
      p.endsWith('%') ? Math.round((parseFloat(p) / 100) * 255) : Math.round(parseFloat(p))
    const rgb: RGB = [part(parts[0]), part(parts[1]), part(parts[2])]
    if (rgb.some((c) => Number.isNaN(c) || c < 0 || c > 255)) return null
    return { rgb, alpha }
  }
  const h = parseFloat(parts[0])
  const s = parseFloat(parts[1]) / 100
  const l = parseFloat(parts[2]) / 100
  if ([h, s, l].some(Number.isNaN)) return null
  return { rgb: hslToRgbColor(h, s, l), alpha }
}

const hexOf = ([r, g, b]: RGB) => `#${[r, g, b].map((v) => v.toString(16).padStart(2, '0')).join('')}`

export function formatColor(rgb: RGB, alpha = 1): string {
  if (alpha >= 1) return hexOf(rgb)
  return `rgba(${rgb[0]}, ${rgb[1]}, ${rgb[2]}, ${Math.round(alpha * 1000) / 1000})`
}

/** Итог перекраски: новая картинка, "и так хорошо" или "перекрашивать нельзя". */
export type Adapted<T> = { out: T } | 'ok' | 'skip'

const PROPS = ['fill', 'stroke', 'stop-color', 'flood-color', 'color']
// В стилях свойство должно стоять отдельно: иначе "color" нашлось бы внутри
// "background-color".
const STYLE_PROP = /(^|[;{\s])(fill|stroke|stop-color|flood-color|color)(\s*:\s*)([^;}]+)/gi

/** Перекрасить SVG по цветам: картинка остается векторной и четкой. */
export function adaptSvg(svg: string, theme: LogoTheme): Adapted<string> {
  const doc = new DOMParser().parseFromString(svg, 'image/svg+xml')
  const root = doc.documentElement
  if (!root || root.localName !== 'svg' || doc.getElementsByTagName('parsererror').length > 0) {
    return 'skip'
  }
  // Вложенную растровую картинку по цветам не перекрасить - лучше не трогать вовсе.
  if (root.getElementsByTagName('image').length > 0) return 'skip'
  const recolor = (raw: string): string | null => {
    const parsed = parseColor(raw)
    if (!parsed || parsed.alpha === 0) return null
    const to = adaptRgb(parsed.rgb, theme)
    return to ? formatColor(to, parsed.alpha) : null
  }
  let changed = false
  for (const el of [root, ...Array.from(root.getElementsByTagName('*'))]) {
    // Маска и контур обрезки сами не рисуются: их цвета задают форму, а не вид.
    if (el.closest('mask, clipPath')) continue
    for (const prop of PROPS) {
      const value = el.getAttribute(prop)
      const to = value ? recolor(value) : null
      if (to) {
        el.setAttribute(prop, to)
        changed = true
      }
    }
    const style = el.getAttribute('style')
    if (style) {
      const next = style.replace(STYLE_PROP, (m, pre, prop, colon, val) => {
        const to = recolor(val)
        return to ? `${pre}${prop}${colon}${to}` : m
      })
      if (next !== style) {
        el.setAttribute('style', next)
        changed = true
      }
    }
  }
  for (const block of Array.from(root.getElementsByTagName('style'))) {
    const css = block.textContent ?? ''
    const next = css.replace(STYLE_PROP, (m, pre, prop, colon, val) => {
      const to = recolor(val)
      return to ? `${pre}${prop}${colon}${to}` : m
    })
    if (next !== css) {
      block.textContent = next
      changed = true
    }
  }
  // Фигуры без заливки по умолчанию черные - это тоже надпись, которую надо подтянуть.
  if (!root.hasAttribute('fill') && !/(^|;)\s*fill\s*:/i.test(root.getAttribute('style') ?? '')) {
    const to = adaptRgb([0, 0, 0], theme)
    if (to) {
      root.setAttribute('fill', hexOf(to))
      changed = true
    }
  }
  return changed ? { out: new XMLSerializer().serializeToString(doc) } : 'ok'
}

// --- картинки: дальше все требует браузера ---

async function loadImage(src: string): Promise<HTMLImageElement | null> {
  const img = new Image()
  img.src = src
  try {
    await img.decode()
  } catch {
    return null
  }
  return img.naturalWidth ? img : null
}

/** Прозрачные ли края картинки и темная ли она сама. */
export async function analyzeLogo(url: string): Promise<{ transparentEdges: boolean; dark: boolean }> {
  const img = await loadImage(url)
  const side = 48
  const canvas = document.createElement('canvas')
  canvas.width = side
  canvas.height = side
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  if (!img || !ctx) return { transparentEdges: true, dark: false }
  ctx.drawImage(img, 0, 0, side, side)
  let px: Uint8ClampedArray
  try {
    px = ctx.getImageData(0, 0, side, side).data
  } catch {
    // Закрытый canvas - не гадаем.
    return { transparentEdges: true, dark: false }
  }
  let edge = 0
  let edgeOpaque = 0
  let lumaSum = 0
  let lumaCount = 0
  for (let y = 0; y < side; y++) {
    for (let x = 0; x < side; x++) {
      const i = (y * side + x) * 4
      if (x < 2 || y < 2 || x >= side - 2 || y >= side - 2) {
        edge++
        if (px[i + 3] > 24) edgeOpaque++
      }
      if (px[i + 3] > 128) {
        lumaSum += 0.2126 * px[i] + 0.7152 * px[i + 1] + 0.0722 * px[i + 2]
        lumaCount++
      }
    }
  }
  return {
    // Края в основном непрозрачные - у картинки свой фон.
    transparentEdges: edge > 0 && edgeOpaque / edge < 0.35,
    // Темный логотип: на темной теме утонет без обработки.
    dark: lumaCount > 0 && lumaSum / lumaCount < 110,
  }
}

function adaptPixels(img: HTMLImageElement, theme: LogoTheme): Adapted<string> {
  const scale = Math.min(1, 1600 / img.naturalWidth)
  const width = Math.max(1, Math.round(img.naturalWidth * scale))
  const height = Math.max(1, Math.round(img.naturalHeight * scale))
  const canvas = document.createElement('canvas')
  canvas.width = width
  canvas.height = height
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  if (!ctx) return 'skip'
  ctx.drawImage(img, 0, 0, width, height)
  let frame: ImageData
  try {
    frame = ctx.getImageData(0, 0, width, height)
  } catch {
    return 'skip'
  }
  const px = frame.data
  // Плоский ли логотип: у надписи и знака цветов единицы, а у фото или объемной
  // эмблемы их сотни - перекраска по цветам такую картинку только испортит.
  const hist = new Map<number, number>()
  let opaque = 0
  for (let i = 0; i < px.length; i += 4) {
    if (px[i + 3] < 200) continue
    opaque++
    const key = ((px[i] >> 3) << 10) | ((px[i + 1] >> 3) << 5) | (px[i + 2] >> 3)
    hist.set(key, (hist.get(key) ?? 0) + 1)
  }
  if (!opaque) return 'skip'
  const top = [...hist.values()]
    .sort((a, b) => b - a)
    .slice(0, 12)
    .reduce((a, b) => a + b, 0)
  if (top / opaque < 0.9) return 'skip'
  // Цветов в логотипе единицы, пикселей - сотни тысяч: считаем каждый цвет раз.
  const memo = new Map<number, RGB | null>()
  let changed = false
  for (let i = 0; i < px.length; i += 4) {
    if (px[i + 3] === 0) continue
    const key = (px[i] << 16) | (px[i + 1] << 8) | px[i + 2]
    let to = memo.get(key)
    if (to === undefined) {
      to = adaptRgb([px[i], px[i + 1], px[i + 2]], theme)
      memo.set(key, to)
    }
    if (to) {
      px[i] = to[0]
      px[i + 1] = to[1]
      px[i + 2] = to[2]
      changed = true
    }
  }
  if (!changed) return 'ok'
  ctx.putImageData(frame, 0, 0)
  return { out: canvas.toDataURL('image/png') }
}

export function svgDataUrl(svg: string): string {
  let bin = ''
  for (const byte of new TextEncoder().encode(svg)) bin += String.fromCharCode(byte)
  return `data:image/svg+xml;base64,${btoa(bin)}`
}

// Текст SVG со своего адреса. data:-адреса fetch'ем не читаем: их не пускает CSP
// панели (connect-src 'self'), а для только что выбранного файла текст и так есть.
async function svgText(source: LogoSource): Promise<string | null> {
  if (source.svg !== undefined) return source.svg
  if (source.url.startsWith('data:')) return null
  try {
    const res = await fetch(source.url)
    if (!res.ok || !(res.headers.get('content-type') ?? '').startsWith('image/svg')) return null
    return await res.text()
  } catch {
    return null
  }
}

const cache = new Map<string, Promise<LogoView>>()

/** Как показать логотип на этой теме: перекрашенным, на плашке или как есть. */
export function logoView(source: LogoSource, theme: LogoTheme, mode: LogoMode): Promise<LogoView> {
  const key = `${theme}|${mode}|${source.url}`
  let got = cache.get(key)
  if (!got) {
    got = compute(source, theme, mode)
    cache.set(key, got)
  }
  return got
}

async function compute(source: LogoSource, theme: LogoTheme, mode: LogoMode): Promise<LogoView> {
  const plain = { src: source.url, adapted: false }
  if (mode === 'always') return { ...plain, plate: true }
  if (mode === 'never') return { ...plain, plate: false }
  const analysis = await analyzeLogo(source.url)
  // Своя подложка у картинки - перекрашивать нечего, её фон и есть фон.
  if (!analysis.transparentEdges) return { ...plain, plate: true }
  const text = await svgText(source)
  let result: Adapted<string> = 'skip'
  if (text) {
    const svg = adaptSvg(text, theme)
    result = typeof svg === 'object' ? { out: svgDataUrl(svg.out) } : svg
  } else {
    const img = await loadImage(source.url)
    if (img) result = adaptPixels(img, theme)
  }
  if (typeof result === 'object') return { src: result.out, plate: false, adapted: true }
  // Перекрасить нельзя, а темный логотип на темной теме не виден - тогда плашка.
  return { ...plain, plate: result === 'skip' && theme === 'dark' && analysis.dark }
}
