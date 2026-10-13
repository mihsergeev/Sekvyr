// Кадры для README: снимает живую панель на демо-данных (docs/demo-seed.py).
//
// Не моки: в кадре тот же фронтенд, что уходит в образ, поэтому картинка не
// может разойтись с интерфейсом. Данные выдуманы: домены из RFC 2606, адреса
// из RFC 5737.
//
// Обычно запускается не руками, а оркестратором, который поднимает панель на
// временной базе и убирает ее за собой:
//
//   cd frontend && npm run build && npm i --no-save playwright-core && cd ..
//   python docs/make-shots.py
//
// Системный Chrome, без скачивания браузеров: PW_CHROME=<путь к chrome>.
import { chromium } from 'playwright-core'
import { mkdir } from 'node:fs/promises'
import path from 'node:path'

const BASE = process.env.SHOTS_BASE || 'http://127.0.0.1:5111'
const PASS = process.env.SHOTS_PASS || ''
const LANG = process.env.SHOTS_LANG || 'en'
const THEME = process.env.SHOTS_THEME || 'dark'
const OUT = process.env.SHOTS_OUT || path.join(import.meta.dirname, '..', '..', 'docs', 'img')
const CHROME =
  process.env.PW_CHROME ||
  (process.platform === 'win32'
    ? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
    : '/usr/bin/google-chrome')

const WIDTH = 1440

// h - потолок высоты кадра: настоящая считается по содержимому, а потолок
// нужен там, где страница длинная и снимать ее целиком незачем.
const SHOTS = [
  { name: 'home', url: '/', h: 900 },
  { name: 'environment', url: '/p/acme/api/prod', h: 900, reveal: 'FEATURE_NEW_CHECKOUT' },
  { name: 'history', url: '/p/acme/api/prod', h: 900, history: 'DATABASE_URL' },
  { name: 'servers', url: '/servers', h: 900 },
  { name: 'access', url: '/access', h: 900 },
]

const HISTORY = { en: 'History', ru: 'История' }

async function token() {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: PASS }),
  })
  if (!res.ok) throw new Error(`вход не удался: ${res.status}`)
  return (await res.json()).access_token
}

function row(page, name) {
  return page
    .locator('.key-row')
    .filter({ has: page.locator('.key-name .mono', { hasText: new RegExp(`^${name}$`) }) })
}

const run = async () => {
  const jwt = await token()
  const browser = await chromium.launch({ executablePath: CHROME })
  const dir = LANG === 'en' ? OUT : path.join(OUT, LANG)
  await mkdir(dir, { recursive: true })
  const context = await browser.newContext({
    viewport: { width: WIDTH, height: 900 },
    deviceScaleFactor: 1,
    colorScheme: THEME,
    locale: LANG === 'ru' ? 'ru-RU' : 'en-US',
    timezoneId: 'Europe/Berlin',
  })
  // Вход, язык, тема и закладки - до первой загрузки страницы.
  await context.addInitScript(
    ({ jwt, lang, theme }) => {
      localStorage.setItem('sekvyr_token', jwt)
      localStorage.setItem('sekvyr_lang', lang)
      localStorage.setItem('sekvyr_theme', theme)
      localStorage.setItem(
        'sekvyr_pins',
        JSON.stringify([
          { group: 'acme', slug: 'api', env: 'prod', at: 2 },
          { group: 'acme', slug: 'web', env: 'prod', at: 1 },
        ]),
      )
    },
    { jwt, lang: LANG, theme: THEME },
  )
  const page = await context.newPage()
  for (const shot of SHOTS) {
    await page.goto(BASE + shot.url, { waitUntil: 'networkidle' })
    await page.waitForTimeout(400)
    if (shot.reveal) {
      await row(page, shot.reveal).click()
      await page.waitForTimeout(400)
    }
    if (shot.history) {
      await row(page, shot.history).locator('.menu-wrap > button').click()
      await page.locator('.menu-pop .menu-item', { hasText: HISTORY[LANG] }).click()
      await page.waitForLoadState('networkidle')
      // Верхняя версия раскрыта: в кадре видно, что именно поменялось.
      await page.locator('.hist-row .hist-main').first().click()
      await page.waitForLoadState('networkidle')
      await page.waitForTimeout(500)
    }
    // Высота - по нижнему краю содержимого, но не выше потолка.
    const height = await page.evaluate(() =>
      Math.ceil(document.documentElement.scrollHeight),
    )
    const file = path.join(dir, `${shot.name}.png`)
    await page.screenshot({
      path: file,
      clip: { x: 0, y: 0, width: WIDTH, height: Math.min(height, shot.h) },
    })
    console.log('  ', file)
  }
  await browser.close()
}

run().catch((err) => {
  console.error(err)
  process.exit(1)
})
