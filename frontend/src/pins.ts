/* Закрепленные окружения.
 *
 * При двух сотнях проектов каждый заход начинался бы с набора имени, хотя рабочих
 * окружений у человека три-четыре. Закладка - про "я сюда хожу каждый день", и
 * ставит её человек сам: список последних посещений решал ту же задачу хуже -
 * один разовый заход вытеснял из него рабочий стенд.
 *
 * Хранится в localStorage: панели знать об этом незачем, а на чужом компьютере
 * чужие закладки и не нужны. Значений здесь нет и быть не может - только имена
 * проекта и окружения, те же, что видны в адресе.
 */

export type PinnedEnv = { group: string; slug: string; env: string; at: number }

const PINS = 'sekvyr_pins'

export function pins(): PinnedEnv[] {
  try {
    const raw = localStorage.getItem(PINS)
    if (!raw) return []
    const list = JSON.parse(raw) as PinnedEnv[]
    if (!Array.isArray(list)) return []
    return list.filter((item) => item && typeof item.slug === 'string' && typeof item.env === 'string')
  } catch {
    // Приватное окно, запрет хранилища, чужой мусор под тем же ключом - во всех
    // случаях ответ один: закладок нет.
    return []
  }
}

export function pinned(group: string, slug: string, env: string): boolean {
  return pins().some((a) => a.group === group && a.slug === slug && a.env === env)
}

/** Закрепить или снять закрепление. Возвращает новое состояние. */
export function togglePin(group: string, slug: string, env: string): boolean {
  const same = (a: PinnedEnv) => a.group === group && a.slug === slug && a.env === env
  const list = pins()
  const next = list.some(same)
    ? list.filter((a) => !same(a))
    : [...list, { group, slug, env, at: Date.now() }]
  try {
    localStorage.setItem(PINS, JSON.stringify(next))
  } catch {
    // Хранилище закрыто: закладка не сохранится, но работать это не мешает.
  }
  return !list.some(same)
}
