/* Как человек разложил у себя список проектов.
 *
 * На двух сотнях проектов список перестает быть списком: девять десятых строк -
 * чужие команды и давно закрытые сервисы. Панель про это знать не может, потому
 * что "мое" у каждого свое, и меняется оно чаще, чем права.
 *
 * Поэтому здесь только привычка конкретного браузера - как в pins.ts: какие
 * группы свернуты, какие проекты убраны с глаз, какие подняты наверх. Имен
 * значений тут нет и быть не может, только куски адреса, те же, что в строке
 * браузера.
 *
 * Общий для всех ответ на "проекта больше нет" - это архив, он живет в базе.
 */

/** Проект куском адреса: "группа/имя". Без группы - просто имя. */
export function projectKey(group: string, slug: string): string {
  return group ? `${group}/${slug}` : slug
}

function read(key: string): string[] {
  try {
    const raw = localStorage.getItem(key)
    if (!raw) return []
    const list = JSON.parse(raw) as string[]
    return Array.isArray(list) ? list.filter((item) => typeof item === 'string') : []
  } catch {
    // Приватное окно, запрет хранилища, чужой мусор под тем же ключом - ответ
    // один: человек ничего не раскладывал.
    return []
  }
}

function write(key: string, list: string[]): void {
  try {
    localStorage.setItem(key, JSON.stringify(list))
  } catch {
    // Не сохранилось - значит в этом браузере раскладка не переживет перезагрузку.
    // Ронять из-за этого страницу незачем.
  }
}

function flip(key: string, item: string): string[] {
  const list = read(key)
  const next = list.includes(item) ? list.filter((a) => a !== item) : [...list, item]
  write(key, next)
  return next
}

const OFF = 'sekvyr_groups_off'
const HIDDEN = 'sekvyr_projects_hidden'
const FAV = 'sekvyr_projects_fav'

/** Свернутые группы: хранится то, что свернуто, а не то, что открыто. Новая
    группа тогда появляется открытой - её видно, а не приходится искать. */
export const collapsedGroups = (): string[] => read(OFF)
export const toggleGroup = (key: string): string[] => flip(OFF, key)
export const setCollapsedGroups = (keys: string[]): void => write(OFF, keys)

/** Проекты, убранные с глаз: живые, но не мои. */
export const hiddenProjects = (): string[] => read(HIDDEN)
export const toggleHidden = (key: string): string[] => flip(HIDDEN, key)

/** Избранные проекты: поднимаются отдельной группой наверх списка. */
export const favProjects = (): string[] => read(FAV)
export const toggleFav = (key: string): string[] => flip(FAV, key)

/* Порядок внутри группы.
 *
 * По имени - чтобы найти известное; по изменению - чтобы увидеть, что живет;
 * по ключам - чтобы понять, где основное добро. Порядок групп при этом не
 * меняется: он про то, как устроена команда, а не про то, что сейчас ищут.
 */

export type SortMode = 'name' | 'changed' | 'keys'

const SORT = 'sekvyr_projects_sort'

export function sortMode(): SortMode {
  try {
    const raw = localStorage.getItem(SORT)
    return raw === 'changed' || raw === 'keys' ? raw : 'name'
  } catch {
    return 'name'
  }
}

export function setSortMode(mode: SortMode): void {
  try {
    localStorage.setItem(SORT, mode)
  } catch {
    // Хранилище закрыто: выбор не переживет перезагрузку, но работать не мешает.
  }
}
