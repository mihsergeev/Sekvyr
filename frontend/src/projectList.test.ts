/* Раскладка списка проектов: что свернуто, что убрано, что поднято наверх.
 *
 * Проверяем то, что руками проверять дольше всего: ключ проекта с группой и без
 * нее, переключение туда-обратно и мусор в хранилище - в приватном окне это
 * обычное дело, а падать из-за раскладки списка панель не должна.
 */

import { beforeEach, describe, expect, it } from 'vitest'
import {
  collapsedGroups,
  favProjects,
  hiddenProjects,
  projectKey,
  setCollapsedGroups,
  setSortMode,
  sortMode,
  toggleFav,
  toggleGroup,
  toggleHidden,
} from './projectList'

describe('ключ проекта', () => {
  it('держит группу, когда она есть', () => {
    expect(projectKey('acme', 'api')).toBe('acme/api')
  })

  it('без группы — просто имя', () => {
    expect(projectKey('', 'wiki')).toBe('wiki')
  })
})

describe('свёрнутые группы', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('по умолчанию не свёрнуто ничего', () => {
    expect(collapsedGroups()).toEqual([])
  })

  it('сворачивает и разворачивает', () => {
    expect(toggleGroup('acme')).toEqual(['acme'])
    expect(collapsedGroups()).toEqual(['acme'])
    expect(toggleGroup('acme')).toEqual([])
  })

  it('свернуть все — это один список', () => {
    setCollapsedGroups(['acme', 'globex'])
    expect(collapsedGroups()).toEqual(['acme', 'globex'])
    setCollapsedGroups([])
    expect(collapsedGroups()).toEqual([])
  })

  it('переживает мусор в хранилище', () => {
    localStorage.setItem('sekvyr_groups_off', 'не json')
    expect(collapsedGroups()).toEqual([])
    localStorage.setItem('sekvyr_groups_off', '{"не":"массив"}')
    expect(collapsedGroups()).toEqual([])
  })
})

describe('скрытые и избранные', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('скрывает и возвращает проект', () => {
    toggleHidden('acme/api')
    expect(hiddenProjects()).toEqual(['acme/api'])
    toggleHidden('acme/api')
    expect(hiddenProjects()).toEqual([])
  })

  it('избранное и скрытые лежат врозь', () => {
    toggleHidden('acme/api')
    toggleFav('globex/bot')
    expect(hiddenProjects()).toEqual(['acme/api'])
    expect(favProjects()).toEqual(['globex/bot'])
  })
})

describe('порядок в группе', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('по умолчанию по имени', () => {
    expect(sortMode()).toBe('name')
  })

  it('помнит выбранный', () => {
    setSortMode('changed')
    expect(sortMode()).toBe('changed')
  })

  it('чужое значение читает как «по имени»', () => {
    localStorage.setItem('sekvyr_projects_sort', 'по-моему')
    expect(sortMode()).toBe('name')
  })
})
