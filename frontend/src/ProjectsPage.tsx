import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  createProject,
  listMachines,
  listProjects,
  searchSecrets,
  updateProject,
  type SecretHit,
  type Machine,
  type Project,
} from './api'
import { Mark } from './Mark'
import { useAuth } from './auth'
import { useDialogs } from './Dialogs'
import { ErrorNote, Skeleton } from './Notes'
import { plural, useI18n } from './i18n'
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
  type SortMode,
} from './projectList'
import { pins } from './pins'
import { useEscape } from './useEscape'
import { usePoll } from './usePoll'
import { formatAgo, formatDateTime, staleClass } from './time'

/* Главная: с чего начинается работа.
 *
 * Сотня проектов - это не "длинный список", а другой способ им пользоваться:
 * человек приходит за конкретным проектом и знает его имя. Поэтому здесь поиск,
 * группировка и счетчики, а не алфавитный перечень одинаковых строк.
 */

// Ключи особых разделов: своих групп с такими именами быть не может -
// настоящий ключ группы это кусок адреса, а он без решеток.
const FAVOURITE = '#fav'
const ARCHIVE = '#archive'

export function ProjectsPage({
  onOpen,
  onOpenServers,
}: {
  onOpen: (group: string, slug: string, env?: string, query?: string) => void
  onOpenServers: () => void
}) {
  const { t, lang } = useI18n()
  const auth = useAuth()
  const { ask } = useDialogs()
  const [projects, setProjects] = useState<Project[]>([])
  const [servers, setServers] = useState<Machine[]>([])
  const [filter, setFilter] = useState('')
  // Ключи ищет сервер: имя ключа человек помнит, а в каком из тридцати
  // окружений он лежит - нет.
  const [hits, setHits] = useState<SecretHit[]>([])
  const [error, setError] = useState('')
  // Первый ответ сервера получен: до него список не пуст, а неизвестен.
  const [ready, setReady] = useState(false)
  // Раскладка списка: что свернуто, что убрано с глаз, что поднято наверх.
  // Живет в браузере - см. projectList.ts.
  const [shutGroups, setShutGroups] = useState<string[]>(() => collapsedGroups())
  const [hidden, setHidden] = useState<string[]>(() => hiddenProjects())
  const [favs, setFavs] = useState<string[]>(() => favProjects())
  const [showHidden, setShowHidden] = useState(false)
  const [sort, setSort] = useState<SortMode>(() => sortMode())
  const [menu, setMenu] = useState<string | null>(null)

  useEscape(() => setMenu(null), menu !== null)

  const reload = useCallback(async () => {
    try {
      setProjects(await listProjects())
      // Серверы видит только ответственный и выше - для остальных счетчик
      // просто не появится, а не выдаст отказ на всю страницу.
      setServers(auth.isManager ? await listMachines().catch(() => []) : [])
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setReady(true)
    }
  }, [])

  useEffect(() => {
    void reload()
  }, [reload])

  // Минута: проекты меняются реже серверов, а список длинный.
  usePoll(reload, 60_000)

  useEffect(() => {
    const needle = filter.trim()
    if (needle.length < 2) {
      setHits([])
      return
    }
    // Ответ на прежний запрос, пришедший после нового, выбрасывается.
    let alive = true
    const timer = window.setTimeout(() => {
      searchSecrets(needle)
        .then((found) => alive && setHits(found))
        // Молча: поиск по ключам - подсказка, а не действие, и падать из-за
        // него всей странице незачем.
        .catch(() => alive && setHits([]))
    }, 300)
    return () => {
      alive = false
      window.clearTimeout(timer)
    }
  }, [filter])

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    if (!needle) return projects
    return projects.filter(
      (p) =>
        p.slug.toLowerCase().includes(needle) ||
        p.title.toLowerCase().includes(needle) ||
        p.group_name.toLowerCase().includes(needle) ||
        p.environments.some((e) => e.toLowerCase().includes(needle)),
    )
  }, [projects, filter])

  // Группы - обычные строки, а не отдельная сущность: они нужны, чтобы длинный
  // список читался, и заводить ради этого иерархию с правами было бы дорого.
  // Группы идут полосой, проекты - строками под ней. Плитки с плашками
  // окружений на сотне проектов превращались в кашу, а сплошной список без
  // полос сливался в одно полотно, где не видно, где кончается одна команда и
  // начинается другая.
  // Какие серверы забирают этот проект. Ключ окружения приходит как
  // "группа/проект/окружение", поэтому сравниваем по началу строки.
  const serversOf = (project: Project) => {
    const prefix = project.group_slug
      ? `${project.group_slug}/${project.slug}/`
      : `${project.slug}/`
    return servers.filter((s) => s.environments.some((e) => e.startsWith(prefix)))
  }

  // Пока ищут, раскладка не действует: "проект есть, но его не видно" - худший
  // ответ на набранное имя.
  const searching = filter.trim() !== ''

  // Порядок внутри группы. Имя - запасной ключ везде: без него проекты с
  // одинаковым числом ключей перескакивают с места на место при каждом ответе
  // сервера.
  const order = useCallback(
    (a: Project, b: Project) => {
      if (sort === 'keys') {
        return b.secret_count - a.secret_count || a.slug.localeCompare(b.slug)
      }
      if (sort === 'changed') {
        const x = a.last_change_at
        const y = b.last_change_at
        if (x && y && x !== y) return y.localeCompare(x)
        // Проект, где не правили ничего, - в конец: "давно не трогали" это
        // ответ, а "не трогали никогда" - пустая строка, и наверху ей не место.
        if (x !== y) return x ? -1 : 1
      }
      return a.slug.localeCompare(b.slug)
    },
    [sort],
  )

  const groups = useMemo(() => {
    const map = new Map<string, { name: string; items: Project[] }>()
    const put = (key: string, name: string, project: Project) => {
      const group = map.get(key) ?? { name, items: [] }
      group.items.push(project)
      map.set(key, group)
    }
    for (const project of visible) {
      const id = projectKey(project.group_slug, project.slug)
      // Архив - общий для всех ответ на "проекта больше нет", поэтому он
      // сильнее личной раскладки: закрытый проект лежит в архиве, даже если он
      // у кого-то в избранном.
      if (project.archived) {
        put(ARCHIVE, t('Архив'), project)
        continue
      }
      if (hidden.includes(id) && !searching && !showHidden) continue
      if (favs.includes(id)) {
        put(FAVOURITE, t('Избранное'), project)
        continue
      }
      // Ключ - кусок адреса, а не написание: "globex" и "Globex" ведут в
      // одно место.
      put(project.group_slug, project.group_name, project)
    }
    for (const group of map.values()) {
      group.items.sort(order)
    }
    const rank = (key: string) =>
      key === FAVOURITE ? 0 : key === ARCHIVE ? 3 : key ? 1 : 2
    return [...map.entries()]
      .map(([key, group]) => ({ key, ...group }))
      .sort((a, b) => rank(a.key) - rank(b.key) || a.name.localeCompare(b.name))
  }, [visible, favs, hidden, searching, showHidden, order, t])

  /** Свернута ли группа. Обычные группы открыты по умолчанию, архив - закрыт,
      поэтому в хранилище лежит не состояние, а отличие от него. */
  const shut = (key: string) => shutGroups.includes(key) !== (key === ARCHIVE)

  function flipGroup(key: string) {
    setShutGroups(toggleGroup(key))
  }

  function flipAll() {
    const keys = groups.map((group) => group.key)
    const next = keys.every(shut) ? [] : keys.filter((key) => key !== ARCHIVE)
    setCollapsedGroups(next)
    setShutGroups(next)
  }

  /** Убрать проект с глаз или вернуть. Только у себя: чужие списки не трогаем. */
  function flipHidden(id: string) {
    setHidden(toggleHidden(id))
  }

  function flipFav(id: string) {
    setFavs(toggleFav(id))
  }

  /** Закрыть проект или вернуть из архива. Это видно всем. */
  async function flipArchive(project: Project) {
    try {
      await updateProject(project.id, { archived: !project.archived })
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  // Сколько живых проектов человек убрал с глаз: строка внизу списка - это
  // единственный способ вспомнить, что они есть.
  const hiddenCount = useMemo(
    () =>
      projects.filter(
        (project) =>
          !project.archived && hidden.includes(projectKey(project.group_slug, project.slug)),
      ).length,
    [projects, hidden],
  )

  // Сводка - про то, чем панель управляет сейчас, поэтому архив в нее не
  // входит: иначе числа наверху не сходятся со списком под ними. Скрытое, наоборот,
  // считается: это раскладка одного браузера, а не состояние дел.
  const totals = useMemo(() => {
    const live = projects.filter((p) => !p.archived)
    return {
      projects: live.length,
      envs: live.reduce((sum, p) => sum + p.env_count, 0),
      secrets: live.reduce((sum, p) => sum + p.secret_count, 0),
      pending: live.reduce((sum, p) => sum + p.pending_count, 0),
    }
  }, [projects])

  async function add() {
    const answer = await ask({
      title: t('Новый проект'),
      submit: t('Создать'),
      fields: [
        {
          name: 'slug',
          label: t('Имя'),
          placeholder: 'billing-api',
          hint: t('строчные латинские буквы, цифры и дефис'),
        },
        {
          name: 'group',
          label: t('Группа'),
          type: 'combo',
          suggestions: projects.map((p) => p.group_name).filter(Boolean),
          placeholder: t('напр. Биллинг'),
          hint: t('имя проекта должно быть уникальным внутри группы, а не во всей панели'),
          optional: true,
        },
        {
          name: 'envs',
          label: t('Окружения'),
          // Один prod по умолчанию: у лендинга или внутреннего сервиса других
          // окружений нет, а создавались три, и лишние удаляли руками.
          value: 'prod',
          placeholder: 'prod',
          quick: ['dev', 'stage'],
          hint: t('через пробел или запятую'),
          optional: true,
        },
      ],
    })
    if (!answer) return
    const slug = answer.slug
    const group = answer.group
    const envs = answer.envs
      .split(/[\s,]+/)
      .map((name) => name.trim())
      .filter(Boolean)
    try {
      const created = await createProject(slug.trim(), '', group.trim(), envs)
      await reload()
      onOpen(created.group_slug, created.slug)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  // Хотя бы один агент отчитался за последний час: тогда число серверов в
  // сводке светится зеленым, а не стоит серым, как остальные.
  const fresh = servers.some((server) => server.last_seen_at && !staleClass(server.last_seen_at))

  // Закладки - только те, что панель все еще показывает: проект могли удалить
  // или отобрать доступ, и вести туда некуда.
  const kept = useMemo(() => {
    if (projects.length === 0) return []
    const known = new Set(projects.map((p) => `${p.group_slug}/${p.slug}`))
    return pins().filter((item) => known.has(`${item.group}/${item.slug}`))
  }, [projects])

  return (
    <div className="stack">
      <ErrorNote text={error} onClose={() => setError('')} />

      <div className="summary">
        <div className="summary-cell">
          <span className="summary-number">{totals.projects}</span>
          <span className="muted small">
            {plural(totals.projects, [t('проект'), t('проекта'), t('проектов')])}
          </span>
        </div>
        <div className="summary-cell">
          <span className="summary-number">{totals.envs}</span>
          <span className="muted small">
            {plural(totals.envs, [t('окружение'), t('окружения'), t('окружений')])}
          </span>
        </div>
        <div className="summary-cell">
          <span className="summary-number">{totals.secrets}</span>
          <span className="muted small">
            {plural(totals.secrets, [t('ключ'), t('ключа'), t('ключей')])}
          </span>
        </div>
        {auth.isManager && (
          // Кликается: серверы - это отдельный раздел, и попасть в него из
          // сводки естественнее, чем искать в меню под шестеренкой.
          <button className="summary-cell summary-link" onClick={onOpenServers}>
            <span className={`summary-number${fresh ? ' summary-ok' : ''}`}>
              {servers.length}
            </span>
            <span className="muted small">
              {plural(servers.length, [t('сервер'), t('сервера'), t('серверов')])}
            </span>
          </button>
        )}
        <div className="summary-cell">
          <span className={`summary-number${totals.pending ? ' summary-warn' : ''}`}>
            {totals.pending}
          </span>
          <span className="muted small">{t('ждут подтверждения')}</span>
        </div>
      </div>

      <div className="row-actions">
        <input
          style={{ flex: 1, minWidth: 200 }}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder={t('поиск по проектам, группам, окружениям и ключам')}
          autoFocus
        />
        {/* Порядок групп не меняется: он про то, как устроена команда. */}
        <select
          className="sort-pick"
          value={sort}
          title={t('Порядок')}
          onChange={(e) => {
            const next = e.target.value as SortMode
            setSort(next)
            setSortMode(next)
          }}
        >
          <option value="name">{t('по имени')}</option>
          <option value="changed">{t('по изменению')}</option>
          <option value="keys">{t('по ключам')}</option>
        </select>
        {groups.length > 1 && !searching && (
          <button className="ghost" onClick={flipAll}>
            {groups.map((group) => group.key).every(shut)
              ? t('Развернуть все')
              : t('Свернуть все')}
          </button>
        )}
        {auth.isOwner && <button onClick={add}>{t('Новый проект')}</button>}
      </div>

      {kept.length > 0 && !filter.trim() && (
        <div className="recent-row">
          <span className="muted small">{t('Закреплённые')}</span>
          {kept.map((item) => (
            <button
              key={`${item.group}/${item.slug}/${item.env}`}
              className="env-chip recent-chip"
              onClick={() => onOpen(item.group, item.slug, item.env)}
            >
              <span className="recent-project">{item.slug}</span>
              <span className="recent-env">{item.env}</span>
            </button>
          ))}
        </div>
      )}

      {hits.length > 0 && (
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">{t('Ключи')}</span>
            <span className="key-folder-count">{hits.length}</span>
          </div>
          {hits.map((hit) => (
            <button
              key={`${hit.group_slug}/${hit.project_slug}/${hit.environment}${hit.path}${hit.name}`}
              className="project-row project-row-hit"
              onClick={() => onOpen(hit.group_slug, hit.project_slug, hit.environment, hit.name)}
            >
              <span className="mono proj-name">
                <Mark text={hit.name} needle={filter} />
              </span>
              <span className="muted small proj-envs">
                {hit.project_title || hit.project_slug}/{hit.environment}
                {hit.path !== '/' && <span className="mono"> {hit.path}</span>}
              </span>
              <span className="chev">›</span>
            </button>
          ))}
        </section>
      )}

      {!ready ? (
        <Skeleton rows={5} />
      ) : projects.length === 0 ? (
        <div className="card empty">
          <p className="empty-title">
            {auth.isOwner ? t('Проектов пока нет') : t('Доступа пока нет')}
          </p>
          <p className="muted small">
            {auth.isOwner
              ? t('Проект — это приложение или сервис. Внутри у него окружения, а в окружении лежат ключи.')
              : t('Вам пока не выдали доступ ни к одному проекту.')}
          </p>
          {auth.isOwner && <button onClick={add}>{t('Новый проект')}</button>}
        </div>
      ) : groups.length === 0 ? (
        <div className="card empty">
          <p className="empty-title">{t('Ничего не нашлось')}</p>
          <p className="muted small">{t('Поиск идёт по имени проекта, группе и окружениям.')}</p>
        </div>
      ) : (
        <div className="project-groups">
        {groups.map((group) => {
          const closed = shut(group.key) && !searching
          const keys = group.items.reduce((sum, p) => sum + p.secret_count, 0)
          const waiting = group.items.reduce((sum, p) => sum + p.pending_count, 0)
          return (
          <section
            key={group.key || '—'}
            className={`key-folder${closed ? ' key-folder-shut' : ''}`}
          >
            {/* Полоса группы - кнопка: чужая команда сворачивается в одну
                строку и больше не занимает экран. В свернутой строке видно, что
                внутри, а ожидающие подтверждения не прячутся вместе с
                проектами. */}
            <button
              className="key-folder-head group-head"
              aria-expanded={!closed}
              onClick={() => flipGroup(group.key)}
            >
              <span className="caret">{closed ? '▸' : '▾'}</span>
              <span className="key-folder-name">{group.name || t('Без группы')}</span>
              <span className="key-folder-count">{group.items.length}</span>
              {closed && (
                <>
                  <span className="group-peek">
                    {group.items.map((p) => p.title || p.slug).join(' · ')}
                  </span>
                  {waiting > 0 && (
                    <span className="tag tag-wait">
                      {waiting} {t('на подтверждении')}
                    </span>
                  )}
                  <span className="group-keys muted small">
                    <span className="count-value">{keys}</span>{' '}
                    {plural(keys, [t('ключ'), t('ключа'), t('ключей')])}
                  </span>
                </>
              )}
            </button>

            {!closed &&
            group.items.map((project) => {
              const own = auth.isManager ? serversOf(project) : []
              const id = projectKey(project.group_slug, project.slug)
              const fav = favs.includes(id)
              const away = hidden.includes(id)
              return (
                <div
                  key={project.id}
                  className={`project-row${auth.isManager ? '' : ' project-row-slim'}${
                    away ? ' project-row-off' : ''
                  }`}
                  // Строка открывается и с клавиатуры: кнопкой её сделать
                  // нельзя, внутри свои кнопки-окружения.
                  role="button"
                  tabIndex={0}
                  onClick={() => onOpen(project.group_slug, project.slug)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      onOpen(project.group_slug, project.slug)
                    }
                  }}
                >
                  <span className="proj-name">
                    {/* Звезда видна у избранных всегда, у остальных - под
                        курсором: две сотни серых звезд это шум. */}
                    <button
                      type="button"
                      className={`proj-star${fav ? ' proj-star-on' : ''}`}
                      title={fav ? t('Убрать из избранного') : t('В избранное')}
                      onClick={(e) => {
                        e.stopPropagation()
                        flipFav(id)
                      }}
                    >
                      {fav ? '★' : '☆'}
                    </button>
                    <span className="project-name">
                      <Mark text={project.title || project.slug} needle={filter} />
                    </span>
                    {away && <span className="tag tag-muted">{t('скрыт')}</span>}
                    {project.pending_count > 0 && (
                      <span className="tag tag-wait">
                        {project.pending_count} {t('на подтверждении')}
                      </span>
                    )}
                  </span>

                  {/* Окружения мелкими плашками: строка через запятую читалась
                      как сплошной серый текст, и prod в ней терялся. Плашка
                      кликается сама - чаще всего человек идет не "в проект", а
                      в конкретное окружение. */}
                  <span className="proj-envs">
                    {project.environments.slice(0, 5).map((name) => (
                      <button
                        key={name}
                        type="button"
                        className={`env-chip${name === 'prod' ? ' env-chip-prod' : ''}`}
                        title={`${project.slug}/${name}`}
                        onClick={(e) => {
                          e.stopPropagation()
                          onOpen(project.group_slug, project.slug, name)
                        }}
                      >
                        {name}
                      </button>
                    ))}
                    {project.environments.length > 5 && (
                      <span className="env-chip env-chip-static">
                        +{project.environments.length - 5}
                      </span>
                    )}
                    {project.environments.length === 0 && (
                      <span className="muted small">{t('нет окружений')}</span>
                    )}
                  </span>

                  {auth.isManager && (
                    // Кто это забирает: точка состояния важнее имени - она
                    // отвечает, доехало ли до сервера то, что здесь лежит.
                    <span className="proj-servers muted small">
                      {own.slice(0, 2).map((server) => (
                        <span
                          key={server.id}
                          className="proj-server"
                          title={
                            server.last_seen_at
                              ? formatDateTime(server.last_seen_at)
                              : t('ещё не забирал')
                          }
                        >
                          <span
                            className={`sdot ${
                              server.last_seen_at && !staleClass(server.last_seen_at)
                                ? 'sdot-up'
                                : 'sdot-stale'
                            }`}
                          />
                          {server.name}
                        </span>
                      ))}
                      {own.length > 2 && <span>+{own.length - 2}</span>}
                    </span>
                  )}

                  <span className="proj-count muted small">
                    {/* Время правки - только когда по нему и сортируют: иначе это
                        еще один столбец, который читают один раз. */}
                    {sort === 'changed' && project.last_change_at && (
                      <>{formatAgo(project.last_change_at, lang)} · </>
                    )}
                    <span className="count-value">{project.secret_count}</span>{' '}
                    {plural(project.secret_count, [t('ключ'), t('ключа'), t('ключей')])}
                  </span>

                  <div
                    className="menu-wrap proj-menu"
                    onClick={(e) => e.stopPropagation()}
                    role="presentation"
                  >
                    <button
                      className="ghost small-btn"
                      aria-label={t('Меню')}
                      onClick={() => setMenu(menu === id ? null : id)}
                    >
                      ⋯
                    </button>
                    {menu === id && (
                      <>
                        <div className="menu-catcher" onClick={() => setMenu(null)} />
                        <div className="menu-pop menu-pop-right">
                          <button
                            className="menu-item"
                            onClick={() => {
                              setMenu(null)
                              flipHidden(id)
                            }}
                          >
                            {away ? t('Вернуть в список') : t('Скрыть у себя')}
                          </button>
                          {auth.isOwner && (
                            <button
                              className="menu-item"
                              onClick={() => {
                                setMenu(null)
                                void flipArchive(project)
                              }}
                            >
                              {project.archived ? t('Вернуть из архива') : t('В архив')}
                            </button>
                          )}
                        </div>
                      </>
                    )}
                  </div>
                </div>
              )
            })}
          </section>
          )
        })}
        </div>
      )}

      {/* Скрытое не должно пропадать бесследно: строка внизу - единственный
          способ вспомнить, что проекты убраны, и вернуть их. */}
      {hiddenCount > 0 && !searching && (
        <button className="ghost small-btn hidden-line" onClick={() => setShowHidden((v) => !v)}>
          {t('Скрыто')} {hiddenCount} · {showHidden ? t('спрятать') : t('показать')}
        </button>
      )}
    </div>
  )
}
