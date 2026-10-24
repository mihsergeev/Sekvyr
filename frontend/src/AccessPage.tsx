import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  addGroupMember,
  createGroup,
  createPolicy,
  deleteGroup,
  deletePolicy,
  listEnvironments,
  listGroups,
  listMachines,
  listPolicies,
  listProjects,
  listUsers,
  removeGroupMember,
  type Environment,
  type GroupRow,
  type Machine,
  type PanelUser,
  type PolicyRow,
  type Project,
} from './api'
import { useDialogs } from './Dialogs'
import { ErrorNote, Skeleton } from './Notes'
import { plural, useI18n } from './i18n'
import { Choice } from './PickInput'
import { useEscape } from './useEscape'
import { endOfDay, formatDate } from './time'

/* Раздел "Доступ": кто, где и что может.
 *
 * Права выдает только владелец панели, поэтому раздел ему и виден. Устроен так
 * же, как список проектов: разделы с полосой и счетчиком, в них компактные
 * строки. Строка права отвечает по порядку - кому, где, что можно, до какого
 * числа: её читают в тот момент, когда разбираются, почему у человека нет
 * доступа.
 */

const ACTIONS = ['list', 'read', 'write', 'delete', 'rotate', 'approve'] as const

// Серверу выдается только чтение - то же ограничение проверяет API и
// ops/selfcheck.py: изменяющих маршрутов в машинном контуре нет вовсе.
const MACHINE_ACTIONS: string[] = ['list', 'read']

// Наблюдателю - только смотреть. Лишнее API не выдаст, а через группу оно не
// подействует.
const VIEWER_ACTIONS: string[] = ['list', 'read']

// i18n
const ACTION_TITLES: Record<string, string> = {
  list: 'видеть ключи',
  read: 'читать значения',
  write: 'менять значения',
  delete: 'удалять ключи',
  rotate: 'менять ключ окружения',
  approve: 'подтверждать изменения',
}

// Короткие подписи для строки права: полными фразами семь действий занимали
// три строки, и прочесть их не получалось. Полная фраза остается в подсказке.
// i18n
const ACTION_SHORT: Record<string, string> = {
  list: 'видеть',
  read: 'читать',
  write: 'менять',
  delete: 'удалять',
  rotate: 'ключ окружения',
  approve: 'подтверждать',
}

// Со скольких прав список перестает читаться целиком.
const SEARCH_FROM = 8

export function AccessPage({
  onOpenServer,
}: {
  onOpenServer: (machine: { id: number; name: string }) => void
}) {
  const { t } = useI18n()
  const { ask, confirm } = useDialogs()
  const [policies, setPolicies] = useState<PolicyRow[]>([])
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [users, setUsers] = useState<PanelUser[]>([])
  const [projects, setProjects] = useState<Project[]>([])
  const [envs, setEnvs] = useState<Environment[]>([])
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')
  // Первый ответ сервера получен: до него список не пуст, а неизвестен.
  const [ready, setReady] = useState(false)
  // Выдача доступа - окном: форма на пол-страницы, а открывают её изредка.
  const [granting, setGranting] = useState(false)
  // Какое меню открыто: у права это его номер, у группы - минус её номер, у
  // сервера - строка "m" и номер.
  const [menu, setMenu] = useState<string | null>(null)

  // форма нового права
  const [subjectType, setSubjectType] = useState<'user' | 'group' | 'machine'>('user')
  const [machines, setMachines] = useState<Machine[]>([])
  const [subjectId, setSubjectId] = useState<number | ''>('')
  const [projectId, setProjectId] = useState<number | ''>('')
  const [envId, setEnvId] = useState<number | ''>('')
  const [pathPrefix, setPathPrefix] = useState('/')
  const [actions, setActions] = useState<string[]>(['list'])
  const [effect, setEffect] = useState('allow')
  const [expires, setExpires] = useState('')
  const [require2fa, setRequire2fa] = useState(false)

  useEscape(() => setMenu(null), menu !== null)
  useEscape(() => setGranting(false), granting && menu === null)

  const reload = useCallback(async () => {
    try {
      const [p, g, u, pr, m] = await Promise.all([
        listPolicies(),
        listGroups(),
        listUsers(),
        listProjects(),
        listMachines(),
      ])
      setPolicies(p)
      setGroups(g)
      setUsers(u)
      setProjects(pr)
      setMachines(m)
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

  useEffect(() => {
    // Окружение прежнего проекта при смене проекта сбрасываем: в списке его уже
    // нет, а в правило оно ушло бы. Ответ на прежний выбор, пришедший позже
    // нового, список не перетирает.
    setEnvId('')
    setEnvs([])
    if (projectId === '') return
    let alive = true
    listEnvironments(Number(projectId))
      .then((got) => {
        if (alive) setEnvs(got)
      })
      .catch(() => {
        if (alive) setEnvs([])
      })
    return () => {
      alive = false
    }
  }, [projectId])

  const subjects = useMemo(() => {
    if (subjectType === 'user') return users.map((u) => ({ id: u.id, name: u.username }))
    if (subjectType === 'machine') return machines.map((m) => ({ id: m.id, name: m.name }))
    return groups.map((g) => ({ id: g.id, name: g.name }))
  }, [subjectType, users, groups, machines])

  // Серверу выдается только чтение: изменяющих маршрутов в машинном контуре нет
  // вовсе, и галочка "запись" обещала бы то, что некому выполнить.
  const viewer =
    subjectType === 'user' && users.find((u) => u.id === subjectId)?.role === 'viewer'
  const allowedActions =
    subjectType === 'machine' ? MACHINE_ACTIONS : viewer ? VIEWER_ACTIONS : ACTIONS

  // Права ищут по тому, кому они выданы и на что: "кто может читать прод"
  // спрашивают чаще, чем листают весь список.
  const match = useCallback(
    (row: PolicyRow) => {
      const needle = filter.trim().toLowerCase()
      if (!needle) return true
      const hay = [
        row.subject_name,
        row.project_slug,
        row.environment_name,
        row.path_prefix,
        ...row.actions,
      ]
        .join(' ')
        .toLowerCase()
      return needle.split(/\s+/).every((part) => hay.includes(part))
    },
    [filter],
  )

  const human = policies.filter((p) => p.subject_type !== 'machine' && match(p))
  const byMachine = useMemo(() => {
    const known = new Set(machines.map((m) => m.id))
    const map = new Map<number, { id: number; name: string; gone: boolean; rows: PolicyRow[] }>()
    for (const policy of policies) {
      if (policy.subject_type !== 'machine') continue
      if (!match(policy)) continue
      const cell = map.get(policy.subject_id) ?? {
        id: policy.subject_id,
        name: policy.subject_name,
        // Сервер удалили, а право осталось: открывать некуда, остается отозвать.
        gone: !known.has(policy.subject_id),
        rows: [],
      }
      cell.rows.push(policy)
      map.set(policy.subject_id, cell)
    }
    return [...map.values()].sort((a, b) => Number(a.gone) - Number(b.gone) || a.name.localeCompare(b.name))
  }, [policies, machines, match])

  /** Разрешение без "видеть ключи" в панели бесполезно: читать или менять можно,
      а ключей не видно ни одного. Поэтому любое право тянет его за собой. Запрет
      не трогаем: там снять "видеть" и оставить "читать" - осмысленный выбор. */
  function withList(list: string[]): string[] {
    return list.some((x) => x !== 'list') && !list.includes('list') ? ['list', ...list] : list
  }

  function openGrant() {
    setSubjectType('user')
    setSubjectId('')
    setProjectId('')
    setEnvId('')
    setPathPrefix('/')
    // Видеть и читать: так выдают чаще всего - dev, stage, серверам. "Только
    // видеть" - осознанный выбор для прода, его и отмечают руками.
    setActions(['list', 'read'])
    setEffect('allow')
    setExpires('')
    setRequire2fa(false)
    setGranting(true)
  }

  async function add() {
    if (subjectId === '') return
    try {
      await createPolicy({
        subject_type: subjectType,
        subject_id: Number(subjectId),
        project_id: projectId === '' ? null : Number(projectId),
        environment_id: envId === '' ? null : Number(envId),
        path_prefix: pathPrefix.trim() || '/',
        actions,
        effect,
        // Дата приходит из поля типа date, то есть без времени: считаем концом
        // указанного дня, иначе "до 30 сентября" отключало бы доступ утром 30-го.
        // День - в зоне панели, в которой его потом и показывают.
        expires_at: expires ? endOfDay(expires) : '',
        require_2fa: require2fa,
      })
      setGranting(false)
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  // Отзыв и снятие запрета спрашивают: пункт меню стоит под рукой, а промах
  // мимо него молча менял, кто видит прод. Снятие запрета опаснее, чем
  // выглядит: оно не убирает доступ, а открывает его.
  async function remove(policy: PolicyRow) {
    const where = `${policy.project_slug || t('все проекты')}${
      policy.environment_name ? `/${policy.environment_name}` : ''
    }${policy.path_prefix !== '/' ? ` ${policy.path_prefix}` : ''}`
    const deny = policy.effect === 'deny'
    const yes = await confirm({
      title: deny
        ? t('Снять запрет для {name}?', { name: policy.subject_name })
        : t('Отозвать право у {name}?', { name: policy.subject_name }),
      text: deny
        ? t('{where}: доступ откроется в той мере, в какой его дают остальные права. Запрет больше не будет их перекрывать.', { where })
        : t('{where}: доступ пропадет сразу, вернуть его можно только выдав право заново.', { where }),
      submit: deny ? t('Снять запрет') : t('Отозвать'),
      danger: true,
    })
    if (!yes) return
    try {
      await deletePolicy(policy.id)
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  /** Снять все права одного человека, группы или сервера. */
  async function removeAllFor(subjectTypeOf: string, subjectIdOf: number, name: string) {
    const mine = policies.filter(
      (p) => p.subject_type === subjectTypeOf && p.subject_id === subjectIdOf,
    )
    const yes = await confirm({
      title: `${t('Отозвать все права')}: ${name}?`,
      text: `${t('Прав будет снято')}: ${mine.length}.`,
      submit: t('Отозвать всё'),
      danger: true,
    })
    if (!yes) return
    try {
      for (const policy of mine) {
        await deletePolicy(policy.id)
      }
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function addGroup() {
    const answer = await ask({
      title: t('Новая группа'),
      submit: t('Создать'),
      fields: [
        {
          name: 'name',
          label: t('Название группы'),
          placeholder: t('напр. Бэкенд'),
          hint: t('право, выданное группе, действует на всех её участников'),
        },
      ],
    })
    if (!answer) return
    try {
      await createGroup(answer.name.trim())
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function joinGroup(group: GroupRow) {
    const candidates = users.filter((u) => !group.members.includes(u.username))
    if (candidates.length === 0) return
    const answer = await ask({
      title: `${t('Кого добавить в группу')} ${group.name}`,
      submit: t('Добавить'),
      fields: [
        {
          name: 'user',
          label: t('Учётная запись'),
          type: 'select',
          options: candidates.map((c) => ({ value: c.username, label: c.username })),
          value: candidates[0]?.username ?? '',
        },
      ],
    })
    const user = candidates.find((c) => c.username === answer?.user)
    if (!user) return
    try {
      await addGroupMember(group.id, user.id)
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function leaveGroup(group: GroupRow, username: string) {
    const user = users.find((u) => u.username === username)
    if (!user) return
    // Крестик у имени - мелкая цель в ряду других имен: без вопроса промах
    // снимал с человека все права группы.
    const yes = await confirm({
      title: t('Убрать {user} из группы {group}?', { user: username, group: group.name }),
      text: t('Права, выданные группе, перестанут действовать на {user} сразу.', { user: username }),
      submit: t('Убрать'),
      danger: true,
    })
    if (!yes) return
    try {
      await removeGroupMember(group.id, user.id)
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const count = (subjectTypeOf: string, subjectIdOf: number) =>
    policies.filter((row) => row.subject_type === subjectTypeOf && row.subject_id === subjectIdOf).length

  return (
    <div className="stack">
      <ErrorNote text={error} onClose={() => setError('')} />

      <div className="row-actions">
        <h2 className="grow">{t('Доступ')}</h2>
        <button onClick={openGrant}>{t('Выдать доступ')}</button>
      </div>

      {ready && policies.length >= SEARCH_FROM && (
        <div className="row-actions">
          <input
            style={{ flex: 1, minWidth: 180 }}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder={t('поиск по кому выдано, проекту и окружению')}
          />
          {filter && (
            <span className="muted small search-count">
              {human.length + byMachine.length} {t('из')} {policies.length}
            </span>
          )}
        </div>
      )}

      {!ready ? (
        <Skeleton rows={4} />
      ) : (
        <>
          {policies.length === 0 && (
            <div className="card empty">
              <p className="empty-title">{t('Прав пока нет')}</p>
              <button onClick={openGrant}>{t('Выдать доступ')}</button>
            </div>
          )}

          {human.length > 0 && (
            <section className="key-folder">
              <div className="key-folder-head group-head">
                <span className="key-folder-name">{t('Люди и группы')}</span>
                <span className="key-folder-count">{human.length}</span>
              </div>
              <div className="access-list">
                {human.map((p) => (
                  <div
                    key={p.id}
                    className={`access-row access-policy${p.effect === 'deny' ? ' policy-deny' : ''}${
                      p.expired ? ' policy-expired' : ''
                    }`}
                  >
                    <span className="access-who">
                      <span className="project-name">{p.subject_name}</span>
                      {p.subject_type === 'group' && <span className="tag tag-muted">{t('группа')}</span>}
                      {p.effect === 'deny' && <span className="tag tag-deny">{t('запрет')}</span>}
                      {p.require_2fa && <span className="tag tag-muted">2FA</span>}
                    </span>
                    <span className="access-where">
                      {p.project_slug || t('все проекты')}
                      {p.environment_name && `/${p.environment_name}`}
                      {p.path_prefix !== '/' && <span className="mono muted"> {p.path_prefix}</span>}
                    </span>
                    <span className="policy-actions">
                      {/* Порядок наш, а не тот, в котором права легли в базу: от
                          "видеть" к "подтверждать" - так их и держат в голове. */}
                      {[...p.actions]
                        .sort((a, b) => ACTIONS.indexOf(a as never) - ACTIONS.indexOf(b as never))
                        .map((a) => (
                          <span key={a} className="env-chip env-chip-static" title={t(ACTION_TITLES[a] ?? a)}>
                            {t(ACTION_SHORT[a] ?? a)}
                          </span>
                        ))}
                    </span>
                    <span className="muted small access-until">
                      {p.expires_at ? `${t('до')} ${formatDate(p.expires_at)}` : t('бессрочно')}
                      {p.expired && ` · ${t('истекло')}`}
                    </span>
                    <div className="menu-wrap">
                      <button
                        className="ghost small-btn"
                        aria-label={t('Меню')}
                        onClick={() => setMenu(menu === `p${p.id}` ? null : `p${p.id}`)}
                      >
                        ⋯
                      </button>
                      {menu === `p${p.id}` && (
                        <>
                          <div className="menu-catcher" onClick={() => setMenu(null)} />
                          <div className="menu-pop menu-pop-right">
                            <button
                              className="menu-item menu-item-danger"
                              onClick={() => {
                                setMenu(null)
                                void remove(p)
                              }}
                            >
                              {p.effect === 'deny' ? t('Снять запрет') : t('Отозвать')}
                            </button>
                            {/* Уходит человек - прав у него обычно не одно, и
                                снимают их все. */}
                            {count(p.subject_type, p.subject_id) > 1 && (
                              <button
                                className="menu-item menu-item-danger"
                                onClick={() => {
                                  setMenu(null)
                                  void removeAllFor(p.subject_type, p.subject_id, p.subject_name)
                                }}
                              >
                                {t('Отозвать все права')}
                              </button>
                            )}
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {byMachine.length > 0 && (
            <section className="key-folder">
              <div className="key-folder-head group-head">
                <span className="key-folder-name">{t('Серверы')}</span>
                <span className="key-folder-count">{byMachine.length}</span>
              </div>
              <div className="access-list">
                {byMachine.map((machine) =>
                  machine.gone ? (
                    // Сервер удалили, а права остались: страницы у него нет,
                    // поэтому строка не ведет никуда, а в меню - отзыв.
                    <div key={machine.id} className="access-row access-server access-gone">
                      <span className="access-who">
                        <span className="project-name">{machine.name}</span>
                        <span className="tag tag-deny">{t('сервер удалён')}</span>
                      </span>
                      <span className="access-chips">
                        {machine.rows.map((row) => (
                          <span key={row.id} className="env-chip env-chip-static">
                            {row.project_slug}
                            {row.environment_name && `/${row.environment_name}`}
                          </span>
                        ))}
                      </span>
                      <span />
                      <div className="menu-wrap">
                        <button
                          className="ghost small-btn"
                          aria-label={t('Меню')}
                          onClick={() => setMenu(menu === `m${machine.id}` ? null : `m${machine.id}`)}
                        >
                          ⋯
                        </button>
                        {menu === `m${machine.id}` && (
                          <>
                            <div className="menu-catcher" onClick={() => setMenu(null)} />
                            <div className="menu-pop menu-pop-right">
                              <button
                                className="menu-item menu-item-danger"
                                onClick={() => {
                                  setMenu(null)
                                  void removeAllFor('machine', machine.id, machine.name)
                                }}
                              >
                                {t('Отозвать все права')}
                              </button>
                            </div>
                          </>
                        )}
                      </div>
                    </div>
                  ) : (
                    <button
                      key={machine.id}
                      className="access-row access-server access-link"
                      onClick={() => onOpenServer(machine)}
                    >
                      <span className="access-who">
                        <span className="project-name">{machine.name}</span>
                      </span>
                      <span className="access-chips">
                        {machine.rows.map((row) => (
                          <span key={row.id} className="env-chip env-chip-static">
                            {row.project_slug}
                            {row.environment_name && `/${row.environment_name}`}
                          </span>
                        ))}
                      </span>
                      <span className="muted small access-until">
                        {machine.rows.length}{' '}
                        {plural(machine.rows.length, [t('окружение'), t('окружения'), t('окружений')])}
                      </span>
                      <span className="chev">›</span>
                    </button>
                  ),
                )}
              </div>
            </section>
          )}

          <section className="key-folder">
            <div className="key-folder-head group-head">
              <span className="key-folder-name">{t('Группы')}</span>
              <span className="key-folder-count">{groups.length}</span>
              <span className="spacer" />
              <button className="ghost small-btn" onClick={addGroup}>
                {t('Новая группа')}
              </button>
            </div>
            {groups.length === 0 ? (
              <div className="muted small access-empty">{t('Групп пока нет')}</div>
            ) : (
              <div className="access-list">
                {groups.map((g) => (
                  <div key={g.id} className="access-row access-group">
                    <span className="access-who">
                      <span className="project-name">{g.name}</span>
                      <span className="muted small">
                        {g.members.length}{' '}
                        {plural(g.members.length, [t('человек'), t('человека'), t('человек')])}
                      </span>
                    </span>
                    <span className="access-chips">
                      {g.members.map((m) => (
                        <button
                          key={m}
                          className="env-chip access-member"
                          onClick={() => void leaveGroup(g, m)}
                          title={t('убрать из группы')}
                        >
                          {m} ✕
                        </button>
                      ))}
                    </span>
                    <button
                      className="ghost small-btn"
                      disabled={users.every((u) => g.members.includes(u.username))}
                      onClick={() => void joinGroup(g)}
                    >
                      {t('Добавить участника')}
                    </button>
                    <div className="menu-wrap">
                      <button
                        className="ghost small-btn"
                        aria-label={t('Меню')}
                        onClick={() => setMenu(menu === `g${g.id}` ? null : `g${g.id}`)}
                      >
                        ⋯
                      </button>
                      {menu === `g${g.id}` && (
                        <>
                          <div className="menu-catcher" onClick={() => setMenu(null)} />
                          <div className="menu-pop menu-pop-right">
                            <button
                              className="menu-item menu-item-danger"
                              onClick={async () => {
                                setMenu(null)
                                const yes = await confirm({
                                  title: t('Удалить группу?'),
                                  text: t('Вместе с ней уйдут и выданные ей права.'),
                                  submit: t('Удалить'),
                                  danger: true,
                                })
                                if (!yes) return
                                try {
                                  await deleteGroup(g.id)
                                  await reload()
                                } catch (e) {
                                  setError(e instanceof Error ? e.message : String(e))
                                }
                              }}
                            >
                              {t('Удалить')}
                            </button>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </>
      )}

      {granting && (
        <div className="modal-backdrop">
          <div className="card modal grant-modal stack">
            <h3>{t('Выдать доступ')}</h3>

            <div className="grant-grid">
              <label>
                {t('Кому')}
                <select
                  value={subjectType}
                  onChange={(e) => {
                    const next = e.target.value as 'user' | 'group' | 'machine'
                    setSubjectType(next)
                    setSubjectId('')
                    setActions(['list', 'read'])
                  }}
                >
                  <option value="user">{t('учётной записи')}</option>
                  <option value="group">{t('группе')}</option>
                  <option value="machine">{t('серверу')}</option>
                </select>
              </label>
              <label>
                {subjectType === 'user' ? t('Учётная запись') : subjectType === 'group' ? t('Группа') : t('Сервер')}
                {/* Серверов бывает сотня - тогда это поле ищет, а не листает. */}
                <Choice
                  value={subjectId === '' ? '' : String(subjectId)}
                  onChange={(next) => {
                    const id = next === '' ? '' : Number(next)
                    setSubjectId(id)
                    // Выбрали наблюдателя - лишние галочки снимаются сразу, а не
                    // отказом после нажатия "Выдать".
                    if (subjectType === 'user' && users.find((u) => u.id === id)?.role === 'viewer') {
                      setActions((prev) => prev.filter((a) => VIEWER_ACTIONS.includes(a)))
                    }
                  }}
                  options={[
                    { value: '', label: t('выберите') },
                    ...subjects.map((s) => ({ value: String(s.id), label: s.name })),
                  ]}
                />
              </label>

              <label>
                {t('Проект')}
                <Choice
                  value={projectId === '' ? '' : String(projectId)}
                  onChange={(next) => setProjectId(next === '' ? '' : Number(next))}
                  options={[
                    { value: '', label: t('все проекты') },
                    ...projects.map((p) => ({ value: String(p.id), label: p.title || p.slug })),
                  ]}
                />
              </label>
              <label>
                {t('Окружение')}
                <select
                  value={envId}
                  onChange={(e) => setEnvId(e.target.value === '' ? '' : Number(e.target.value))}
                  disabled={projectId === ''}
                >
                  <option value="">{t('все окружения')}</option>
                  {envs.map((e) => (
                    <option key={e.id} value={e.id}>
                      {e.name}
                    </option>
                  ))}
                </select>
              </label>

              <label>
                {t('Папка и ниже')}
                <input value={pathPrefix} onChange={(e) => setPathPrefix(e.target.value)} />
              </label>
              <label>
                {t('Действует до')}
                <input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
              </label>

              <label>
                {t('Тип')}
                <select
                  value={effect}
                  onChange={(e) => {
                    setEffect(e.target.value)
                    if (e.target.value === 'allow') setActions(withList)
                  }}
                >
                  <option value="allow">{t('разрешение')}</option>
                  <option value="deny">{t('запрет')}</option>
                </select>
              </label>
            </div>

            <div className="grant-actions">
              <span className="muted small">{t('Права')}</span>
              <div className="grant-checks">
                {allowedActions.map((a) => (
                  <label key={a} className="checkline">
                    <input
                      type="checkbox"
                      checked={actions.includes(a)}
                      // Пока отмечено что-то еще, "видеть ключи" не снимается:
                      // см. withList.
                      disabled={effect === 'allow' && a === 'list' && actions.some((x) => x !== 'list')}
                      onChange={(e) =>
                        setActions((prev) => {
                          if (!e.target.checked) return prev.filter((x) => x !== a)
                          const next = [...prev, a]
                          return effect === 'allow' ? withList(next) : next
                        })
                      }
                    />
                    {t(ACTION_TITLES[a])}
                  </label>
                ))}
              </div>
            </div>

            <label className="checkline">
              <input
                type="checkbox"
                checked={require2fa}
                onChange={(e) => setRequire2fa(e.target.checked)}
              />
              {t('только со включённым вторым фактором')}
            </label>

            <div className="row-actions dialog-actions">
              <button className="ghost" onClick={() => setGranting(false)}>
                {t('Отмена')}
              </button>
              <button onClick={add} disabled={subjectId === '' || actions.length === 0}>
                {t('Выдать доступ')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
