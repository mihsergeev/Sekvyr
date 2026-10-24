import { useCallback, useEffect, useState } from 'react'
import {
  adoptCluster,
  adoptMachine,
  agentLatest,
  attachEnvironment,
  deleteMachine,
  deletePolicy,
  listAllEnvironments,
  listClusters,
  listMachines,
  listPolicies,
  listProjects,
  rotateMachineSecret,
  updateMachine,
  type Machine,
  type MachineApp,
  type PolicyRow,
  type Project,
} from './api'
import { useAuth } from './auth'
import { useDialogs } from './Dialogs'
import { formatAgo, formatDate, formatDateTime, staleClass } from './time'
import { CountryFlag } from './CountryFlag'
import { ErrorNote } from './Notes'
import { OsIcon } from './osIcon'
import { ServerAddr } from './ServerAddr'
import { useI18n } from './i18n'
import type { View } from './router'
import { usePoll } from './usePoll'
import { useEscape } from './useEscape'
import { newerVersion } from './version'

/* Один сервер целиком: что ему выдано и что он на самом деле забирает.
 *
 * Раньше это лежало в двух разных разделах: приложения - в списке серверов,
 * права - в "Доступе", где одна машина повторялась столько раз, сколько у нее
 * приложений. Вопрос при этом задают один: "что подключено к этой машине".
 */

// i18n
const ACTION_TITLES: Record<string, string> = {
  list: 'видеть ключи',
  read: 'читать значения',
}

// i18n
const ACTION_SHORT: Record<string, string> = {
  list: 'видеть',
  read: 'читать',
}

/* Обычное право агента: видеть ключи и читать значения - без этого он не
   заберет окружение. Такой набор стоит у всех строк подряд и потому ничего о
   строке не говорит; показываем права, только когда они другие. */
const USUAL = ['list', 'read']

function plain(actions: string[]): boolean {
  return actions.length === USUAL.length && USUAL.every((a) => actions.includes(a))
}

/** Строка списка: одно окружение - право на него и приложение, которое его берет. */
type Row = {
  key: string
  /** "acme/worker/prod" или "весь проект api". */
  where: string
  policy?: PolicyRow
  app?: MachineApp
  /** Доступ есть, но своей строки права у него здесь нет: право шире (на весь
      проект) или списка прав этому человеку не видно. */
  granted?: boolean
}

/** Проект так, как его называет агент: "группа/проект" или просто "проект". */
function projectName(policy: PolicyRow, projects: Project[]): string {
  const project = projects.find((p) => p.id === policy.project_id)
  if (!project) return policy.project_slug
  return project.group_slug ? `${project.group_slug}/${project.slug}` : project.slug
}

/* Право знает проект по номеру, агент отчитывается полным именем с группой.
   Сравниваются имена целиком: по хвосту право на web/prod цеплялось к
   приложению admin-web/prod и к одноименному проекту из другой группы, а
   настоящее web/prod при этом получало ложное "права нет". Пока список
   проектов не пришел, группу взять неоткуда, и хвост сверяется по границе "/". */
function matches(app: MachineApp, policy: PolicyRow, projects: Project[]): boolean {
  if (!policy.environment_name) return false
  const full = `${projectName(policy, projects)}/${policy.environment_name}`
  if (projects.some((p) => p.id === policy.project_id)) return app.environment === full
  return app.environment === full || app.environment.endsWith(`/${full}`)
}

/** Приложение под действующим правом на весь проект или на все проекты. */
function coveredWide(app: MachineApp, policies: PolicyRow[], projects: Project[]): boolean {
  const parts = app.environment.split('/')
  const appProject = parts.slice(0, -1).join('/')
  return policies.some((policy) => {
    if (policy.effect !== 'allow' || policy.expired || policy.environment_name) return false
    if (policy.project_id === null) return true
    if (projects.some((p) => p.id === policy.project_id)) {
      return appProject === projectName(policy, projects)
    }
    return parts.length >= 2 && parts[parts.length - 2] === policy.project_slug
  })
}

/** Куда ведет строка подключения. null - проекта этому человеку не видно:
    ссылка на "не найдено" хуже, чем её отсутствие. */
function target(row: Row, projects: Project[]): View | null {
  const policy = row.policy
  if (policy) {
    const project = projects.find((p) => p.id === policy.project_id)
    if (!project) return null
    return policy.environment_name
      ? {
          kind: 'env',
          group: project.group_slug,
          slug: project.slug,
          env: policy.environment_name,
        }
      : { kind: 'project', group: project.group_slug, slug: project.slug }
  }
  const named = row.app?.environment ?? (row.granted ? row.where : '')
  if (named) {
    // Строка без своего права: агент отчитывается полным именем, и карточка
    // сервера перечисляет выданное так же - "группа/проект/стенд" или
    // "проект/стенд".
    const parts = named.split('/')
    const env = parts.pop() ?? ''
    const slug = parts.pop() ?? ''
    const group = parts.pop() ?? ''
    const project = projects.find((p) => p.slug === slug && p.group_slug === group)
    if (project && env) return { kind: 'env', group, slug, env }
  }
  return null
}

function build(
  machine: Machine,
  policies: PolicyRow[],
  all: string,
  projects: Project[],
  known: boolean,
): Row[] {
  const rows: Row[] = []
  const used = new Set<string>()
  const apps = machine.apps || []

  if (known) {
    for (const policy of policies) {
      const app = apps.find((a) => matches(a, policy, projects))
      if (app) used.add(app.environment)
      const base = projectName(policy, projects)
      rows.push({
        key: `p${policy.id}`,
        where: policy.environment_name ? `${base}/${policy.environment_name}` : base || all,
        policy,
        app,
      })
    }
  } else {
    // Список прав отдают только владельцу панели. Ответственному выданное
    // берется из карточки сервера: там те же права, уже полными именами.
    // Раньше вместо этого все приложения помечались "права нет".
    for (const name of machine.environments) {
      const app = apps.find((a) => a.environment === name)
      if (app) used.add(app.environment)
      rows.push({ key: `e${name}`, where: name, app, granted: true })
    }
  }

  // Приложение без права: агент его записал, а политику потом отозвали. Файл на
  // сервере при этом остается, а обновляться перестает - молчать об этом нельзя.
  // Право на весь проект своей строки окружения не дает, но приложение под ним
  // живое.
  for (const app of apps) {
    if (used.has(app.environment)) continue
    rows.push({
      key: `a${app.environment}`,
      where: app.environment,
      app,
      granted: known ? coveredWide(app, policies, projects) : undefined,
    })
  }
  return rows
}

export function ServerPage({
  name,
  id,
  onBack,
  onGo,
}: {
  name: string
  /** Номер из адреса. Имя не уникально, поэтому ищем по номеру, а имя - для
      старых ссылок, где номера еще не было. */
  id?: number
  onBack: () => void
  onGo: (view: View) => void
}) {
  const { t, lang } = useI18n()
  const auth = useAuth()
  const { ask, confirm, notify } = useDialogs()
  const [machine, setMachine] = useState<Machine | null>(null)
  const [policies, setPolicies] = useState<PolicyRow[]>([])
  // Виден ли список прав: без него нельзя утверждать, что у приложения права нет.
  const [known, setKnown] = useState(false)
  // Проекты - только ради группы в адресе стенда: имя проекта уникально
  // внутри группы, а не по всей панели.
  const [projects, setProjects] = useState<Project[]>([])
  const [missing, setMissing] = useState(false)
  const [error, setError] = useState('')
  const [menu, setMenu] = useState<string | null>(null)
  // Версия агента, которую панель раздает: без нее "0.25.0" в заголовке
  // ничего не говорит - свежая она или полугодовой давности.
  const [latest, setLatest] = useState('')

  useEscape(() => setMenu(null), menu !== null)

  const reload = useCallback(async () => {
    try {
      const rows = await listMachines()
      const found = rows.find((m) => (id ? m.id === id : m.name === name)) ?? null
      setMachine(found)
      setMissing(!found)
      if (found) {
        // Права машин видит только владелец панели; управляющему список просто
        // не отдадут, и страница должна остаться рабочей без него.
        try {
          const all = await listPolicies()
          setPolicies(all.filter((p) => p.subject_type === 'machine' && p.subject_id === found.id))
          setKnown(true)
        } catch {
          setPolicies([])
          setKnown(false)
        }
      }
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [name, id])

  useEffect(() => {
    void reload()
  }, [reload])

  useEffect(() => {
    void agentLatest().then(setLatest)
    void listProjects()
      .then(setProjects)
      .catch(() => setProjects([]))
  }, [])

  usePoll(reload, 30_000)

  async function attach() {
    if (!machine) return
    try {
      const environments = await listAllEnvironments()
      if (environments.length === 0) {
        await notify(t('Подключить приложение'), t('Сначала заведите проект с окружением.'))
        return
      }
      const answer = await ask({
        title: t('Подключить приложение'),
        text: t('Панель выдаст серверу это окружение и покажет команду, которой оно добавляется агенту.'),
        submit: t('Подключить'),
        fields: [
          {
            name: 'env',
            label: t('Окружение'),
            type: 'select',
            options: environments.map((e) => ({
              value: String(e.id),
              label: `${e.group_slug ? e.group_slug + '/' : ''}${e.project_slug}/${e.name}`,
            })),
            value: String(environments[0].id),
          },
        ],
      })
      if (!answer) return
      const result = await attachEnvironment(machine.id, Number(answer.env))
      await notify(
        t('Выполните на сервере'),
        [
          result.command,
          '',
          `${t('Окружение')}: ${result.environment}`,
          result.granted ? t('Доступ выдан.') : t('Доступ уже был выдан раньше.'),
          // Срок права машины: не дольше, чем доступ того, кто подключает.
          ...(result.expires_at ? [`${t('Доступ действует до')} ${formatDateTime(result.expires_at)}`] : []),
          t('Каталог приложения должен совпадать с именем проекта: /app/<проект>/compose.yml'),
        ].join('\n'),
      )
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function toggle() {
    if (!machine) return
    try {
      await updateMachine(machine.id, { disabled: !machine.disabled })
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function rotate() {
    if (!machine) return
    const yes = await confirm({
      title: t('Сменить секрет?'),
      text: t('Прежний секрет и все выданные по нему токены перестанут работать сразу.'),
      submit: t('Сменить'),
    })
    if (!yes) return
    try {
      const fresh = await rotateMachineSecret(machine.id)
      await reload()
      await notify(
        t('Секрет сервера'),
        `${t('Идентификатор')}: ${fresh.client_id}\n${t('Секрет')}: ${fresh.client_secret}\n\n${t('Секрет показывается один раз — сохраните его сейчас.')}`,
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  /** Забрать сервер (или кластер его пода) на себя: доступ держится на том,
      кто завел и выдал, и встает, когда его отключают или понижают. */
  async function adopt(whole: boolean) {
    if (!machine) return
    const yes = await confirm({
      title: whole ? t('Забрать кластер на себя?') : t('Забрать сервер на себя?'),
      text: whole
        ? t('Кластер, личности его подов и выданные им права будут держаться на вас. Можно, только если вы сами читаете все, что они получают.')
        : t('Сервер и выданные ему права будут держаться на вас. Можно, только если вы сами читаете все, что он получает.'),
      submit: t('Забрать'),
    })
    if (!yes) return
    try {
      if (whole) {
        const cluster = (await listClusters()).find((c) => c.name === machine.cluster)
        if (!cluster) return
        await adoptCluster(cluster.id)
      } else {
        await adoptMachine(machine.id)
      }
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function remove() {
    if (!machine) return
    const answer = await ask({
      title: t('Удалить сервер?'),
      text: t('Вместе с ней исчезнут её права. Записи в журнале останутся.'),
      submit: t('Удалить'),
      danger: true,
      fields: [{ name: 'confirm', label: t('Введите имя сервера'), placeholder: machine.name }],
    })
    if (!answer) return
    try {
      await deleteMachine(machine.id, answer.confirm.trim())
      onBack()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function revoke(policy: PolicyRow) {
    const yes = await confirm({
      title: t('Отозвать доступ?'),
      text: t('Сервер перестанет получать это окружение при следующем обращении. Файл, который уже лежит на нём, останется.'),
      submit: t('Отозвать'),
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

  /** Снять с сервера все выданные окружения разом. */
  async function revokeAll() {
    const live = rows.map((row) => row.policy).filter(Boolean) as PolicyRow[]
    if (live.length === 0) return
    const yes = await confirm({
      title: t('Отозвать все доступы?'),
      text: `${t('Прав будет снято')}: ${live.length}. ${t('Сервер перестанет получать эти окружения при следующем обращении. Файлы, которые уже лежат на нём, останутся.')}`,
      submit: t('Отозвать всё'),
      danger: true,
    })
    if (!yes) return
    try {
      // По одному: пакетной ручки у панели нет, зато каждая правка попадает в
      // журнал отдельной записью - так же, как при отзыве руками.
      for (const policy of live) {
        await deletePolicy(policy.id)
      }
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  if (missing) {
    return (
      <div className="stack">
        <div className="card empty">
          <p className="empty-title">{t('Такого сервера нет')}</p>
          <p className="muted small">{name}</p>
          <button onClick={onBack}>{t('К списку серверов')}</button>
        </div>
      </div>
    )
  }

  if (!machine) {
    return (
      <div className="stack">
        <ErrorNote text={error} onClose={() => setError('')} />
      </div>
    )
  }

  const fresh = machine.last_seen_at && !staleClass(machine.last_seen_at)
  const behind = Boolean(
    latest && machine.agent_version && newerVersion(latest, machine.agent_version),
  )
  const rows = build(machine, policies, t('все проекты'), projects, known)

  return (
    <div className="stack">
      <ErrorNote text={error} onClose={() => setError('')} />

      <div className="server-title">
        <span
          className={`sdot${machine.disabled ? ' sdot-off' : fresh ? ' sdot-up' : ' sdot-stale'}`}
        />
        <OsIcon os={machine.os} size={16} />
        <CountryFlag code={machine.country} />
        <h2>{machine.name}</h2>
        {machine.disabled && <span className="tag tag-muted">{t('выключен')}</span>}
        {machine.cluster && <span className="tag tag-muted">{machine.cluster}</span>}
        <span className="spacer" />
        <span className="muted small">
          {machine.last_seen_at ? (
            <span className={staleClass(machine.last_seen_at)}>
              {formatAgo(machine.last_seen_at, lang)}
            </span>
          ) : (
            t('ещё не забирал')
          )}
          {machine.agent_version &&
            (behind ? (
              <>
                {` · ${t('агент')} `}
                <span
                  className="stale-warn"
                  title={`${t('панель раздаёт')} ${latest} — ${t('агент обновится сам')}`}
                >
                  {machine.agent_version}
                </span>
              </>
            ) : (
              ` · ${t('агент')} ${machine.agent_version}`
            ))}
        </span>
        {auth.isManager && (
          <>
            <button onClick={() => void attach()}>{t('Подключить приложение')}</button>
            <div className="menu-wrap">
              <button
                className="ghost icon-btn"
                aria-label={t('Меню')}
                onClick={() => setMenu(menu === 'machine' ? null : 'machine')}
              >
                ⋯
              </button>
              {menu === 'machine' && (
                <>
                  <div className="menu-catcher" onClick={() => setMenu(null)} />
                  <div className="menu-pop menu-pop-right">
                    <div className="menu-head mono">
                      {machine.cluster
                        ? `${machine.k8s_namespace}/${machine.k8s_service_account}`
                        : machine.client_id}
                    </div>
                    <button
                      className="menu-item"
                      onClick={() => {
                        setMenu(null)
                        void toggle()
                      }}
                    >
                      {machine.disabled ? t('Включить') : t('Выключить')}
                    </button>
                    {auth.isOwner && rows.some((row) => row.policy) && (
                      <button
                        className="menu-item menu-item-danger"
                        onClick={() => {
                          setMenu(null)
                          void revokeAll()
                        }}
                      >
                        {t('Отозвать все доступы')}
                      </button>
                    )}
                    {!machine.cluster && (
                      <button
                        className="menu-item"
                        onClick={() => {
                          setMenu(null)
                          void rotate()
                        }}
                      >
                        {t('Сменить секрет')}
                      </button>
                    )}
                    {(machine.stalled || machine.created_by !== auth.username) && (
                      <button
                        className="menu-item"
                        onClick={() => {
                          setMenu(null)
                          void adopt(false)
                        }}
                      >
                        {t('Забрать на себя')}
                      </button>
                    )}
                    {machine.cluster && (
                      <button
                        className="menu-item"
                        onClick={() => {
                          setMenu(null)
                          void adopt(true)
                        }}
                      >
                        {t('Забрать кластер на себя')}
                      </button>
                    )}
                    <button
                      className="menu-item menu-item-danger"
                      onClick={() => {
                        setMenu(null)
                        void remove()
                      }}
                    >
                      {t('Удалить сервер')}
                    </button>
                  </div>
                </>
              )}
            </div>
          </>
        )}
      </div>

      {/* Что это за машина: адреса и система. Строкой под именем, потому что
          спрашивают это раньше, чем "какие права выданы". */}
      {(machine.last_ip || machine.local_ip || machine.os) && (
        <p className="server-facts">
          <ServerAddr external={machine.last_ip} local={machine.local_ip} />
          {machine.os && <span className="muted small">{machine.os}</span>}
        </p>
      )}

      {machine.description && <p className="muted small">{machine.description}</p>}

      {/* Доступ сервера держится на людях: на том, кто его завел, завел его
          кластер или выдал права. Отключили или понизили человека - сервер
          перестает получать выданное им, и об этом надо сказать здесь, а не
          ждать, пока заметят по упавшему приложению. */}
      {machine.stalled && (
        <p className="small stale-warn">
          {t('Часть выданного не действует: тот, кто завел сервер, его кластер или выдал доступ, отключен, понижен или сам больше этого не читает.')}{' '}
          {auth.isManager && t('Заберите сервер на себя, чтобы он снова получал значения.')}
        </p>
      )}

      {rows.length === 0 ? (
        <div className="card empty">
          <p className="empty-title">{t('Ничего не подключено')}</p>
          <p className="muted small">
            {t('«Подключить приложение» выдаст серверу окружение и покажет команду, которой оно добавляется агенту.')}
          </p>
          {auth.isManager && (
            <button onClick={() => void attach()}>{t('Подключить приложение')}</button>
          )}
        </div>
      ) : (
        <div className="conns">
          {rows.map((row) => {
            const to = target(row, projects)
            const orphan = known && !row.policy && !row.granted
            return (
              <div key={row.key} className={`card conn${orphan ? ' conn-orphan' : ''}`}>
                <div className="conn-head">
                  <span
                    className={`key-dot${row.app ? ' conn-dot-live' : ''}`}
                    title={row.app ? t('агент забирает') : t('выдано, но не забирается')}
                  />
                  {/* Имя стенда - переход в него: на страницу сервера
                      приходят посмотреть, что он забирает, и тут же правят
                      ключ. */}
                  {to ? (
                    <button className="conn-link project-name" onClick={() => onGo(to)}>
                      {row.where}
                      <span className="chev">›</span>
                    </button>
                  ) : (
                    <span className="project-name">{row.where}</span>
                  )}
                  {row.app?.path && <span className="mono muted small">{row.app.path}</span>}
                  <span className="spacer" />
                  {row.policy?.expires_at && (
                    <span className={`small ${row.policy.expired ? 'stale-warn' : 'muted'}`}>
                      {t('до')} {formatDate(row.policy.expires_at)}
                    </span>
                  )}
                  {auth.isOwner && row.policy && (
                    <div className="menu-wrap">
                      <button
                        className="ghost small-btn"
                        aria-label={t('Меню')}
                        onClick={() => setMenu(menu === row.key ? null : row.key)}
                      >
                        ⋯
                      </button>
                      {menu === row.key && (
                        <>
                          <div className="menu-catcher" onClick={() => setMenu(null)} />
                          <div className="menu-pop menu-pop-right">
                            <button
                              className="menu-item menu-item-danger"
                              onClick={() => {
                                setMenu(null)
                                void revoke(row.policy as PolicyRow)
                              }}
                            >
                              {t('Отозвать доступ')}
                            </button>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>

                <div className="conn-body">
                  {row.policy ? (
                    plain(row.policy.actions) ? null : (
                      <span className="policy-actions">
                        {row.policy.actions.map((a) => (
                          <span
                            key={a}
                            className="env-chip env-chip-static"
                            title={t(ACTION_TITLES[a] ?? a)}
                          >
                            {t(ACTION_SHORT[a] ?? a)}
                          </span>
                        ))}
                      </span>
                    )
                  ) : orphan ? (
                    <span className="small stale-warn">
                      {t('права нет — файл больше не обновляется')}
                    </span>
                  ) : known && row.granted ? (
                    <span className="muted small">{t('по праву на весь проект')}</span>
                  ) : null}
                  {row.app ? (
                    <span className="muted small">
                      {t('обновлено')} {formatAgo(row.app.last_seen_at, lang)}
                    </span>
                  ) : (
                    <span className="muted small">{t('не используется')}</span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
