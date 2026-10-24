import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  agentLatest,
  createCluster,
  createEnrollToken,
  createMachine,
  deleteCluster,
  listClusters,
  listEnvironments,
  listMachines,
  listProjects,
  updateCluster,
  type Cluster,
  type Machine,
} from './api'
import { useAuth } from './auth'
import { useDialogs } from './Dialogs'
import { endOfDay, formatAgo, formatDateTime, staleClass } from './time'
import { CountryFlag } from './CountryFlag'
import { ErrorNote, Skeleton } from './Notes'
import { OsIcon } from './osIcon'
import { ServerAddr } from './ServerAddr'
import { useI18n } from './i18n'
import { usePoll } from './usePoll'
import { useEscape } from './useEscape'
import { newerVersion } from './version'

/* Серверы: ноды, сборки и кластеры, которые забирают секреты сами.
 *
 * Список отвечает на один вопрос - какие серверы есть и живы ли они. Все
 * остальное (что подключено, права, секрет, удаление) живет на странице
 * самого сервера: в строке списка это не помещалось, а кнопки в каждой строке
 * занимали её треть.
 */

// Выданное, но не забираемое: права есть, а приложения на сервере нет. Чаще
// всего это забытый шаг "sekvyr add", и увидеть его лучше здесь, чем гадать,
// почему на сервере нет файла.
function granted(machine: Machine): string[] {
  const taken = new Set((machine.apps || []).map((app) => app.environment))
  return machine.environments.filter((name) => !taken.has(name))
}

/** Сервер без приложений и выданных окружений: агент стоит и ждет. В панель
    он ходит только за приложениями, поэтому его "давно не был" - не молчание. */
function bare(machine: Machine): boolean {
  return machine.environments.length === 0 && (machine.apps?.length ?? 0) === 0
}

/** Сервер молчит дольше положенного (и это не выключенная машина). */
function silent(machine: Machine): boolean {
  if (machine.disabled || bare(machine)) return false
  return !machine.last_seen_at || Boolean(staleClass(machine.last_seen_at))
}

// Со скольких серверов список перестает читаться целиком и начинает искаться.
const SEARCH_FROM = 6

export function ServersPage({
  onOpen,
}: {
  onOpen: (machine: { id: number; name: string }) => void
}) {
  const { t, lang } = useI18n()
  const auth = useAuth()
  const { ask, notify } = useDialogs()
  const [rows, setRows] = useState<Machine[]>([])
  const [clusters, setClusters] = useState<Cluster[]>([])
  const [error, setError] = useState('')
  // Первый ответ сервера получен: до него список не пуст, а неизвестен.
  const [ready, setReady] = useState(false)
  const [menu, setMenu] = useState(false)
  const [filter, setFilter] = useState('')
  // Отбор, а не сортировка: спрашивают "кто отвалился" и "кто ничего не
  // забирает", и это два разных разговора.
  const [kind, setKind] = useState<'all' | 'silent' | 'idle' | 'old'>('all')
  // Версия агента, которую панель раздает. Пусто - версия не подписана, и
  // сравнивать не с чем.
  const [latest, setLatest] = useState('')

  useEscape(() => setMenu(false), menu)

  const reload = useCallback(async () => {
    try {
      setRows(await listMachines())
      setClusters(await listClusters())
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
    void agentLatest().then(setLatest)
  }, [])

  // Полминуты: агент отчитывается раз в минуту, чаще обновлять нечего.
  usePoll(reload, 30_000)

  /** Агент старее той версии, которую панель раздает. */
  const outdated = useCallback(
    (machine: Machine) =>
      Boolean(latest && machine.agent_version && newerVersion(latest, machine.agent_version)),
    [latest],
  )

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    const parts = needle ? needle.split(/\s+/) : []
    return rows.filter((machine) => {
      if (kind === 'silent' && !silent(machine)) return false
      if (kind === 'idle' && (machine.apps?.length ?? 0) > 0) return false
      if (kind === 'old' && !outdated(machine)) return false
      if (parts.length === 0) return true
      // Ищем по всему, что видно в карточке, и по тому, что за ней стоит:
      // адрес, система, выданные окружения. Имя сервера человек помнит не
      // всегда, а "тот, что забирает api/prod" - почти всегда.
      const hay = [
        machine.name,
        machine.description,
        machine.last_ip,
        machine.local_ip,
        machine.os,
        machine.cluster,
        ...(machine.apps || []).map((app) => app.environment),
        ...machine.environments,
      ]
        .join(' ')
        .toLowerCase()
      return parts.every((part) => hay.includes(part))
    })
  }, [rows, filter, kind, outdated])

  // Подключение сервера одной командой: панель создает одноразовый токен и
  // показывает готовую строку. Токен действует четверть часа и годен на одно
  // подключение - переслать его "на всякий случай" бесполезно.
  async function connect() {
    let projects: { id: number; slug: string; group_name: string }[] = []
    try {
      projects = await listProjects()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      return
    }
    const chosen = await ask({
      title: t('Подключить сервер'),
      // Без проекта спрашивать больше нечего: токен создается сразу.
      submit: (v) => (v.bare ? t('Создать токен') : t('Дальше')),
      fields: [
        // Сервер можно подключить и без проекта: агент встанет и будет ждать, а
        // приложения добавляются потом со страницы сервера. Галочка стоит над
        // выбором: под ней он прячется, и сама она под курсором не прыгает.
        {
          name: 'bare',
          label: t('Без проекта'),
          type: 'check',
          optional: true,
          value: projects.length > 0 ? '' : '1',
        },
        {
          name: 'project',
          label: t('Проект'),
          type: 'select',
          options: projects.map((p) => ({
            value: String(p.id),
            label: p.group_name ? `${p.group_name} / ${p.slug}` : p.slug,
          })),
          value: projects[0] ? String(projects[0].id) : '',
          hide: (v) => Boolean(v.bare),
        },
        {
          name: 'minutes',
          label: t('Срок действия токена, минут'),
          value: '15',
          hint: t('действует на одно подключение'),
          check: (v) =>
            /^\d+$/.test(v.trim()) && Number(v) >= 1 && Number(v) <= 1440
              ? ''
              : t('от 1 до 1440 минут'),
          hide: (v) => !v.bare,
        },
      ],
    })
    if (!chosen) return
    if (chosen.bare) {
      await connectBare(Number(chosen.minutes) || 15)
      return
    }
    const envs = await listEnvironments(Number(chosen.project)).catch(() => [])
    if (envs.length === 0) {
      await notify(t('Подключить сервер'), t('У проекта нет окружений.'))
      return
    }
    const second = await ask({
      title: t('Подключить сервер'),
      submit: t('Создать токен'),
      fields: [
        {
          name: 'env',
          label: t('Окружение'),
          type: 'select',
          options: envs.map((e) => ({ value: String(e.id), label: e.name })),
          value: String(envs[0].id),
        },
        {
          name: 'minutes',
          label: t('Срок действия токена, минут'),
          value: '15',
          hint: t('действует на одно подключение'),
          check: (v) =>
            /^\d+$/.test(v.trim()) && Number(v) >= 1 && Number(v) <= 1440
              ? ''
              : t('от 1 до 1440 минут'),
        },
      ],
    })
    if (!second) return
    try {
      const ticket = await createEnrollToken({
        environment_id: Number(second.env),
        minutes: Number(second.minutes) || 15,
        lang,
      })
      await notify(
        t('Выполните на сервере'),
        [
          t('1. Новый сервер — подключение, агент и приложение одной командой:'),
          ticket.command,
          '',
          // Второй случай встречается чаще первого: сервер уже подключен, а
          // приложение на нем новое. Второго агента при этом не появляется -
          // приложение дописывается в список тому, который уже работает.
          t('2. Сервер уже подключён — добавить ему это приложение:'),
          ticket.app_command,
          '',
          `${t('Окружение')}: ${ticket.environment}`,
          `${t('Токен действителен до')}: ${formatDateTime(ticket.expires_at)}`,
          t('Вторая команда не расходует токен и ничего не перезапускает.'),
        ].join('\n'),
      )
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  /** Сервер без приложений: только агент и личность в панели. */
  async function connectBare(minutes: number) {
    try {
      const ticket = await createEnrollToken({ environment_id: null, minutes, lang })
      await notify(
        t('Выполните на сервере'),
        [
          ticket.command,
          '',
          `${t('Токен действителен до')}: ${formatDateTime(ticket.expires_at)}`,
          t('Приложения добавляются на странице сервера кнопкой «Подключить приложение».'),
        ].join('\n'),
      )
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  // Личность за подом: секрета нет вовсе, доказательством служит подпись
  // кластера под ServiceAccount-токеном.
  async function addFromCluster() {
    if (clusters.length === 0) {
      await notify(t('Личность в кластере'), t('Сначала добавьте кластер.'))
      return
    }
    const answer = await ask({
      title: t('Личность в кластере'),
      submit: t('Завести'),
      fields: [
        {
          name: 'cluster',
          label: t('Кластер'),
          type: 'select',
          options: clusters.map((c) => ({ value: String(c.id), label: c.name })),
          value: String(clusters[0].id),
        },
        { name: 'namespace', label: 'namespace', placeholder: 'billing' },
        { name: 'account', label: 'ServiceAccount', placeholder: 'app' },
      ],
      send: async (a) => {
        await createMachine({
          name: `${a.namespace.trim()}/${a.account.trim()}`,
          cluster_id: Number(a.cluster),
          k8s_namespace: a.namespace.trim(),
          k8s_service_account: a.account.trim(),
        })
      },
    })
    if (!answer) return
    try {
      await reload()
      await notify(
        t('Личность в кластере'),
        t('Готово. Выдайте ей окружение в разделе «Доступ» — секрет здесь не нужен.'),
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function addCluster() {
    const answer = await ask({
      title: t('Добавить кластер'),
      submit: t('Добавить'),
      fields: [
        { name: 'name', label: t('Имя'), placeholder: 'web-1' },
        {
          name: 'issuer',
          label: 'issuer',
          placeholder: 'https://kubernetes.example/cluster',
          hint: t('поле iss из токена ServiceAccount'),
        },
        {
          name: 'audience',
          label: 'audience',
          value: 'sekvyr',
          hint: t('для кого под просит токен; «для kubernetes» панели не подойдёт'),
        },
        {
          name: 'jwks',
          label: 'JWKS',
          type: 'textarea',
          placeholder: '{"keys": [...]}',
          hint: 'kubectl get --raw /openid/v1/jwks',
        },
      ],
      // Битый JWKS или занятое имя - ответ в окне, вставленные ключи на месте.
      send: async (a) => {
        await createCluster({
          name: a.name.trim(),
          issuer: a.issuer.trim(),
          audience: a.audience.trim() || 'sekvyr',
          jwks: a.jwks.trim(),
        })
      },
    })
    if (!answer) return
    try {
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  // Ключи подписи кластер меняет редко, но после смены токены подов перестают
  // проходить. Правка на месте сохраняет личности подов и выданные им права.
  async function updateClusterKeys(cluster: Cluster) {
    const answer = await ask({
      title: t('Обновить ключи'),
      submit: t('Сохранить'),
      fields: [
        { name: 'issuer', label: 'issuer', value: cluster.issuer },
        { name: 'audience', label: 'audience', value: cluster.audience },
        {
          name: 'jwks',
          label: 'JWKS',
          type: 'textarea',
          placeholder: '{"keys": [...]}',
          hint: 'kubectl get --raw /openid/v1/jwks',
        },
      ],
      send: async (a) => {
        await updateCluster(cluster.id, {
          issuer: a.issuer.trim(),
          audience: a.audience.trim(),
          jwks: a.jwks.trim(),
        })
      },
    })
    if (!answer) return
    try {
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function removeCluster(cluster: Cluster) {
    const answer = await ask({
      title: t('Удалить кластер?'),
      text: t('Вместе с ним исчезнут личности его подов: проверять их токены станет нечем.'),
      submit: t('Удалить'),
      danger: true,
      fields: [{ name: 'confirm', label: t('Введите имя кластера'), placeholder: cluster.name }],
    })
    if (!answer) return
    try {
      await deleteCluster(cluster.id, answer.confirm.trim())
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function add() {
    // Ответ отправки из окна: присваивается внутри send.
    const out: { made?: Awaited<ReturnType<typeof createMachine>> } = {}
    const answer = await ask({
      title: t('Машина без агента'),
      submit: t('Завести'),
      fields: [
        { name: 'name', label: t('Имя'), placeholder: 'ci-runner' },
        {
          name: 'description',
          label: t('Зачем'),
          placeholder: t('например: сборки биллинга'),
          optional: true,
        },
        {
          name: 'allow_ips',
          label: t('Адреса'),
          placeholder: '203.0.113.7 198.51.100.0/24',
          hint: t('через пробел; пусто — откуда угодно'),
          optional: true,
        },
        {
          name: 'expires_at',
          label: t('Действует до'),
          placeholder: '2026-12-31',
          hint: t('пусто — бессрочно'),
          optional: true,
        },
      ],
      // Неверный адрес или дата - ответ в окне, набранное на месте.
      send: async (a) => {
        out.made = await createMachine({
          name: a.name.trim(),
          description: a.description.trim(),
          allow_ips: a.allow_ips.trim(),
          // "Действует до 2026-12-31" - до конца этого дня в зоне панели, а не
          // до его начала по UTC. Полную метку времени передаем как есть.
          expires_at: /^\d{4}-\d{2}-\d{2}$/.test(a.expires_at.trim())
            ? endOfDay(a.expires_at.trim())
            : a.expires_at.trim(),
        })
      },
    })
    const made = out.made
    if (!answer || !made) return
    try {
      await reload()
      // Секрет показываем один раз и говорим об этом прямо: второй раз панель
      // его не покажет, потому что в базе лежит только хеш.
      await notify(
        t('Секрет сервера'),
        `${t('Идентификатор')}: ${made.client_id}\n${t('Секрет')}: ${made.client_secret}\n\n${t('Секрет показывается один раз — сохраните его сейчас.')}`,
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="stack">
      <ErrorNote text={error} onClose={() => setError('')} />

      <div className="row-actions">
        <h2 className="grow">{t('Серверы')}</h2>
        {auth.isManager && <button onClick={connect}>{t('Подключить сервер')}</button>}
        {auth.isManager && (
          // Редкие способы завести машину - в меню: тремя кнопками подряд шапка
          // не помещалась в строку и уезжала за край.
          <div className="menu-wrap">
            <button className="ghost icon-btn" aria-label={t('Меню')} onClick={() => setMenu(!menu)}>
              ⋯
            </button>
            {menu && (
              <>
                <div className="menu-catcher" onClick={() => setMenu(false)} />
                <div className="menu-pop menu-pop-right">
                  <button
                    className="menu-item"
                    onClick={() => {
                      setMenu(false)
                      void addFromCluster()
                    }}
                  >
                    {t('Личность в кластере')}
                  </button>
                  <button
                    className="menu-item"
                    onClick={() => {
                      setMenu(false)
                      void add()
                    }}
                  >
                    {t('Машина без агента')}
                  </button>
                  <div className="menu-divider" />
                  <button
                    className="menu-item"
                    onClick={() => {
                      setMenu(false)
                      void addCluster()
                    }}
                  >
                    {t('Добавить кластер')}
                  </button>
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {ready && rows.length >= SEARCH_FROM && (
        <div className="row-actions">
          <input
            style={{ flex: 1, minWidth: 180 }}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder={t('поиск по имени, адресу, системе и окружениям')}
          />
          <div className="chip-row">
            {(
              [
                ['all', t('все')],
                ['silent', t('молчат')],
                ['idle', t('ничего не забирают')],
                ['old', t('агент устарел')],
              ] as const
            ).map(([value, title]) => (
              <button
                key={value}
                className={`env-chip${kind === value ? ' env-chip-prod' : ''}`}
                onClick={() => setKind(kind === value ? 'all' : value)}
              >
                {title}
              </button>
            ))}
          </div>
          {(filter || kind !== 'all') && (
            <span className="muted small search-count">
              {visible.length} {t('из')} {rows.length}
            </span>
          )}
        </div>
      )}

      {!ready ? (
        <Skeleton rows={3} />
      ) : rows.length === 0 ? (
        <div className="card empty">
          <p className="empty-title">{t('Серверов пока нет')}</p>
          <p className="muted small">
            {t('«Подключить сервер» покажет команду установки агента с одноразовым токеном.')}
          </p>
          {auth.isManager && <button onClick={connect}>{t('Подключить сервер')}</button>}
        </div>
      ) : visible.length === 0 ? (
        <div className="card empty">
          <p className="empty-title">{t('Ничего не нашлось')}</p>
          <p className="muted small">{t('Поиск идёт по имени, адресу, системе и выданным окружениям.')}</p>
          <button
            className="ghost"
            onClick={() => {
              setFilter('')
              setKind('all')
            }}
          >
            {t('Сбросить поиск')}
          </button>
        </div>
      ) : (
        <div className="servers">
          {visible.map((machine) => {
            const waiting = granted(machine)
            const fresh = machine.last_seen_at && !staleClass(machine.last_seen_at)
            const idle = bare(machine)
            return (
              <button
                key={machine.id}
                className={`card server-row${machine.disabled ? ' server-off' : ''}`}
                onClick={() => onOpen(machine)}
              >
                <span className="server-head">
                  <span
                    className={`sdot${
                      machine.disabled || idle ? ' sdot-off' : fresh ? ' sdot-up' : ' sdot-stale'
                    }`}
                  />
                  {/* Система и страна - до имени: и то, и другое панель узнает
                      сама, а имя сервера про них ничего не доказывает, как бы
                      аккуратно его ни назвали. */}
                  <OsIcon os={machine.os} />
                  <CountryFlag code={machine.country} />
                  <span className="project-name">{machine.name}</span>
                  {machine.disabled && <span className="tag tag-muted">{t('выключен')}</span>}
                  {machine.description && (
                    <span className="muted small server-note">{machine.description}</span>
                  )}
                  <span className="spacer" />
                  <span className="muted small server-seen">
                    {idle ? (
                      t('без приложений')
                    ) : machine.last_seen_at ? (
                      <span className={staleClass(machine.last_seen_at)}>
                        {formatAgo(machine.last_seen_at, lang)}
                      </span>
                    ) : (
                      t('ещё не забирал')
                    )}
                    {machine.agent_version &&
                      (outdated(machine) ? (
                        <>
                          {' · '}
                          <span
                            className="stale-warn"
                            title={`${t('панель раздаёт')} ${latest} — ${t('агент обновится сам')}`}
                          >
                            {machine.agent_version}
                          </span>
                        </>
                      ) : (
                        ` · ${machine.agent_version}`
                      ))}
                  </span>
                  <span className="chev">›</span>
                </span>

                {/* Адреса своей строкой: в голове карточки им тесно, а
                    вопрос "куда зайти" задают чаще, чем читают имя. */}
                <ServerAddr external={machine.last_ip} local={machine.local_ip} />

                {/* Что подключено - плашками: имя окружения отвечает на вопрос
                    "что тут крутится", а путь к файлу нужен уже внутри. */}
                <span className="server-chips">
                  {(machine.apps || []).map((app) => {
                    // Право отозвали, а файл на сервере остался: он больше не
                    // обновляется, и в списке это должно быть видно сразу.
                    const orphan = !machine.environments.includes(app.environment)
                    return (
                      <span
                        key={app.environment}
                        className={`env-chip env-chip-static${orphan ? ' chip-orphan' : ''}`}
                        title={orphan ? t('права нет — файл больше не обновляется') : undefined}
                      >
                        {app.environment}
                      </span>
                    )
                  })}
                  {waiting.map((name) => (
                    <span
                      key={name}
                      className="env-chip env-chip-static chip-waiting"
                      title={t('выдано, но не забирается')}
                    >
                      {name}
                    </span>
                  ))}
                  {!machine.apps?.length && waiting.length === 0 && (
                    <span className="muted small">{t('ничего не выдано')}</span>
                  )}
                </span>
              </button>
            )
          })}
        </div>
      )}

      {auth.isManager && clusters.length > 0 && (
        <div className="stack">
          <h3>{t('Кластеры')}</h3>
          <div className="card band-card">
            <table className="grid">
              <thead>
                <tr>
                  <th>{t('Кластер')}</th>
                  <th>issuer</th>
                  <th>audience</th>
                  <th>{t('Личностей')}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {clusters.map((cluster) => (
                  <tr key={cluster.id}>
                    <td className="project-name">{cluster.name}</td>
                    <td className="mono small muted">{cluster.issuer}</td>
                    <td className="mono small muted">{cluster.audience}</td>
                    <td className="muted small">{cluster.identities}</td>
                    <td className="cell-actions">
                      <button
                        className="ghost small-btn"
                        onClick={() => void updateClusterKeys(cluster)}
                      >
                        {t('Обновить ключи')}
                      </button>
                      <button
                        className="ghost small-btn danger-text"
                        onClick={() => void removeCluster(cluster)}
                      >
                        {t('Удалить')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Одна строка внизу вместо двух абзацев сверху: пояснения нужны тому,
          кто здесь впервые, а не каждый раз перед списком. */}
      <p className="muted small">
        {t('Сервер только читает выданные ему окружения: в машинном контуре нет маршрутов, которые пишут в секреты.')}
        {auth.isManager && clusters.length === 0 && (
          <>
            {' '}
            {t('Под в кластере может доказать себя подписью кластера, без секрета вовсе: для этого добавьте кластер в меню сверху.')}
          </>
        )}
      </p>
    </div>
  )
}
