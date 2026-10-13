import { useCallback, useEffect, useState } from 'react'
import {
  createUser,
  listUsers,
  resetUserPassword,
  updateUser,
  MIN_PASSWORD_LEN,
  passwordProblem,
  type PanelUser,
  type Role,
} from './api'
import { LEVELS, useAuth } from './auth'
import { useDialogs } from './Dialogs'
import { ErrorNote, Skeleton } from './Notes'
import { useI18n } from './i18n'
import { useEscape } from './useEscape'
import { formatDate } from './time'

/* Учетные записи: кто вообще может войти и с какими полномочиями.
 *
 * Список сгруппирован по ролям, потому что вопрос к нему всегда один и тот же -
 * "у кого какие полномочия", а не "кого завели третьим". Таблица на пять
 * колонок отвечала на него в последнюю очередь: роль стояла второй колонкой и
 * читалась построчно, а треть строки занимали две кнопки, которые нажимают
 * несколько раз в год.
 */

// i18n
const ROLE_TITLES: Record<Role, string> = {
  owner: 'Владелец',
  maintainer: 'Ответственный',
  developer: 'Разработчик',
  viewer: 'Наблюдатель',
}

// Что роль дает на самом деле. Полномочия людей задаются в двух местах сразу -
// ролью (какие разделы панели видны и ждут ли правки подтверждения) и правами в
// "Доступе" (какие секреты), - и без этой строки роль читается как звание, а не
// как набор возможностей.
// i18n
const ROLE_HINTS: Record<Role, string> = {
  owner: 'Все проекты без выданного доступа, права, сейф, оповещения и бэкапы.',
  maintainer:
    'Серверы, учётные записи и журнал; окружения - в проектах, выданных целиком. Секреты - по выданному доступу, правки без подтверждения.',
  developer:
    'Меняет секреты в пределах выданного доступа. Правки ждут подтверждения, если проект этого требует.',
  viewer: 'Только видит ключи и читает значения в пределах выданного доступа.',
}

// От старшей роли к младшей - тот же порядок, что в бэкенде.
const ROLE_ORDER = (Object.keys(LEVELS) as Role[]).sort((a, b) => LEVELS[b] - LEVELS[a])

export function UsersPage() {
  const { t } = useI18n()
  const auth = useAuth()
  const { ask, confirm } = useDialogs()
  const [users, setUsers] = useState<PanelUser[]>([])
  const [error, setError] = useState('')
  // Первый ответ сервера получен: до него список не пуст, а неизвестен.
  const [ready, setReady] = useState(false)
  const [filter, setFilter] = useState('')
  const [menu, setMenu] = useState<number | null>(null)

  useEscape(() => setMenu(null), menu !== null)

  const reload = useCallback(async () => {
    try {
      setUsers(await listUsers())
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setReady(true)
    }
  }, [])

  useEffect(() => {
    void reload()
  }, [reload])

  // Роли строго ниже своей - ровно то, что разрешит бэкенд. Список собираем из
  // уровней, а не пишем руками: иначе новая роль появится в API и потеряется
  // в интерфейсе.
  const grantable = (Object.keys(LEVELS) as Role[]).filter((r) => LEVELS[r] < auth.level)

  async function add() {
    const answer = await ask({
      title: t('Новая учётная запись'),
      text: t('Доступ к секретам выдаётся в разделе «Доступ», роль его не даёт.'),
      submit: t('Завести'),
      fields: [
        {
          name: 'username',
          label: t('Логин'),
          placeholder: 'ivan',
          // То же правило, что у сервера (UserIn.username).
          check: (v) =>
            /^[A-Za-z0-9._-]{1,64}$/.test(v.trim())
              ? ''
              : t('латинские буквы, цифры, точка, дефис и подчеркивание'),
        },
        {
          name: 'password',
          label: t('Пароль'),
          type: 'password',
          hint: t('Пароль не короче {n} символов', { n: MIN_PASSWORD_LEN }),
          check: (v) => passwordProblem(v, t),
        },
        {
          name: 'role',
          label: t('Роль'),
          type: 'cards',
          options: grantable.map((r) => ({
            value: r,
            label: t(ROLE_TITLES[r]),
            hint: t(ROLE_HINTS[r]),
          })),
          value: grantable[grantable.length - 1] ?? '',
        },
      ],
      // Занятый логин - ответ в окне, пароль набирать заново не нужно.
      send: async (a) => {
        await createUser(a.username.trim(), a.password, a.role as Role)
      },
    })
    if (!answer) return
    try {
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function changeRole(u: PanelUser) {
    const answer = await ask({
      title: `${t('Роль')}: ${u.username}`,
      text: t('Доступ к секретам выдаётся в разделе «Доступ», роль его не даёт.'),
      submit: t('Сохранить'),
      fields: [
        {
          name: 'role',
          label: t('Роль'),
          type: 'cards',
          options: grantable.map((r) => ({
            value: r,
            label: t(ROLE_TITLES[r]),
            hint: t(ROLE_HINTS[r]),
          })),
          value: u.role,
        },
      ],
    })
    if (!answer || answer.role === u.role) return
    try {
      await updateUser(u.id, { role: answer.role as Role })
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  /** Откуда этой учетной записи разрешено работать. */
  async function changeIps(u: PanelUser) {
    const answer = await ask({
      title: `${t('Откуда пускать')}: ${u.username}`,
      text: t('Адреса и подсети через пробел. Пусто — откуда угодно. Проверяется на каждом запросе, поэтому смена адреса закрывает и уже выданный токен.'),
      submit: t('Сохранить'),
      fields: [
        {
          name: 'ips',
          label: t('Адреса'),
          value: u.allow_ips,
          placeholder: '10.0.0.0/8 203.0.113.7',
          optional: true,
        },
      ],
    })
    if (!answer) return
    try {
      await updateUser(u.id, { allow_ips: answer.ips.trim() })
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function toggle(u: PanelUser) {
    if (!u.disabled) {
      const yes = await confirm({
        title: t('Отключить учётную запись?'),
        text: `${u.username} — ${t('вход закроется сразу, а имя останется в журнале')}`,
        submit: t('Отключить'),
        danger: true,
      })
      if (!yes) return
    }
    try {
      await updateUser(u.id, { disabled: !u.disabled })
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function resetPassword(u: PanelUser) {
    const answer = await ask({
      title: `${t('Сбросить пароль')}: ${u.username}`,
      text: t('Прежние сессии этой учётки закроются, а событие попадёт в журнал.'),
      submit: t('Сбросить пароль'),
      fields: [
        {
          name: 'password',
          label: t('Новый пароль'),
          type: 'password',
          hint: t('Пароль не короче {n} символов', { n: MIN_PASSWORD_LEN }),
          check: (v) => passwordProblem(v, t),
        },
      ],
    })
    if (!answer) return
    try {
      await resetUserPassword(u.id, answer.password)
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const needle = filter.trim().toLowerCase()
  const visible = needle
    ? users.filter((u) =>
        `${u.username} ${t(ROLE_TITLES[u.role] ?? u.role)}`.toLowerCase().includes(needle),
      )
    : users

  return (
    <div className="stack">
      <ErrorNote text={error} onClose={() => setError('')} />

      <div className="row-actions">
        <h2 className="grow">{t('Учётные записи')}</h2>
        {/* Поиск появляется, когда список перестает читаться целиком. */}
        {users.length > 8 && (
          <input
            style={{ width: 200 }}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder={t('поиск по логину и роли')}
          />
        )}
        {grantable.length > 0 && <button onClick={add}>{t('Новая учётная запись')}</button>}
      </div>

      {!ready ? (
        <Skeleton rows={4} />
      ) : visible.length === 0 ? (
        <div className="card empty">
          <p className="empty-title">{users.length ? t('Ничего не нашлось') : t('Никого нет')}</p>
          <p className="muted small">
            {t('Роль решает, какие разделы панели человек видит. Что он видит внутри проектов, задаётся правами в «Доступе».')}
          </p>
          {grantable.length > 0 && <button onClick={add}>{t('Новая учётная запись')}</button>}
        </div>
      ) : (
        ROLE_ORDER.map((role) => {
          const list = visible.filter((u) => u.role === role)
          if (list.length === 0) return null
          return (
            <section key={role} className="key-folder">
              <div className="key-folder-head">
                <span className="key-folder-name">{t(ROLE_TITLES[role])}</span>
                <span className="key-folder-count">{list.length}</span>
                <span className="muted small role-hint">{t(ROLE_HINTS[role])}</span>
              </div>

              {list.map((u) => {
                // Распоряжаться можно только тем, кто строго ниже: то же
                // правило проверяет и бэкенд.
                const managed = LEVELS[u.role] < auth.level
                return (
                  <div key={u.id} className={`user-row${u.disabled ? ' user-off' : ''}`}>
                    <span
                      className={`key-dot${u.disabled ? '' : ' conn-dot-live'}`}
                      title={u.disabled ? t('Отключена') : t('Активна')}
                    />
                    <span className="user-name">{u.username}</span>
                    {u.username === auth.username && (
                      <span className="tag tag-muted">{t('это вы')}</span>
                    )}
                    {u.disabled && <span className="tag tag-muted">{t('отключена')}</span>}
                    {u.totp_enabled && (
                      <span className="tag tag-muted" title={t('вход подтверждается кодом')}>
                        2FA
                      </span>
                    )}
                    <span className="spacer" />
                    <span className="muted small user-since">
                      {t('заведена')} {formatDate(u.created_at)}
                    </span>
                    {managed ? (
                      <div className="menu-wrap">
                        <button
                          className="ghost small-btn"
                          aria-label={t('Меню')}
                          onClick={() => setMenu(menu === u.id ? null : u.id)}
                        >
                          ⋯
                        </button>
                        {menu === u.id && (
                          <>
                            <div className="menu-catcher" onClick={() => setMenu(null)} />
                            <div className="menu-pop menu-pop-right">
                              <button
                                className="menu-item"
                                onClick={() => {
                                  setMenu(null)
                                  void changeRole(u)
                                }}
                              >
                                {t('Сменить роль')}
                              </button>
                              <button
                                className="menu-item"
                                onClick={() => {
                                  setMenu(null)
                                  void resetPassword(u)
                                }}
                              >
                                {t('Сбросить пароль')}
                              </button>
                              <button
                                className="menu-item"
                                onClick={() => {
                                  setMenu(null)
                                  void changeIps(u)
                                }}
                              >
                                {t('Откуда пускать')}
                              </button>
                              <button
                                className={`menu-item${u.disabled ? '' : ' menu-item-danger'}`}
                                onClick={() => {
                                  setMenu(null)
                                  void toggle(u)
                                }}
                              >
                                {u.disabled ? t('Включить') : t('Отключить')}
                              </button>
                            </div>
                          </>
                        )}
                      </div>
                    ) : (
                      // Место под меню держим всегда: без него строки старших
                      // ролей короче остальных и список выглядит рваным.
                      <span className="menu-gap" />
                    )}
                  </div>
                )
              })}
            </section>
          )
        })
      )}
    </div>
  )
}
