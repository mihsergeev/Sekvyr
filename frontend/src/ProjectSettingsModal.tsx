import { useEffect, useState } from 'react'
import {
  deleteProject,
  enableE2e,
  getE2eWrap,
  listE2eMachines,
  listEnvironments,
  listProjects,
  machinePublicKey,
  myPermissions,
  rotateEnvKey,
  updateEnvironment,
  exportProject,
  updateProject,
  wrapE2eForMachine,
  type E2eMachine,
  type Environment,
  type Permissions,
  type Project,
} from './api'
import { ComboInput } from './ComboInput'
import { useAuth } from './auth'
import { useDialogs } from './Dialogs'
import { plural, useI18n } from './i18n'
import { createProjectKey, keyFor, rememberKey, unlockProjectKey, wrapForMachine } from './e2e'
import { useEscape } from './useEscape'
import { useLeave } from './useLeave'

/* Настройки проекта - одно место для всего, что задают один раз.
 *
 * Здесь же настраиваются окружения: наследование и смена ключа. Отдельная
 * шестеренка рядом с переключателем окружений выглядела как "настройки
 * проекта", но открывала другое, и это сбивало каждый раз.
 *
 * Подтверждение правок по умолчанию выключено: в большинстве проектов правку
 * разрешают правами, а не церемонией.
 */

export function ProjectSettingsModal({
  project,
  onClose,
  onSaved,
  onDeleted,
}: {
  project: Project
  onClose: () => void
  onSaved: () => void
  onDeleted: () => void
}) {
  const { t } = useI18n()
  const auth = useAuth()
  const { ask, confirm } = useDialogs()
  const [title, setTitle] = useState(project.title)
  const [group, setGroup] = useState(project.group_name)
  const [approval, setApproval] = useState(project.approval_min_level)
  const [required, setRequired] = useState(project.required_keys)
  const [stale, setStale] = useState(project.stale_after_days)
  const [e2eMachines, setE2eMachines] = useState<E2eMachine[]>([])
  const [groups, setGroups] = useState<string[]>([])
  const [envs, setEnvs] = useState<Environment[]>([])
  // Права на каждое окружение: ответственному проект может быть выдан не
  // целиком, и кнопка, которая всегда кончается отказом, только путает.
  const [perms, setPerms] = useState<Record<number, Permissions | null>>({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  // Escape и "Отмена" с измененными настройками спрашивают, как окна правки.
  const dirty =
    title !== project.title ||
    group !== project.group_name ||
    approval !== project.approval_min_level ||
    required !== project.required_keys ||
    stale !== project.stale_after_days
  const leave = useLeave(dirty && !busy, onClose)
  useEscape(leave)

  useEffect(() => {
    listProjects()
      .then((all) => setGroups(all.map((p) => p.group_name).filter(Boolean)))
      .catch(() => setGroups([]))
    listEnvironments(project.id).then(setEnvs).catch(() => setEnvs([]))
    if (project.e2e) {
      // Кому из машин ключ проекта еще не выдан - самая частая причина того,
      // что агент получает блобы и молчит.
      listE2eMachines(project.id).then(setE2eMachines).catch(() => setE2eMachines([]))
    }
  }, [project.id, project.e2e])

  useEffect(() => {
    let alive = true
    void Promise.all(
      envs.map(async (env) => [env.id, await myPermissions(env.id).catch(() => null)] as const),
    ).then((pairs) => {
      if (alive) setPerms(Object.fromEntries(pairs))
    })
    return () => {
      alive = false
    }
  }, [envs])

  async function reloadEnvs() {
    try {
      setEnvs(await listEnvironments(project.id))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function save() {
    setBusy(true)
    setError('')
    try {
      await updateProject(project.id, {
        title,
        group_name: group,
        approval_min_level: approval,
        required_keys: required,
        stale_after_days: stale,
      })
      onSaved()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  /** Все окружения проекта одним файлом: для переезда и разбора. */
  async function downloadAll() {
    setBusy(true)
    setError('')
    try {
      const out = await exportProject(project.id)
      const blob = new Blob([out.text], { type: 'text/plain;charset=utf-8' })
      const link = document.createElement('a')
      link.href = URL.createObjectURL(blob)
      link.download = `${project.slug}.env`
      link.click()
      URL.revokeObjectURL(link.href)
      if (out.skipped.length) {
        // Молчать о пропущенных нельзя: неполный файл принимают за полный.
        setNote(`${t('не попали в файл')}: ${out.skipped.join(', ')}`)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  async function setParent(env: Environment, parentId: number | null) {
    setError('')
    // Значения наследника меняются сразу и уезжают на серверы на следующем
    // круге: случайный выбор в списке не должен этого делать молча.
    const next = envs.find((other) => other.id === parentId)
    const yes = await confirm({
      title: `${t('Сменить родителя?')} ${env.name}`,
      text: next
        ? t('Окружение начнет брать недостающие ключи из {name}, а унаследованное от прежнего родителя пропадет. Серверы получат новые значения на следующем круге.', { name: next.name })
        : t('Унаследованные ключи пропадут из окружения, останутся только свои. Серверы получат это на следующем круге.'),
      submit: t('Сменить родителя'),
      danger: true,
    })
    if (!yes) return
    try {
      await updateEnvironment(env.id, { parent_id: parentId })
      await reloadEnvs()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function rotate(env: Environment) {
    const yes = await confirm({
      title: `${t('Сменить ключ окружения?')} ${env.name}`,
      text: t('Все значения этого окружения будут перешифрованы новым ключом. Читаться они будут как раньше.'),
      submit: t('Сменить'),
    })
    if (!yes) return
    try {
      const res = await rotateEnvKey(env.id)
      setNote(
        `${env.name}: ${t('перешифровано версий')} ${res.reencrypted_versions}, ${t('Поколение ключа')} ${res.key_generation}`,
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function remove() {
    // Подтверждение именем, а не кнопкой "точно?": это единственная операция
    // панели, после которой значения исчезают безвозвратно.
    const answer = await ask({
      title: t('Удалить проект?'),
      text: t('Вместе с ним исчезнут все окружения, ключи и их история. Восстановить можно только из бэкапа базы.'),
      submit: t('Удалить проект'),
      danger: true,
      fields: [
        { name: 'confirm', label: t('Введите имя проекта'), placeholder: project.slug },
      ],
    })
    if (!answer) return
    try {
      await deleteProject(project.id, answer.confirm.trim())
      onDeleted()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function turnOnE2e() {
    const answer = await ask({
      title: t('Шифрование в браузере'),
      text: t(
        'Значения такого проекта шифруются здесь, в браузере: сервер их не увидит и не восстановит. Забытый пароль проекта означает потерю значений без вариантов. Включить можно только у пустого проекта.',
      ),
      submit: t('Включить'),
      danger: true,
      fields: [
        {
          name: 'password',
          label: t('Пароль проекта'),
          type: 'password',
          hint: t('его придётся сказать каждому, кто будет читать значения'),
          check: (v) => (v.length < 12 ? t('Пароль проекта короче двенадцати символов') : ''),
        },
        {
          name: 'repeat',
          label: t('Пароль ещё раз'),
          type: 'password',
          check: (v, all) => (v !== all.password ? t('Пароли не совпали') : ''),
        },
      ],
      // Отказ сервера (в проекте уже есть ключи) - в этом же окне.
      send: async (a) => {
        const wrap = await getE2eWrap(project.id)
        const made = await createProjectKey(a.password, wrap.iterations || 600000)
        await enableE2e(project.id, {
          salt: made.wrap.salt,
          nonce: made.wrap.nonce,
          wrapped_key: made.wrap.wrapped_key,
          verifier_nonce: made.wrap.verifier_nonce,
          verifier: made.wrap.verifier,
        })
        rememberKey(project.id, made.key)
      },
    })
    if (answer) onSaved()
  }

  async function giveKey(machine: E2eMachine) {
    try {
      let key = keyFor(project.id)
      if (!key) {
        // Ключ проекта есть только у того, кто ввел пароль: сервер запечатать
        // его для машины не может - в этом и смысл режима.
        const wrap = await getE2eWrap(project.id)
        const answer = await ask({
          title: t('Пароль проекта'),
          submit: t('Открыть'),
          fields: [{ name: 'password', label: t('Пароль проекта'), type: 'password' }],
        })
        if (!answer) return
        key = await unlockProjectKey(wrap, answer.password)
        if (!key) {
          setError(t('Пароль не подошёл'))
          return
        }
        rememberKey(project.id, key)
      }
      const { public_key } = await machinePublicKey(machine.machine_id)
      if (!public_key) {
        setError(t('У машины ещё нет ключа: агент присылает его при первом обращении'))
        return
      }
      const sealed = await wrapForMachine(key, public_key)
      await wrapE2eForMachine(project.id, { machine_id: machine.machine_id, ...sealed })
      setE2eMachines(await listE2eMachines(project.id))
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal modal-wide stack">
        <h3>{t('Настройки проекта')}</h3>
        <p className="muted small mono">{project.slug}</p>

        {/* Название, группу, обязательные ключи и срок давности API меняет
            только владельцу панели. Ответственный раньше видел поля и кнопку
            "Сохранить", а получал "Требуются права владельца панели". */}
        {!auth.isOwner && (
          <p className="muted small">
            {t('Название, группу и требования к ключам меняет владелец панели.')}
          </p>
        )}
        {auth.isOwner && (
        <div className="row-actions">
          <label style={{ flex: 1, minWidth: 200 }}>
            {t('Название')}
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder={project.slug}
            />
          </label>
          <label style={{ flex: 1, minWidth: 200 }}>
            {t('Группа')}
            <ComboInput
              value={group}
              options={groups}
              placeholder={t('напр. Биллинг')}
              onChange={setGroup}
            />
          </label>
        </div>
        )}

        {auth.isOwner && (
          <label>
            {t('Подтверждение изменений')}
            <select value={approval} onChange={(e) => setApproval(Number(e.target.value))}>
              <option value={0}>{t('не требуется')}</option>
              {/* Подтверждения ждет роль НИЖЕ порога: 30 - правки
                  разработчиков, 40 - еще и ответственных, сразу пишет только
                  владелец. Раньше 40 выбрать было нельзя, а выставленный через
                  API порог select показывал первым пунктом, "не требуется". */}
              <option value={30}>{t('правки разработчиков')}</option>
              <option value={40}>{t('правки разработчиков и ответственных')}</option>
              {/* 10 и 20 сервер принимает, но наблюдатели не пишут, так что
                  ждать подтверждения некому. Показываем, только если такой
                  порог уже стоит. */}
              {approval === 20 && (
                <option value={20}>{t('правки наблюдателей: они не пишут, на деле никто')}</option>
              )}
              {approval === 10 && (
                <option value={10}>{t('ниже наблюдателя: таких ролей нет, на деле никто')}</option>
              )}
              {![0, 10, 20, 30, 40].includes(approval) && (
                <option value={approval}>{t('уровень {level}', { level: approval })}</option>
              )}
            </select>
            <span className="muted small field-hint">
              {t('правка от роли ниже порога не вступит в силу, пока её не подтвердит кто-то выше')}
            </span>
          </label>
        )}

        {auth.isOwner && (
          <label>
            {t('Обязательные ключи')}
            <textarea
              className="value-input"
              rows={3}
              value={required}
              placeholder="DB_DSN APP_ENV SENTRY_DSN"
              onChange={(e) => setRequired(e.target.value)}
            />
            <span className="muted small field-hint">
              {t('имена через пробел; панель покажет их нехватку в каждом окружении, включая новое')}
            </span>
          </label>
        )}

        {auth.isOwner && (
          <label>
            {t('Давним считать значение старше')}
            <select value={stale} onChange={(e) => setStale(Number(e.target.value))}>
              <option value={90}>{t('трёх месяцев')}</option>
              <option value={180}>{t('полугода')}</option>
              <option value={365}>{t('года')}</option>
              <option value={730}>{t('двух лет')}</option>
            </select>
            <span className="muted small field-hint">
              {t('для токена оплаты год — много, для внутреннего ключа мало; отсюда и настройка')}
            </span>
          </label>
        )}

        {/* У e2e-проекта сервер собрал бы файл из блобов, поэтому он честно
            пропускает такие окружения, и кнопка скачивала бы пустой файл. */}
        {auth.isManager && !project.e2e && (
          <label>
            {t('Все окружения одним файлом')}
            <button className="ghost" onClick={() => void downloadAll()} disabled={busy}>
              {t('Скачать проект')}
            </button>
            <span className="muted small field-hint">
              {t('каждое окружение своим блоком; попадёт только то, что вам разрешено читать')}
            </span>
          </label>
        )}

        {auth.isManager && (
          <>
            <div className="menu-divider" />
            <h3>{t('Шифрование в браузере')}</h3>
            {project.e2e ? (
              <>
                <p className="muted small">
                  {t('Включено: сервер хранит значения этого проекта запечатанными и прочитать их не может. Машинам ключ проекта выдаётся отсюда — панель сделать это за вас не в состоянии.')}
                </p>
                {e2eMachines.length === 0 ? (
                  <p className="muted small">{t('Машин с доступом в проект пока нет.')}</p>
                ) : (
                  <div className="env-lines">
                    {e2eMachines.map((machine) => (
                      <div key={machine.machine_id} className="env-line">
                        {/* Точка отвечает за всю строку: зеленая - ключ проекта
                            у машины есть; янтарная - агент ключ прислал, а ключ
                            проекта ему еще не выдали; пустая - ждем агента. */}
                        <span
                          className={`sdot ${
                            machine.has_wrap ? 'sdot-up' : machine.has_key ? 'sdot-stale' : 'sdot-off'
                          }`}
                        />
                        <span className="env-line-name">{machine.name}</span>
                        <span
                          className={`small ${machine.has_wrap ? 'muted' : 'stale-warn'} env-line-count`}
                        >
                          {machine.has_wrap
                            ? t('ключ проекта выдан')
                            : machine.has_key
                              ? t('ключ проекта не выдан')
                              : t('агент ещё не прислал свой ключ')}
                        </span>
                        <button
                          className="ghost small-btn"
                          onClick={() => void giveKey(machine)}
                          disabled={!machine.has_key}
                        >
                          {machine.has_wrap ? t('Выдать заново') : t('Выдать ключ')}
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <>
                <p className="muted small">
                  {t('Обычный проект панель шифрует сама, и распечатанная панель видит значения. В этом режиме их шифрует браузер: сервер хранит непрозрачные блобы. Плата — забытый пароль проекта означает потерю значений без вариантов.')}
                </p>
                {/* Режим - на весь проект: включает тот, кому проект выдан
                    целиком (или владелец). */}
                {(auth.isOwner || project.manage) && (
                  <div className="row-actions">
                    <button className="ghost danger-text" onClick={() => void turnOnE2e()}>
                      {t('Включить шифрование в браузере')}
                    </button>
                  </div>
                )}
              </>
            )}
          </>
        )}

        {envs.length > 0 && (
          <>
            <div className="menu-divider" />
            <h3>{t('Окружения')}</h3>
            <p className="muted small">
              {t('Наследование и смена ключа — то, что трогают редко, поэтому живут здесь. Правки применяются сразу, без кнопки «Сохранить».')}
            </p>
            {/* Строками, а не таблицей в собственной прокрутке: окно и так
                листается, а прокрутка внутри прокрутки прячет половину
                окружений от того, кто их пришел настроить. */}
            <div className="env-lines">
              {envs.map((env) => (
                <div key={env.id} className="env-line">
                  <span className="mono env-line-name">{env.name}</span>
                  <label className="env-line-parent">
                    <span className="muted small">{t('наследует от')}</span>
                    <select
                      value={env.parent_id ?? ''}
                      disabled={!perms[env.id]?.write}
                      onChange={(e) =>
                        setParent(env, e.target.value === '' ? null : Number(e.target.value))
                      }
                    >
                      <option value="">{t('ни от какого')}</option>
                      {envs
                        .filter((other) => other.id !== env.id)
                        .map((other) => (
                          <option key={other.id} value={other.id}>
                            {other.name}
                          </option>
                        ))}
                    </select>
                  </label>
                  <span className="muted small env-line-count">
                    {env.secret_count}{' '}
                    {plural(env.secret_count, [t('ключ'), t('ключа'), t('ключей')])}
                    {env.parent_id !== null &&
                      ` · ${env.own_count} ${plural(env.own_count, [t('свой'), t('своих'), t('своих')])}`}
                  </span>
                  {perms[env.id]?.rotate && (
                    <button className="ghost small-btn" onClick={() => rotate(env)}>
                      {t('Сменить ключ')}
                    </button>
                  )}
                </div>
              ))}
            </div>
          </>
        )}

        {auth.isOwner && (
          <>
            <div className="menu-divider" />
            <div className="row-actions">
              <button className="ghost danger-text" onClick={remove}>
                {t('Удалить проект')}
              </button>
              <span className="muted small">{t('вместе со всеми ключами и историей')}</span>
            </div>
          </>
        )}

        {error && <p className="form-error">{error}</p>}
        {note && <p className="muted small">{note}</p>}

        <div className="row-actions dialog-actions">
          {auth.isOwner ? (
            <>
              <button className="ghost" onClick={leave}>
                {t('Отмена')}
              </button>
              <button onClick={save} disabled={busy}>
                {t('Сохранить')}
              </button>
            </>
          ) : (
            <button className="ghost" onClick={onClose}>
              {t('Закрыть')}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
