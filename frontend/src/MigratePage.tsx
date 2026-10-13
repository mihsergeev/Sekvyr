import { useCallback, useEffect, useRef, useState } from 'react'
import {
  applyMigration,
  infisicalProjects,
  listAllEnvironments,
  previewMigration,
  type EnvBrief,
  type InfisicalProject,
  type MigratePreview,
  type MigrateSource,
} from './api'
import { ErrorNote } from './Notes'
import { useI18n } from './i18n'
import { serverText } from './serverText'

/* Перенос из Infisical и Vault.
 *
 * Экран устроен в два шага намеренно: сначала "покажи, что там", потом
 * "перенеси". Чужой набор ключей поверх рабочего окружения - самый быстрый
 * способ незаметно испортить прод, поэтому по умолчанию существующее не
 * трогается, а что именно случится, видно заранее.
 *
 * Реквизиты источника живут в этой вкладке и уходят только в запрос: панель их
 * не сохраняет и вторым местом хранения доступа к старому хранилищу не
 * становится.
 */

export function MigratePage() {
  const { t } = useI18n()
  const [source, setSource] = useState<'infisical' | 'vault'>('infisical')
  const [url, setUrl] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [workspace, setWorkspace] = useState('')
  const [sourceEnv, setSourceEnv] = useState('')
  const [secretPath, setSecretPath] = useState('/')
  const [token, setToken] = useState('')
  const [mount, setMount] = useState('secret')
  const [path, setPath] = useState('')
  const [projects, setProjects] = useState<InfisicalProject[]>([])

  const [environments, setEnvironments] = useState<EnvBrief[]>([])
  const [envId, setEnvId] = useState(0)
  const [targetPath, setTargetPath] = useState('/')
  const [overwrite, setOverwrite] = useState(false)

  const [preview, setPreview] = useState<MigratePreview | null>(null)
  // Запрос, по которому построен предпросмотр. Перенос уходит именно с ним:
  // раньше после смены окружения или папки на экране оставался предпросмотр
  // для stage, а перенос с перезаписью уходил в prod.
  const [previewed, setPreviewed] = useState<ReturnType<typeof body> | null>(null)
  // Счетчик правок полей: ответ на запрос, после которого поля меняли, отбрасывается.
  const edits = useRef(0)
  // "Совпадает" - самая частая строка предпросмотра и самая бесполезная: при
  // втором заходе она занимает весь экран, а смотрят на две другие.
  const [onlyChanges, setOnlyChanges] = useState(false)
  const [done, setDone] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const rows = await listAllEnvironments()
      setEnvironments(rows)
      if (rows.length && !envId) setEnvId(rows[0].id)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [envId])

  useEffect(() => {
    void load()
  }, [load])

  const body = (): MigrateSource & { environment_id: number; target_path: string } => ({
    source,
    url: url.trim(),
    client_id: clientId.trim(),
    client_secret: clientSecret,
    workspace_id: workspace.trim(),
    environment: sourceEnv.trim(),
    secret_path: secretPath.trim() || '/',
    token,
    mount: mount.trim() || 'secret',
    path: path.trim(),
    environment_id: envId,
    target_path: targetPath.trim() || '/',
  })

  async function run(action: () => Promise<void>) {
    setBusy(true)
    setError('')
    setDone('')
    try {
      await action()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const findProjects = () =>
    run(async () => {
      const rows = await infisicalProjects({
        url: url.trim(),
        client_id: clientId.trim(),
        client_secret: clientSecret,
        environment_id: envId,
      })
      setProjects(rows)
      if (rows.length) {
        setWorkspace(rows[0].id)
        if (rows[0].environments.length) setSourceEnv(rows[0].environments[0])
      }
    })

  const look = () =>
    run(async () => {
      const asked = body()
      const at = edits.current
      let answer: Awaited<ReturnType<typeof previewMigration>>
      try {
        answer = await previewMigration(asked)
      } catch (e) {
        // Ошибка запроса, после которого поля поменяли, - про прежний адрес
        // или токен, а не про то, что на экране.
        if (edits.current !== at) return
        throw e
      }
      // Поля поменяли, пока шел запрос: ответ описывает уже не то, что на
      // экране, и перенос по нему ушел бы в прежнее окружение.
      if (edits.current !== at) return
      setPreview(answer)
      setPreviewed(asked)
    })

  const move = () =>
    run(async () => {
      if (!previewed) return
      const res = await applyMigration({ ...previewed, overwrite })
      setPreview(null)
      setPreviewed(null)
      setDone(
        t('Перенесено: создано {created}, обновлено {updated}, пропущено {skipped}', {
          created: String(res.created),
          updated: String(res.updated),
          skipped: String(res.skipped.length),
        }),
      )
    })

  // Любая правка шагов 1 и 2 снимает предпросмотр: он описывал другой запрос.
  useEffect(() => {
    edits.current += 1
    setPreview(null)
    setPreviewed(null)
  }, [source, url, clientId, clientSecret, workspace, sourceEnv, secretPath, token, mount, path, envId, targetPath])

  const actionClass = (action: string) =>
    action === 'обновить' ? 'stale-warn' : action === 'совпадает' ? 'muted' : ''

  // Точка вместо слова в колонке: создать - зеленая, обновить - янтарная,
  // совпадает - тихая серая.
  const actionDot = (action: string) =>
    action === 'обновить'
      ? 'key-dot audit-dot-sensitive'
      : action === 'совпадает'
        ? 'key-dot'
        : 'key-dot conn-dot-live'

  const rows = (preview?.rows ?? []).filter(
    (row) => !onlyChanges || row.action !== 'совпадает',
  )

  return (
    <div className="stack">
      <h2>{t('Перенос из другого хранилища')}</h2>
      <ErrorNote text={error} onClose={() => setError('')} />
      {done && <p className="muted small">{done}</p>}

      <div className="card stack">
        <h3>{t('Шаг 1. Откуда')}</h3>
        <p className="muted small">
          {t('Реквизиты уходят только в этот запрос: панель их не сохраняет и вторым местом хранения доступа к старому хранилищу не становится.')}
        </p>
        <label>
          {t('Источник')}
          <select
            value={source}
            onChange={(e) => {
              setSource(e.target.value as 'infisical' | 'vault')
              setPreview(null)
            }}
          >
            <option value="infisical">Infisical</option>
            <option value="vault">Vault KV v2</option>
          </select>
        </label>
        <label>
          {t('Адрес')}
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={source === 'infisical' ? 'https://app.infisical.com' : 'https://vault.example.ru'}
          />
        </label>

        {source === 'infisical' ? (
          <>
            <label>
              {t('Идентификатор машинной личности')}
              <input value={clientId} onChange={(e) => setClientId(e.target.value)} />
            </label>
            <label>
              {t('Секрет машинной личности')}
              <input
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
              />
            </label>
            <div className="row-actions">
              <button className="ghost" onClick={findProjects} disabled={busy || !envId}>
                {t('Найти проекты')}
              </button>
            </div>
            {projects.length > 0 && (
              <label>
                {t('Проект')}
                <select
                  value={workspace}
                  onChange={(e) => {
                    setWorkspace(e.target.value)
                    const found = projects.find((p) => p.id === e.target.value)
                    if (found?.environments.length) setSourceEnv(found.environments[0])
                  }}
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label>
              {t('Окружение источника')}
              <input
                value={sourceEnv}
                onChange={(e) => setSourceEnv(e.target.value)}
                placeholder="prod"
              />
            </label>
            <label>
              {t('Путь в источнике')}
              <input value={secretPath} onChange={(e) => setSecretPath(e.target.value)} />
            </label>
          </>
        ) : (
          <>
            <label>
              {t('Токен Vault')}
              <input type="password" value={token} onChange={(e) => setToken(e.target.value)} />
            </label>
            <label>
              {t('Раздел KV')}
              <input value={mount} onChange={(e) => setMount(e.target.value)} />
            </label>
            <label>
              {t('Путь в источнике')}
              <input
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="billing"
              />
            </label>
          </>
        )}
      </div>

      <div className="card stack">
        <h3>{t('Шаг 2. Куда')}</h3>
        <label>
          {t('Окружение')}
          <select value={envId} onChange={(e) => setEnvId(Number(e.target.value))}>
            {environments.map((e) => (
              <option key={e.id} value={e.id}>
                {`${e.group_slug ? e.group_slug + '/' : ''}${e.project_slug}/${e.name}`}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t('Папка')}
          <input value={targetPath} onChange={(e) => setTargetPath(e.target.value)} />
        </label>
        <label className="checkline">
          <input
            type="checkbox"
            checked={overwrite}
            onChange={(e) => setOverwrite(e.target.checked)}
          />
          {t('Перезаписывать существующие значения')}
        </label>
        <div className="row-actions">
          <button onClick={look} disabled={busy || !url || !envId}>
            {t('Посмотреть, что будет')}
          </button>
        </div>
      </div>

      {preview && (
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">{t('Шаг 3. Что изменится')}</span>
            <span className="key-folder-count">{preview.total}</span>
            <span className="muted small role-hint">
              {t('создать')} {preview.create} · {t('обновить')} {preview.update} ·{' '}
              {t('совпадает')} {preview.same}
            </span>
          </div>

          {preview.note && <div className="banner">{serverText(preview.note)}</div>}
          {preview.update > 0 && !overwrite && (
            <p className="muted small">
              {t('Существующие значения останутся как есть: включите перезапись, если нужно иначе.')}
            </p>
          )}

          <div className="row-actions">
            <label className="checkline">
              <input
                type="checkbox"
                checked={onlyChanges}
                onChange={(e) => setOnlyChanges(e.target.checked)}
              />
              {t('только изменения')}
            </label>
            <span className="spacer" />
            <button onClick={move} disabled={busy}>
              {t('Перенести')}
            </button>
          </div>

          {rows.length === 0 ? (
            <div className="card empty">
              <p className="empty-title">{t('Менять нечего')}</p>
              <p className="muted small">{t('Всё, что нашлось в источнике, уже лежит здесь с теми же значениями.')}</p>
            </div>
          ) : (
            rows.map((row) => (
              <div key={`${row.path}/${row.name}`} className="mig-row">
                <span className={actionDot(row.action)} title={t(row.action)} />
                <span className="mono small muted mig-path" title={row.path}>
                  {row.path}
                </span>
                <span className="mono small mig-name" title={row.name}>
                  {row.name}
                </span>
                <span className={`small ${actionClass(row.action)}`}>{t(row.action)}</span>
                <span className="muted small mig-size">
                  {row.size} {t('симв.')}
                </span>
              </div>
            ))
          )}
        </section>
      )}
    </div>
  )
}
