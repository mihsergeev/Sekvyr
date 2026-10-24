import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import {
  exportEnv,
  importEnv,
  myPermissions,
  putSecret,
  readAllValues,
  readSecret,
  readSecretVersion,
  rollbackSecret,
  secretHistory,
  spreadSecret,
  type SecretRow,
  type SecretValueRow,
  type SpreadResult,
  type SecretVersion,
  versionConflict,
} from './api'
import { copyToClipboard, forgetLater } from './clipboard'
import { diffCounts, lineDiff, type DiffLine } from './diff'
import { useDialogs } from './Dialogs'
import { useI18n } from './i18n'
import { useEscape } from './useEscape'
import { useLeave } from './useLeave'
import { formatDateTime } from './time'
import { versionComment } from './serverText'

/* Небольшие окна раздела секретов. Собраны в один файл: каждое - тридцать
 * строк разметки вокруг одного вызова API, и раскладывать их по отдельным
 * файлам значит плодить навигацию на ровном месте. */

/** Сколько открытое значение стоит на экране без правок. Одно на список и на
 *  окно всех значений: "закрывается само" должно значить одно и то же. */
export const HIDE_AFTER_MS = 45_000

function err(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/* Высота поля под содержимое: пять строк минимум, сорок максимум.
 * Выше поле уже не помещается в окно даже на большом экране, а само окно
 * листается - в отличие от поля, где прокрутка прячет нужную строку. */
/* В списке поле начинается с одной строки: ключей много, и пять пустых строк
 * у каждого превратили бы окно в простыню. */
function rowsForInline(text: string): number {
  // Строка про запас: при wrap=off снизу появляется полоса прокрутки и
  // съедает последнюю строку, из-за чего поле начинает листаться внутри.
  return text.split('\n').length + 1
}

function rowsFor(text: string): number {
  return Math.min(Math.max(text.split('\n').length + 1, 3), 40)
}

// ---------------------------------------------------------------- значение

/** Сервер не принял правку: ключ успели изменить. current - действующая
 *  версия (0 - своего ключа больше нет), theirs - действующее значение, null
 *  пока не загрузили или если читать его нельзя. */
type Clash = { current: number; theirs: string | null }

export function SecretEditor({
  secret,
  onClose,
  onSaved,
  save,
  read,
  resume,
}: {
  secret: SecretRow | null
  onClose: () => void
  onSaved: () => void
  save: (body: {
    name: string
    path: string
    value: string
    comment: string
    expected_version: number
  }) => Promise<void>
  /** Откуда взять значение ключа и его версию. Пусто - нет права читать:
   *  поле открывается пустым, а при конфликте правок разницу не показать. */
  read?: (name: string, path: string) => Promise<{ value: string; version: number }>
  /** Правка из строки списка, которую сервер не принял, потому что ключ
   *  успели изменить: окно открывается с набранным и сразу с конфликтом. */
  resume?: { value: string; version: number; current: number }
}) {
  const { t } = useI18n()
  const [name, setName] = useState(secret?.name ?? '')
  const [path, setPath] = useState(secret?.path ?? '/')
  const [value, setValue] = useState(resume?.value ?? '')
  // Человек что-то ввел сам. Пока нет, пустое поле без загруженного значения
  // значит "не знаю, что там", а не "сделать пустым".
  const [touched, setTouched] = useState(Boolean(resume))
  // Версия своего ключа, от которой начата правка: ее сверяет сервер. У
  // унаследованного и у нового ключа своей версии нет, это 0.
  const [base, setBase] = useState(
    resume?.version ?? (secret && !secret.inherited_from ? secret.version : 0),
  )
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(Boolean(secret && read && !resume))
  const [loadFailed, setLoadFailed] = useState(false)
  const [clash, setClash] = useState<Clash | null>(
    resume ? { current: resume.current, theirs: null } : null,
  )
  const [showDiff, setShowDiff] = useState(false)
  const [error, setError] = useState(
    resume ? t('Ключ изменили, пока вы его правили: ваша правка не записана') : '',
  )

  // Escape и переход по разделам с набранным спрашивают: раньше они молча
  // выбрасывали правку.
  const dirty = touched || comment.trim() !== '' || (!secret && name.trim() !== '')
  const leave = useLeave(dirty && !busy, onClose)
  useEscape(leave)

  const readRef = useRef(read)
  readRef.current = read

  // Что сейчас на сервере: чтобы показать разницу и дать взять новое значение.
  const fetchTheirs = useCallback((keyName: string, keyPath: string, current: number) => {
    const fetchValue = readRef.current
    if (!fetchValue || current === 0) return
    fetchValue(keyName, keyPath)
      .then((now) => setClash((prev) => (prev ? { current: now.version, theirs: now.value } : prev)))
      .catch(() => undefined)
  }, [])

  // Правка начинается с того, что есть сейчас. Пустое поле означало "перезаписать
  // вслепую": человек не видел, что меняет, и терял все, чего не помнил.
  const opening = useRef({ secret, resume })
  useEffect(() => {
    const { secret: key, resume: back } = opening.current
    if (!key) return
    if (back) {
      fetchTheirs(key.name, key.path, back.current)
      return
    }
    const fetchValue = readRef.current
    if (!fetchValue) return
    let alive = true
    fetchValue(key.name, key.path)
      .then((current) => {
        if (!alive) return
        setValue(current.value)
        if (!key.inherited_from) setBase(current.version)
        setLoading(false)
      })
      .catch((e) => {
        if (!alive) return
        setError(err(e))
        setLoadFailed(true)
        setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [fetchTheirs])

  // Значения не видно: нет права читать или загрузка не удалась.
  const blind = Boolean(secret) && (!read || loadFailed)

  async function submit() {
    setBusy(true)
    setError('')
    const keyName = secret ? secret.name : name.trim()
    const keyPath = secret ? secret.path : path.trim() || '/'
    try {
      // Пока на экране конфликт, кнопка перезаписывает осознанно: поверх той
      // версии, о которой человеку только что сказали.
      await save({
        name: keyName,
        path: keyPath,
        value,
        comment,
        expected_version: clash ? clash.current : base,
      })
      onSaved()
    } catch (e) {
      const conflict = versionConflict(e)
      if (conflict) {
        setClash({ current: conflict.current, theirs: null })
        setShowDiff(false)
        fetchTheirs(keyName, keyPath, conflict.current)
      }
      setError(err(e))
    } finally {
      setBusy(false)
    }
  }

  // Отказаться от своей правки и продолжить с того, что записали без нас.
  function takeTheirs() {
    if (!clash || clash.theirs === null) return
    setValue(clash.theirs)
    setBase(clash.current)
    setTouched(false)
    setClash(null)
    setShowDiff(false)
    setError('')
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal modal-wide stack">
        {/* Заголовок - сам ключ: отдельная строка "Новое значение ключа" ничего
            не добавляла к тому, что и так видно по содержимому окна. */}
        {secret ? (
          <h3 className="mono">
            {secret.path}
            {secret.path.endsWith('/') ? '' : '/'}
            {secret.name}{' '}
            <span className="muted small">
              {t('версия')} {secret.version}
            </span>
          </h3>
        ) : (
          <h3>{t('Новый ключ')}</h3>
        )}
        {secret ? null : (
          <div className="row-actions">
            <label style={{ flex: 1 }}>
              {t('Имя')}
              <input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
            </label>
            <label style={{ width: 160 }}>
              {t('Папка')}
              <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/" />
            </label>
          </div>
        )}
        <label>
          {t('Значение')}
          {/* textarea, а не input: в секретах живут ключи в несколько строк, и
              однострочное поле молча съедало бы переносы */}
          <textarea
            className="value-input"
            value={loading ? t('Загружаем…') : value}
            onChange={(e) => {
              setValue(e.target.value)
              setTouched(true)
            }}
            disabled={loading}
            spellCheck={false}
            autoComplete="off"
            wrap="off"
            rows={rowsFor(value)}
          />
        </label>
        {/* Без этой строки пустое поле читалось как "значение пустое", и его
            сохраняли, стирая настоящее. */}
        {blind && (
          <p className="muted small">
            {loadFailed
              ? t('Текущее значение не загрузилось. Введенное заменит его целиком.')
              : t('Текущее значение не показывается: читать его вам нельзя. Введенное заменит его целиком.')}
          </p>
        )}
        <label>
          {t('Комментарий к изменению')}
          <input
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder={t('зачем меняем — это останется в истории')}
          />
        </label>
        {error && <p className="form-error">{error}</p>}
        {clash && (
          <div className="stack-tight">
            <p className="muted small">
              {clash.current === 0
                ? t('Сохранить все равно значит завести ключ заново.')
                : t(
                    'Действующая версия теперь {version}. Перезаписать значит поставить ваше значение поверх нее, она останется в истории.',
                    { version: clash.current },
                  )}
            </p>
            {clash.theirs !== null && (
              <div className="row-actions">
                <button className="ghost small-btn" onClick={() => setShowDiff((v) => !v)}>
                  {showDiff ? t('Скрыть разницу') : t('Показать разницу')}
                </button>
                <button className="ghost small-btn" onClick={takeTheirs}>
                  {t('Взять новое значение')}
                </button>
              </div>
            )}
            {showDiff && clash.theirs !== null && (
              <>
                <p className="muted small">{t('Чем ваше значение отличается от действующего:')}</p>
                <DiffView lines={lineDiff(clash.theirs, value)} />
              </>
            )}
          </div>
        )}
        <div className="row-actions dialog-actions">
          <button className="ghost" onClick={leave}>
            {t('Отмена')}
          </button>
          <button
            className={clash ? 'danger-btn' : undefined}
            onClick={submit}
            disabled={busy || loading || (!secret && !name.trim()) || (blind && !touched)}
          >
            {clash
              ? clash.current === 0
                ? t('Сохранить все равно')
                : t('Перезаписать')
              : t('Сохранить')}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- история

export function HistoryModal({
  envId,
  secret,
  reveal,
  onClose,
  onChanged,
}: {
  envId: number
  secret: SecretRow
  /** Как раскрыть значение версии. В e2e-проекте сервер отдает блобы, и
   *  сравнивать надо то, что под ними, а не два шифротекста. */
  reveal?: (value: string) => Promise<string>
  onClose: () => void
  onChanged: () => void
}) {
  const { t } = useI18n()
  useEscape(onClose)
  const { confirm, toast } = useDialogs()
  const [rows, setRows] = useState<SecretVersion[]>([])
  // Права именно в папке ключа: у того, кому выдана одна папка, на корне прав
  // нет, а читать и откатывать ключ в ней он может. До ответа и при ошибке -
  // ничего: кнопка, которая кончается отказом, хуже отсутствующей.
  const [readHere, setReadHere] = useState(false)
  const [writeHere, setWriteHere] = useState(false)
  const [permsFailed, setPermsFailed] = useState(false)
  const [permsLoaded, setPermsLoaded] = useState(false)
  useEffect(() => {
    let alive = true
    myPermissions(envId, secret.path)
      .then((p) => {
        if (!alive) return
        setReadHere(p.read)
        setWriteHere(p.write)
        setPermsLoaded(true)
      })
      .catch((e) => {
        // Кнопок нет, но и "читать нельзя" было бы неправдой: прав не узнали.
        if (!alive) return
        setPermsFailed(true)
        setError(err(e))
      })
    return () => {
      alive = false
    }
  }, [envId, secret.path])
  const [open, setOpen] = useState<number | null>(null)
  // 'closed' - значение версии лежало в папке, где читать нельзя.
  const [diffs, setDiffs] = useState<Record<number, DiffLine[] | 'closed'>>({})
  const [error, setError] = useState('')

  const reload = useCallback(async () => {
    try {
      setRows(await secretHistory(envId, secret.name, secret.path))
    } catch (e) {
      setError(err(e))
    }
  }, [envId, secret.name, secret.path])

  useEffect(() => {
    void reload()
  }, [reload])

  // История отдается новыми вперед, поэтому предыдущая версия - ниже по
  // списку. Сравниваем с той, что действовала: ожидающая или отклоненная правка
  // ни дня не была значением, и разница с ней показывала бы не то, что
  // поменялось на самом деле. Разницу считаем по требованию: значения ходят с
  // сервера по одному, и каждое обращение попадает в журнал.
  async function toggle(index: number) {
    const v = rows[index]
    if (open === v.version) {
      setOpen(null)
      return
    }
    setOpen(v.version)
    await load(index)
  }

  // Строку раскрыли раньше, чем пришли права в папке: догружаем, как только
  // они пришли, иначе в ней навсегда висело "Загружаем...".
  useEffect(() => {
    if (!readHere || open === null) return
    const index = rows.findIndex((row) => row.version === open)
    if (index >= 0) void load(index)
    // load читает текущее состояние; перезапуск нужен только по правам
  }, [readHere])

  async function load(index: number) {
    const v = rows[index]
    if (diffs[v.version] || !readHere) return
    setError('')
    if (v.closed) {
      setDiffs((d) => ({ ...d, [v.version]: 'closed' }))
      return
    }
    try {
      const prev = rows
        .slice(index + 1)
        .find((row) => row.status !== 'pending' && row.status !== 'rejected')
      const plain = reveal ?? (async (value: string) => value)
      const after = v.deleted || v.inherits
        ? ''
        : await plain((await readSecretVersion(envId, secret.name, secret.path, v.version)).value)
      // Предыдущая версия из закрытой папки - сравнивать не с чем, разница
      // показывается от пустого.
      const before =
        prev && !prev.deleted && !prev.inherits && !prev.closed
          ? await plain(
              (await readSecretVersion(envId, secret.name, secret.path, prev.version)).value,
            )
          : ''
      setDiffs((d) => ({ ...d, [v.version]: lineDiff(before, after) }))
    } catch (e) {
      setError(err(e))
    }
  }

  async function rollback(version: number) {
    const yes = await confirm({
      title: t('Вернуть прежнее значение?'),
      text: t('Вернуть значение версии {n}? Появится новая версия.', { n: version }),
      submit: t('Вернуть'),
    })
    if (!yes) return
    try {
      const res = await rollbackSecret(envId, secret.name, secret.path, version)
      // Ниже порога откат - такое же предложение, как правка: значение пока
      // прежнее, и молча закрытое окно читалось бы как "вернул".
      if (res.pending) toast(t('отправлено на подтверждение'))
      setOpen(null)
      setDiffs({})
      await reload()
      onChanged()
    } catch (e) {
      setError(err(e))
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal modal-wide stack">
        <h3>
          {t('История')}: {secret.name}
        </h3>
        {error && <p className="form-error">{error}</p>}
        <p className="muted small">{t('Строка разворачивается: видно, что именно поменялось.')}</p>
        {/* Строками, а не таблицей: пять колонок с кнопкой в последней ячейке
            разъезжались на длинных комментариях, а прокрутка внутри прокрутки
            прятала половину версий. */}
        <div className="history">
          {rows.map((v, index) => (
            <Fragment key={v.version}>
              <div className={`hist-row${open === v.version ? ' hist-row-open' : ''}`}>
                <span
                  className="hist-main"
                  role="button"
                  tabIndex={0}
                  onClick={() => void toggle(index)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      void toggle(index)
                    }
                  }}
                >
                  <span className="caret">{open === v.version ? '▾' : '▸'}</span>
                  <span className="mono hist-version">{v.version}</span>
                  {v.current && <span className="tag">{t('текущая')}</span>}
                  {v.deleted && <span className="tag tag-muted">{t('удаление')}</span>}
                  {v.inherits && <span className="tag tag-muted">{t('у родителя')}</span>}
                  {v.status === 'pending' && <span className="tag">{t('ждёт подтверждения')}</span>}
                  {v.status === 'rejected' && <span className="tag tag-muted">{t('отклонена')}</span>}
                  <span className="mono small muted hist-when">{formatDateTime(v.created_at)}</span>
                  <span className="hist-who">{v.author}</span>
                  <span className="muted small hist-comment">
                    {versionComment(v.comment)}
                    {v.name !== secret.name && ` (${v.name})`}
                  </span>
                </span>
                {/* Вернуть можно только версию, которая действовала: ожидающая или
                    отклоненная правка ни дня не действовала, а у версии "у
                    родителя" своего значения нет. Сервер откажет и сам. */}
                {readHere &&
                writeHere &&
                !v.closed &&
                !v.deleted &&
                !v.inherits &&
                !v.current &&
                (v.status === undefined || v.status === 'superseded') ? (
                  <button className="ghost small-btn" onClick={() => void rollback(v.version)}>
                    {t('Вернуть')}
                  </button>
                ) : (
                  <span className="menu-gap" />
                )}
              </div>
              {open === v.version && (
                <div className="hist-diff">
                  {!permsLoaded && !permsFailed ? (
                    <p className="muted small">{t('Загружаем…')}</p>
                  ) : permsFailed ? (
                    <p className="muted small">{t('Права в этой папке не загрузились: значения не показаны.')}</p>
                  ) : !readHere ? (
                    <p className="muted small">{t('Значения читать нельзя, видно только события.')}</p>
                  ) : diffs[v.version] === 'closed' ? (
                    <p className="muted small">{t('Значение этой версии лежало в папке, где у вас нет права читать.')}</p>
                  ) : diffs[v.version] ? (
                    <DiffView lines={diffs[v.version] as DiffLine[]} />
                  ) : (
                    <p className="muted small">{t('Загружаем…')}</p>
                  )}
                </div>
              )}
            </Fragment>
          ))}
        </div>
        <div className="row-actions dialog-actions">
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>
      </div>
    </div>
  )
}


/* Разница версий в привычном виде: убранное красным, добавленное зеленым.
 *
 * Контекст показываем целиком, без сворачивания "одинаковых" кусков: значение
 * секрета редко длиннее экрана, а спрятанная строка в конфиге - это ровно то
 * место, где потом ищут причину. */
function DiffView({ lines }: { lines: DiffLine[] }) {
  const { t } = useI18n()
  const { added, removed } = diffCounts(lines)

  if (lines.length === 0) return <p className="muted small">{t('Значение пустое')}</p>
  if (added === 0 && removed === 0)
    return <p className="muted small">{t('Значение не менялось')}</p>

  return (
    <div className="stack-tight">
      <p className="small">
        <span className="diff-plus">+{added}</span> <span className="diff-minus">−{removed}</span>
      </p>
      <pre className="diff">
        {lines.map((line, i) => (
          <span
            key={i}
            className={
              line.sign === '+'
                ? 'diff-line diff-add'
                : line.sign === '-'
                  ? 'diff-line diff-del'
                  : 'diff-line diff-ctx'
            }
          >
            {`${line.sign} ${line.text}`}
          </span>
        ))}
      </pre>
    </div>
  )
}

// ---------------------------------------------------------------- импорт

export function ImportModal({
  envId,
  onClose,
  onDone,
}: {
  envId: number
  onClose: () => void
  onDone: () => void
}) {
  const { t } = useI18n()
  const [text, setText] = useState('')
  const [path, setPath] = useState('/')
  const [overwrite, setOverwrite] = useState(false)
  const [result, setResult] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  // Вставленный и еще не импортированный текст: Escape спрашивает.
  const leave = useLeave(Boolean(text.trim()) && !result && !busy, onClose)
  useEscape(leave)

  async function submit() {
    setBusy(true)
    setError('')
    try {
      const res = await importEnv(envId, text, path.trim() || '/', overwrite)
      setResult(
        t('Создано {c}, обновлено {u}, пропущено {s}', {
          c: res.created,
          u: res.updated,
          s: res.skipped.length,
        }) + (res.skipped.length ? `: ${res.skipped.join(', ')}` : ''),
      )
      onDone()
    } catch (e) {
      setError(err(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal modal-wide stack">
        <h3>{t('Импорт .env')}</h3>
        <label className="file-pick">
          {t('Выбрать файл')}
          <input
            type="file"
            accept=".env,.txt,text/plain"
            onChange={(e) => {
              const file = e.target.files?.[0]
              if (!file) return
              // Читаем в браузере: файл с секретами незачем гонять на сервер
              // отдельным запросом, содержимое и так уедет туда при импорте.
              void file.text().then(setText)
            }}
          />
        </label>
        <label>
          {t('Содержимое файла')}
          <textarea
            className="value-input"
            rows={10}
            value={text}
            onChange={(e) => setText(e.target.value)}
            spellCheck={false}
            placeholder={`DB_PASSWORD=…\nAPI_KEY="${t('значение с пробелами')}"`}
          />
        </label>
        <div className="row-actions">
          <label style={{ width: 240 }}>
            {t('Папка')}
            <input value={path} onChange={(e) => setPath(e.target.value)} />
            <span className="muted small field-hint">
              {t('для ключей без указанной папки')}
            </span>
          </label>
          <label className="checkline">
            <input
              type="checkbox"
              checked={overwrite}
              onChange={(e) => setOverwrite(e.target.checked)}
            />
            {t('перезаписывать существующие')}
          </label>
        </div>
        <p className="muted small">
          {t('По умолчанию существующие ключи не перезаписываются.')}
        </p>
        {error && <p className="form-error">{error}</p>}
        {result && <p className="muted small">{result}</p>}
        <div className="row-actions dialog-actions">
          <button className="ghost" onClick={leave}>
            {t('Закрыть')}
          </button>
          <button onClick={submit} disabled={busy || !text.trim()}>
            {t('Импортировать')}
          </button>
        </div>
      </div>
    </div>
  )
}


// ------------------------------------------------------- правка всего разом

/* Все значения окружения в одном окне.
 *
 * Раньше здесь была выгрузка текстом .env. Читать её было тяжело: значение в
 * несколько строк там превращается в одну строку с \n, а чтобы поправить один
 * ключ, приходилось искать его глазами среди сотни. Список полей решает обе
 * задачи, а файл по-прежнему можно скачать кнопкой.
 */
export function BulkEditModal({
  envId,
  subject,
  filename,
  canWrite,
  onClose,
  onChanged,
}: {
  envId: number
  /** Что правим: проект и окружение. Окно открыто во весь экран, и без подписи
   *  через минуту уже не вспомнить, чьи это значения. */
  subject: string
  filename: string
  canWrite: boolean
  onClose: () => void
  onChanged: () => void
}) {
  const { t } = useI18n()
  const [rows, setRows] = useState<SecretValueRow[]>([])
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  // Значения не отдали (закрытая папка в окружении): окно говорит только
  // причину. "Ключей пока нет" и кнопки выгрузки рядом с отказом путали.
  const [refused, setRefused] = useState(false)
  // Значения убраны с экрана по таймеру, как в списке.
  const [hidden, setHidden] = useState(false)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState('')
  const [error, setError] = useState('')
  // Ключи, которые успели изменить, пока окно было открыто: их правки сервер
  // не записал.
  const [stale, setStale] = useState<Record<string, Clash>>({})
  const [showDiff, setShowDiff] = useState(false)

  const id = (row: { path: string; name: string }) => `${row.path}:${row.name}`

  const fetchAll = useCallback(() => {
    setLoading(true)
    readAllValues(envId)
      .then((values) => {
        setRows(values)
        setDraft(Object.fromEntries(values.map((row) => [id(row), row.value])))
        setStale({})
        setHidden(false)
      })
      .catch((e) => {
        setRefused(true)
        setError(err(e))
      })
      .finally(() => setLoading(false))
  }, [envId])

  useEffect(() => {
    fetchAll()
  }, [fetchAll])

  const changed = rows.filter((row) => draft[id(row)] !== row.value)
  // Спорные - только пока в них остается своя правка.
  const staleRows = changed.filter((row) => stale[id(row)])
  const fresh = changed.length - staleRows.length

  const leave = useLeave(changed.length > 0 && !busy, onClose)
  useEscape(leave)

  // Значения не висят на экране вечно, как и в списке: без несохраненных
  // правок окно убирает их через то же время. Начатую правку таймер не трогает.
  const calm = !loading && !hidden && rows.length > 0 && changed.length === 0
  useEffect(() => {
    if (!calm) return
    const timer = window.setTimeout(() => {
      setHidden(true)
      setRows([])
      setDraft({})
      setResult('')
    }, HIDE_AFTER_MS)
    return () => window.clearTimeout(timer)
  }, [calm])

  // Папки идут отдельными подписями: сотня полей подряд читается как стена.
  const folders: [string, SecretValueRow[]][] = []
  for (const row of rows) {
    const last = folders.at(-1)
    if (last && last[0] === row.path) last[1].push(row)
    else folders.push([row.path, [row]])
  }

  // overwrite - записать поверх тех, что изменили без нас: человек видел
  // предупреждение и выбрал свое значение.
  async function save(overwrite = false) {
    setBusy(true)
    setError('')
    setResult('')
    const targets = changed.filter((row) => Boolean(stale[id(row)]) === overwrite)
    // Что записано, а что ушло на подтверждение: в проекте с порогом правка
    // разработчика не вступает в силу сразу, и "Сохранено" с новым значением в
    // поле было бы неправдой.
    const written = new Map<string, number>()
    const proposed = new Set<string>()
    const clashed: Record<string, Clash> = {}
    let failed = false
    try {
      // По четыре за раз: правок обычно единицы, а сотня параллельных записей
      // легла бы очередью на сервере и перемешала бы порядок в журнале.
      for (let i = 0; i < targets.length; i += 4) {
        const chunk = targets.slice(i, i + 4)
        const out = await Promise.allSettled(
          chunk.map((row) =>
            putSecret(envId, {
              name: row.name,
              path: row.path,
              value: draft[id(row)],
              expected_version:
                stale[id(row)]?.current ?? (row.inherited_from ? 0 : row.version),
            }),
          ),
        )
        let reason: unknown = null
        out.forEach((res, k) => {
          const key = id(chunk[k])
          if (res.status === 'fulfilled') {
            if (res.value.pending) proposed.add(key)
            else written.set(key, res.value.version)
            return
          }
          // Чужая правка в одном ключе не повод бросать остальные.
          const conflict = versionConflict(res.reason)
          if (conflict) clashed[key] = { current: conflict.current, theirs: null }
          else if (reason === null) reason = res.reason
        })
        if (reason !== null) throw reason
      }
    } catch (e) {
      failed = true
      setError(err(e))
    } finally {
      // В список попадает только вступившее в силу. Предложенное ждет
      // подтверждения: поле возвращается к действующему значению.
      setRows((prev) =>
        prev.map((row) => {
          const version = written.get(id(row))
          return version === undefined
            ? row
            : { ...row, value: draft[id(row)], version, inherited_from: undefined }
        }),
      )
      if (proposed.size) {
        setDraft((prev) => {
          const next = { ...prev }
          for (const row of rows) if (proposed.has(id(row))) next[id(row)] = row.value
          return next
        })
      }
      setStale((prev) => {
        const next = { ...prev }
        for (const key of [...written.keys(), ...proposed]) delete next[key]
        return { ...next, ...clashed }
      })
      const parts: string[] = []
      if (written.size) parts.push(`${t('Сохранено ключей')}: ${written.size}`)
      if (proposed.size) parts.push(`${t('отправлено на подтверждение')}: ${proposed.size}`)
      const lost = Object.keys(clashed).length
      if (lost) parts.push(`${t('изменили без вас')}: ${lost}`)
      if (failed) {
        parts.push(
          `${t('не записано')}: ${targets.length - written.size - proposed.size - lost}`,
        )
      }
      setResult(parts.join(' · '))
      if (written.size || proposed.size) onChanged()
      setBusy(false)
    }
    // Действующие значения тех, что изменили без нас: показать разницу и дать
    // взять их. Совпало с набранным - правка уже на месте, спорить не о чем.
    for (const [key, clash] of Object.entries(clashed)) {
      const row = targets.find((one) => id(one) === key)
      if (!row || clash.current === 0) continue
      try {
        const now = await readSecret(envId, row.name, row.path)
        if (now.value === draft[key]) {
          setRows((prev) =>
            prev.map((one) =>
              id(one) === key
                ? { ...one, value: now.value, version: now.version, inherited_from: undefined }
                : one,
            ),
          )
          setStale((prev) => {
            const next = { ...prev }
            delete next[key]
            return next
          })
        } else {
          setStale((prev) =>
            prev[key] ? { ...prev, [key]: { current: now.version, theirs: now.value } } : prev,
          )
        }
      } catch {
        // Не прочитали - разницы не будет, перезаписать все равно можно.
      }
    }
  }

  // Отказаться от своих правок там, где ключи изменили без нас.
  function takeTheirs() {
    const taken = staleRows.filter((row) => stale[id(row)].theirs !== null)
    setRows((prev) =>
      prev.map((row) => {
        const clash = stale[id(row)]
        return clash && clash.theirs !== null
          ? { ...row, value: clash.theirs, version: clash.current, inherited_from: undefined }
          : row
      }),
    )
    setDraft((prev) => {
      const next = { ...prev }
      for (const row of taken) next[id(row)] = stale[id(row)].theirs as string
      return next
    })
    setStale((prev) => {
      const next = { ...prev }
      for (const row of taken) delete next[id(row)]
      return next
    })
    setShowDiff(false)
  }

  async function download() {
    try {
      const res = await exportEnv(envId)
      const url = URL.createObjectURL(new Blob([res.text], { type: 'text/plain' }))
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      link.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(err(e))
    }
  }

  async function copyAll() {
    try {
      const res = await exportEnv(envId)
      // Без navigator.clipboard (панель по http) раньше показывалось
      // "Скопировано", хотя в буфере ничего не было.
      if (await copyToClipboard(res.text)) {
        forgetLater(res.text)
        setResult(t('Скопировано в буфер'))
      } else setError(t('Скопировать не вышло'))
    } catch (e) {
      setError(err(e))
    }
  }

  const anyTheirs = staleRows.some((row) => stale[id(row)].theirs !== null)

  return (
    <div className="modal-backdrop">
      <div className="card modal modal-full stack">
        <h3>
          {t('Все значения')} <span className="muted">· {subject}</span>
        </h3>

        {loading ? (
          <p className="muted">{t('Загружаем…')}</p>
        ) : refused ? null : hidden ? (
          <div className="row-actions">
            <p className="muted">{t('Значения скрыты: окно долго стояло без правок.')}</p>
            <button className="ghost small-btn" onClick={fetchAll}>
              {t('Показать снова')}
            </button>
          </div>
        ) : rows.length === 0 ? (
          <p className="muted">{t('Ключей пока нет')}</p>
        ) : (
          <div className="stack">
            {folders.map(([path, items]) => (
              // Папка - карточка с полосой, как на самой странице: иначе сотня
              // полей идет сплошняком и границы папок теряются.
              <div key={path} className="band-card bulk-folder">
                {folders.length > 1 && (
                  <div className="group-band">
                    <span className="group-band-name folder-band mono">{path}</span>
                  </div>
                )}
                {/* Сетка на всю папку, а не на строку: колонка имен тогда
                    шириной с самое длинное имя, и значения не уезжают от
                    ключей через полэкрана. */}
                <div className="bulk-grid">
                {items.map((row) => (
                  // Строка - своя сетка на колонках папки: так у пары "ключ -
                  // значение" есть граница, а колонки остаются общими.
                  <div
                    key={id(row)}
                    className={`bulk-row${
                      (draft[id(row)] ?? '').includes('\n') ? ' bulk-row-multi' : ''
                    }${draft[id(row)] !== row.value ? ' bulk-row-changed' : ''}`}
                  >
                    <span className="bulk-name mono">
                      {row.name}
                      {row.inherited_from && (
                        <span className="tag tag-muted">{row.inherited_from}</span>
                      )}
                      {stale[id(row)] && draft[id(row)] !== row.value ? (
                        <span className="tag tag-deny">{t('изменили без вас')}</span>
                      ) : (
                        draft[id(row)] !== row.value && (
                          <span className="tag">{t('изменено')}</span>
                        )
                      )}
                    </span>
                    {/* Однострочное значение - обычное поле: у textarea в одну
                        строку всегда торчит полоса прокрутки, и ряд из сотни
                        таких полос выглядит как решетка. */}
                    {(draft[id(row)] ?? '').includes('\n') ? (
                      <textarea
                        className="value-input"
                        rows={rowsForInline(draft[id(row)] ?? '')}
                        value={draft[id(row)] ?? ''}
                        readOnly={!canWrite}
                        spellCheck={false}
                        autoComplete="off"
                        wrap="off"
                        onChange={(e) =>
                          setDraft((prev) => ({ ...prev, [id(row)]: e.target.value }))
                        }
                      />
                    ) : (
                      <input
                        className="value-input"
                        value={draft[id(row)] ?? ''}
                        readOnly={!canWrite}
                        spellCheck={false}
                        autoComplete="off"
                        onChange={(e) =>
                          setDraft((prev) => ({ ...prev, [id(row)]: e.target.value }))
                        }
                      />
                    )}
                  </div>
                ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {error && <p className="form-error">{error}</p>}
        {result && <p className="muted small">{result}</p>}

        {staleRows.length > 0 && (
          <div className="stack-tight">
            <p className="form-error">
              {t('Эти ключи изменили, пока вы правили, и ваши правки в них не записаны:')}{' '}
              <span className="mono">{staleRows.map((row) => row.name).join(', ')}</span>
            </p>
            <div className="row-actions">
              {anyTheirs && (
                <button className="ghost small-btn" onClick={() => setShowDiff((v) => !v)}>
                  {showDiff ? t('Скрыть разницу') : t('Показать разницу')}
                </button>
              )}
              {anyTheirs && (
                <button className="ghost small-btn" onClick={takeTheirs}>
                  {t('Взять новые значения')}
                </button>
              )}
              <button
                className="danger-btn small-btn"
                onClick={() => void save(true)}
                disabled={busy}
              >
                {t('Перезаписать своими')}
              </button>
            </div>
            {showDiff &&
              staleRows.map((row) => {
                const theirs = stale[id(row)].theirs
                if (theirs === null) return null
                return (
                  <div key={id(row)} className="stack-tight">
                    <p className="mono small">{row.name}</p>
                    <DiffView lines={lineDiff(theirs, draft[id(row)] ?? '')} />
                  </div>
                )
              })}
          </div>
        )}

        <div className="row-actions dialog-actions">
          {!refused && (
            <>
              <button className="ghost" onClick={download}>
                {t('Скачать файл')}
              </button>
              <button className="ghost" onClick={copyAll}>
                {t('Скопировать')}
              </button>
            </>
          )}
          <button className="ghost" onClick={leave}>
            {t('Закрыть')}
          </button>
          {canWrite && !refused && !hidden && (
            <button
              onClick={() => void save()}
              disabled={busy || fresh === 0}
            >
              {t('Сохранить')}
              {fresh > 0 && ` (${fresh})`}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

/* Разложить ключ по стендам.
 *
 * Один и тот же токен вносят в двадцать окружений руками, и это ровно та
 * работа, которую машина делает лучше человека: значение берется отсюда,
 * записывается туда, где выбрали, и каждое место получает свою версию.
 *
 * Итог показывается построчно, а не одной фразой: "в четыре записал, в двух
 * уже было то же самое, в одно не пустили" - это три разных новости, и
 * сворачивать их в "готово" значит скрывать последнюю.
 */
export function SpreadModal({
  envId,
  secret,
  targets,
  onClose,
  onDone,
}: {
  envId: number
  secret: SecretRow
  /** Соседние окружения проекта: куда можно разложить. */
  targets: { id: number; name: string }[]
  onClose: () => void
  onDone: () => void
}) {
  const { t } = useI18n()
  useEscape(onClose)
  const [picked, setPicked] = useState<Record<number, boolean>>({})
  const [rows, setRows] = useState<SpreadResult[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const chosen = targets.filter((env) => picked[env.id]).map((env) => env.id)

  async function go() {
    setBusy(true)
    setError('')
    try {
      setRows(await spreadSecret(envId, secret.name, secret.path, chosen))
      onDone()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const TITLES: Record<SpreadResult['state'], string> = {
    // i18n
    written: 'записано',
    pending: 'ждёт подтверждения',
    denied: 'нет права писать',
    same: 'уже такое же',
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal stack">
        <h3>{t('Скопировать в другие окружения')}</h3>
        <p className="muted small">
          {t('Значение записывается в выбранные окружения новой версией. Где оно уже совпадает, запись не создаётся.')}
        </p>
        <p className="mono">{secret.path === '/' ? secret.name : `${secret.path}/${secret.name}`}</p>

        {rows === null ? (
          <>
            <div className="spread-list">
              {targets.map((env) => (
                <label key={env.id} className="checkline">
                  <input
                    type="checkbox"
                    checked={Boolean(picked[env.id])}
                    onChange={(e) =>
                      setPicked((prev) => ({ ...prev, [env.id]: e.target.checked }))
                    }
                  />
                  {env.name}
                </label>
              ))}
            </div>
            {targets.length > 1 && (
              <button
                className="ghost small-btn spread-all"
                onClick={() =>
                  setPicked(
                    chosen.length === targets.length
                      ? {}
                      : Object.fromEntries(targets.map((env) => [env.id, true])),
                  )
                }
              >
                {chosen.length === targets.length ? t('Снять выбор') : t('Выбрать все')}
              </button>
            )}
          </>
        ) : (
          <div className="spread-list">
            {rows.length === 0 && <span className="muted small">{t('ничего не выбрано')}</span>}
            {rows.map((row) => (
              <div key={row.environment} className="spread-row">
                <span className="mono">{row.environment}</span>
                <span className="spacer" />
                <span className={`small ${row.state === 'denied' ? 'stale-warn' : 'muted'}`}>
                  {t(TITLES[row.state])}
                </span>
              </div>
            ))}
          </div>
        )}

        {error && <p className="form-error">{error}</p>}

        <div className="row-actions dialog-actions">
          <button className="ghost" onClick={onClose}>
            {rows === null ? t('Отмена') : t('Закрыть')}
          </button>
          {rows === null && (
            <button onClick={() => void go()} disabled={busy || chosen.length === 0}>
              {t('Записать')}
              {chosen.length > 0 && ` (${chosen.length})`}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
