import { useCallback, useEffect, useRef, useState } from 'react'
import { listAudit, verifyAudit, type AuditEntry } from './api'
import { useAuth } from './auth'
import { csvText } from './csv'
import { ErrorNote, Skeleton } from './Notes'
import { useI18n } from './i18n'
import { serverText } from './serverText'
import { usePoll } from './usePoll'
import { formatDate, formatDateTime, formatTime, timeZone } from './time'
import { ACTIONS } from './auditActions'

// Отказы: то, ради чего в журнал заходят после инцидента.
const DENIED = new Set([
  'login_failed',
  'reauth_failed',
  'vault_unseal_failed',
  'machine_denied',
  'machine_enroll_denied',
  'secret_rejected',
])

// Действия, меняющие саму защиту: ключи, права, аварийный доступ. Их отмечаем
// янтарным - не ошибка, но и не рядовая строка.
const SENSITIVE = new Set([
  'vault_initialized',
  'vault_unsealed',
  'vault_sealed',
  'vault_root_rotated',
  'vault_key_remembered',
  'vault_key_forgotten',
  'owner_password_reset',
  'user_password_reset',
  'policy_created',
  'policy_deleted',
  'machine_secret_rotated',
  'env_key_rotated',
  'emergency_archive',
  'env_exported',
  'env_values_read',
  'e2e_enabled',
  'totp_disabled',
])

// Сколько строк выгрузки берем за раз в файл.
const LIMIT = 5000

export function AuditPage() {
  const { t } = useI18n()
  const auth = useAuth()
  const [entries, setEntries] = useState<AuditEntry[]>([])
  // Сколько записей отвечает поиску во всем журнале, а не сколько загружено.
  const [total, setTotal] = useState(0)
  const [more, setMore] = useState(false)
  const [saving, setSaving] = useState(false)
  // Выгрузка обрезана пределом: сколько записей попало в файл и из скольких.
  // Сбрасывается сменой отбора: к другому отбору прежняя пометка не относится.
  const [cut, setCut] = useState<[number, number] | null>(null)
  // Чем сужаем выдачу: тип события и период. Разбор инцидента начинается
  // именно с этого, а не с текста.
  const [kind, setKind] = useState<'all' | 'denied' | 'sensitive'>('all')
  const [period, setPeriod] = useState(0)
  const [verdict, setVerdict] = useState('')
  const [ok, setOk] = useState<boolean | null>(null)
  const [filter, setFilter] = useState('')
  const [error, setError] = useState('')
  // Первый ответ сервера получен: до него список не пуст, а неизвестен.
  const [ready, setReady] = useState(false)
  const filterRef = useRef('')

  // Русские названия действий живут здесь, а в базе лежат коды. Поэтому строку
  // отправляем как есть и вместе с ней - коды действий, чье название под нее
  // подходит: "записано значение" найдет secret_written. Название сверяется и
  // в переводе: в английском интерфейсе ищут тем, что видят на экране.
  const codesFor = useCallback(
    (needle: string) => {
      const text = needle.trim().toLowerCase()
      if (text.length < 2) return []
      return Object.entries(ACTIONS)
        .filter(
          ([, title]) =>
            title.toLowerCase().includes(text) || t(title).toLowerCase().includes(text),
        )
        .map(([code]) => code)
    },
    [t],
  )

  const load = useCallback(
    async (needle: string, offset = 0, only = kind, within = period) => {
      try {
        const page = await listAudit({
          offset,
          q: needle.trim(),
          queryActions: codesFor(needle),
          onlyActions:
            only === 'denied' ? [...DENIED] : only === 'sensitive' ? [...SENSITIVE] : [],
          days: within,
        })
        setTotal(page.total)
        // Страницы считаются от свежих записей, а новые события приходят как
        // раз сверху: следующая страница начинается с уже показанных строк.
        // Без отсева они шли повторно - и на экран, и в выгрузку CSV.
        setEntries((prev) => {
          if (offset === 0) return page.entries
          const seen = new Set(prev.map((e) => e.id))
          return [...prev, ...page.entries.filter((e) => !seen.has(e.id))]
        })
        setError('')
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err))
      } finally {
        setReady(true)
        setMore(false)
      }
    },
    [codesFor, kind, period],
  )

  // Обновляем сам, но только пока человек смотрит первую страницу: если он
  // догрузил еще сотни, вернуть его к началу - хуже, чем показать несвежее.
  const refresh = useCallback(() => {
    if (entries.length > 100) return
    void load(filterRef.current, 0)
  }, [entries.length, load])

  usePoll(refresh, 30_000)

  // Пока набирают, запрос не уходит на каждую букву: журнал большой, а поиск по
  // нему - не подсказка, а запрос к базе.
  useEffect(() => {
    filterRef.current = filter
    const timer = window.setTimeout(() => void load(filter), filter ? 300 : 0)
    return () => window.clearTimeout(timer)
  }, [filter, load])

  // Пометка об обрезанной выгрузке к другому отбору не относится.
  useEffect(() => setCut(null), [filter, kind, period])

  // Выгрузка того же, что на экране: с теми же поиском и отбором. Инцидент
  // разбирают не в браузере - записи уносят в таблицу и сверяют с чужими
  // логами.
  async function download() {
    setSaving(true)
    setCut(null)
    try {
      const rows: AuditEntry[] = []
      const seen = new Set<number>()
      // Порциями: журнал бывает на десятки тысяч записей, и одним запросом его
      // не берут ни сервер, ни браузер. Новые записи (чтения агентов) сдвигают
      // страницы, пока идет выгрузка: строки, уже взятые, отсеиваются по номеру,
      // а выгрузка идет дальше, пока не наберет свое.
      let offset = 0
      // Сколько записей подходит под отбор - по ответу самой выгрузки, а не
      // по экрану: пока страница висела, журнал рос (опрос выключен после
      // "Показать еще"), и выгрузка молча останавливалась на старом числе.
      let matched: number | null = null
      while (rows.length < Math.min(matched ?? Number.MAX_SAFE_INTEGER, LIMIT)) {
        const page = await listAudit({
          limit: 500,
          offset,
          q: filter.trim(),
          queryActions: codesFor(filter),
          onlyActions:
            kind === 'denied' ? [...DENIED] : kind === 'sensitive' ? [...SENSITIVE] : [],
          days: period,
        })
        if (matched === null) matched = page.total
        if (page.entries.length === 0) break
        offset += page.entries.length
        for (const entry of page.entries) {
          if (!seen.has(entry.id)) {
            seen.add(entry.id)
            rows.push(entry)
          }
        }
      }

      // Сдвиг страниц добирает строки сверх предела: файл - ровно предел.
      rows.splice(LIMIT)
      // Предел молча выглядел как весь журнал: файл с последними записями
      // считали полным.
      if (matched !== null && rows.length < matched) setCut([rows.length, matched])

      const cell = (value: string) => `"${csvText(value).replaceAll('"', '""')}"`
      // Время - в зоне панели с ее названием и отдельно в UTC: в час перевода
      // часов два разных момента дают одну и ту же местную строку.
      const head = [
        `${t('Когда')} (${timeZone()})`,
        'UTC',
        t('Кто'),
        t('Код'),
        t('Действие'),
        t('Над чем'),
        t('Подробности'),
        t('Адрес'),
      ]
      const lines = [head.map(cell).join(';')]
      for (const row of rows) {
        lines.push(
          [
            formatDateTime(row.ts),
            Number.isNaN(new Date(row.ts).getTime()) ? row.ts : new Date(row.ts).toISOString(),
            row.actor,
            row.action,
            t(ACTIONS[row.action] ?? row.action),
            row.target,
            row.detail,
            row.ip,
          ]
            .map(cell)
            .join(';'),
        )
      }

      // BOM: без него таблица открывает кириллицу как кракозябры, и файл
      // приходится "чинить" вручную.
      const blob = new Blob(['\uFEFF' + lines.join('\r\n')], {
        type: 'text/csv;charset=utf-8',
      })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `sekvyr-audit-${new Date().toISOString().slice(0, 10)}.csv`
      link.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  async function verify() {
    try {
      const res = await verifyAudit()
      setOk(res.ok)
      setVerdict(
        res.ok
          ? t('Цепочка журнала цела')
          : t('Цепочка нарушена: первое расхождение — запись {id}, всего расхождений {count}', {
              id: String(res.broken_id),
              count: String(res.breaks),
            }),
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const visible = entries

  // Дни отдельными блоками: журнал читают "что было вчера вечером", а не
  // "строки с 200-й по 260-ю".
  const days: [string, AuditEntry[]][] = []
  for (const entry of visible) {
    const day = formatDate(entry.ts)
    const last = days[days.length - 1]
    if (last && last[0] === day) last[1].push(entry)
    else days.push([day, [entry]])
  }

  return (
    <div className="stack">
      <ErrorNote text={error} onClose={() => setError('')} />
      {cut && (
        <p className="muted small">
          {t('В файл попали последние записи: {n} из {total}. Сузьте поиск или период', {
            n: cut[0],
            total: cut[1],
          })}
        </p>
      )}

      <div className="row-actions">
        <h2>{t('Журнал')}</h2>
        <input
          style={{ flex: 1, minWidth: 200 }}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder={t('поиск по журналу: кто, что, над чем, адрес — по всем записям')}
        />
        <span className="muted small">
          {entries.length} {t('из')} {total}
        </span>
        {/* Панель показывает время в своей зоне, а не в зоне браузера. Молчать
            об этом нельзя: разбор инцидента - это спор про часы и минуты. */}
        <span className="muted small" title={t('панель показывает время в своей зоне, а не в зоне вашего компьютера')}>
          {t('время')} {timeZone()}
        </span>
        <button className="ghost" disabled={saving || entries.length === 0} onClick={download}>
          {saving ? t('Собираем…') : t('Скачать файл')}
        </button>
        {auth.isOwner && (
          <button className="ghost" onClick={verify}>
            {t('Проверить целостность')}
          </button>
        )}
      </div>

      {/* Отбор идет до чтения: "отказы за неделю" - это первый вопрос разбора,
          а текстом такое не набирается. */}
      <div className="row-actions audit-filters">
        <div className="chip-row">
          {(
            [
              ['all', t('все события')],
              ['denied', t('только отказы')],
              ['sensitive', t('над самой защитой')],
            ] as const
          ).map(([value, title]) => (
            <button
              key={value}
              className={`env-chip${kind === value ? ' env-chip-prod' : ''}`}
              onClick={() => {
                setKind(value)
                void load(filter, 0, value, period)
              }}
            >
              {title}
            </button>
          ))}
        </div>

        <span className="spacer" />

        <div className="chip-row">
          {(
            [
              [1, t('сутки')],
              [7, t('неделя')],
              [30, t('месяц')],
              [0, t('всё время')],
            ] as const
          ).map(([value, title]) => (
            <button
              key={value}
              className={`env-chip${period === value ? ' env-chip-prod' : ''}`}
              onClick={() => {
                setPeriod(value)
                void load(filter, 0, kind, value)
              }}
            >
              {title}
            </button>
          ))}
        </div>
      </div>

      {verdict && (
        <p className={`small ${ok ? 'chain-ok' : 'chain-broken'}`}>{verdict}</p>
      )}

      {!ready ? (
        <Skeleton rows={6} />
      ) : visible.length === 0 ? (
        <div className="card empty">
          <p className="empty-title">
            {entries.length ? t('Ничего не нашлось') : t('Записей пока нет')}
          </p>
          <p className="muted small">
            {t('Журнал пишется сам: вход, чтение значений, правки, выданные права.')}
          </p>
        </div>
      ) : (
        days.map(([day, rows]) => (
          <section key={day} className="key-folder">
            <div className="key-folder-head">
              <span className="key-folder-name">{day}</span>
              <span className="key-folder-count">{rows.length}</span>
            </div>
            {rows.map((e) => (
              <div key={e.id} className="audit-row">
                <span
                  className={`key-dot${
                    DENIED.has(e.action)
                      ? ' audit-dot-denied'
                      : SENSITIVE.has(e.action)
                        ? ' audit-dot-sensitive'
                        : ''
                  }`}
                  title={DENIED.has(e.action) ? t('отказ') : undefined}
                />
                <span className="mono small muted audit-time" title={formatDateTime(e.ts)}>
                  {formatTime(e.ts)}
                </span>
                <span className="audit-actor" title={e.actor}>
                  {serverText(e.actor)}
                </span>
                <span className="audit-action" title={e.action}>
                  {t(ACTIONS[e.action] ?? e.action)}
                </span>
                <span className="audit-target mono small" title={e.target}>
                  {e.target}
                </span>
                <span className="muted small audit-detail" title={e.detail}>
                  {serverText(e.detail)}
                </span>
                <span className="mono small muted audit-ip">{e.ip}</span>
              </div>
            ))}
          </section>
        ))
      )}

      {entries.length > 0 && entries.length < total && (
        <div className="row-actions">
          <button
            className="ghost"
            disabled={more}
            onClick={() => {
              setMore(true)
              void load(filter, entries.length)
            }}
          >
            {more ? t('Загружаем…') : t('Показать ещё')}
          </button>
          <span className="muted small">
            {t('осталось')} {total - entries.length}
          </span>
        </div>
      )}
    </div>
  )
}
