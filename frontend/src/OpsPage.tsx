import { useCallback, useEffect, useState } from 'react'
import {
  MIN_PASSWORD_LEN,
  buildEmergencyArchive,
  getAlerts,
  getBackupState,
  saveAlerts,
  testAlerts,
  type AlertsConfig,
  type BackupState,
} from './api'
import { useDialogs } from './Dialogs'
import { ErrorNote } from './Notes'
import { useI18n } from './i18n'
import { serverText } from './serverText'
import { formatDateTime } from './time'

/* Обслуживание: оповещения, бэкап, аварийный архив.
 *
 * Страница отвечает на один вопрос - узнаете ли вы о беде и сможете ли из нее
 * выбраться. Все, что здесь есть, нужно настроить в спокойный день: в день
 * происшествия настраивать поздно.
 *
 * Токен и адреса приходят с сервера обрезанными, поэтому договор с API такой:
 * пустое поле оставляет прежнее значение, "-" выключает канал. Иначе
 * сохранение соседней настройки однажды стерло бы оповещения целиком.
 */

export function OpsPage() {
  const { t } = useI18n()
  const { ask, confirm, notify } = useDialogs()
  const [alerts, setAlertsState] = useState<AlertsConfig | null>(null)
  const [backup, setBackup] = useState<BackupState | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)

  const reload = useCallback(async () => {
    try {
      setAlertsState(await getAlerts())
      setBackup(await getBackupState())
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [])

  useEffect(() => {
    void reload()
  }, [reload])

  async function run(action: () => Promise<void>) {
    setBusy(true)
    setError('')
    setNote('')
    try {
      await action()
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const editAlerts = () =>
    run(async () => {
      const answer = await ask({
        title: t('Оповещения'),
        text: t('Пустое поле оставит прежнее значение, «-» выключит канал.'),
        submit: t('Сохранить'),
        fields: [
          {
            name: 'telegram_token',
            label: t('Токен бота Telegram'),
            type: 'password',
            placeholder: alerts?.telegram_token || t('не задан'),
            optional: true,
          },
          {
            name: 'telegram_chat',
            label: t('Чат или канал'),
            value: alerts?.telegram_chat ?? '',
            placeholder: '-1001234567890',
            optional: true,
          },
          {
            name: 'telegram_api',
            label: t('Зеркало Bot API'),
            value: alerts?.telegram_api ?? '',
            hint: t('для сетей, где api.telegram.org недоступен'),
            optional: true,
          },
          {
            name: 'webhook',
            label: t('Вебхук'),
            placeholder: alerts?.webhook || 'https://…',
            hint: t('только https и только внешний адрес'),
            optional: true,
          },
          {
            name: 'audit_webhook',
            label: t('Приёмник журнала'),
            placeholder: alerts?.audit_webhook || 'https://…',
            hint: t('копия записей журнала уезжает туда пачками — её не срезать вместе с базой'),
            optional: true,
          },
        ],
      })
      if (!answer) return
      await saveAlerts(answer)
      setNote(t('Сохранено'))
    })

  const check = () =>
    run(async () => {
      const res = await testAlerts()
      if (res.sent) {
        setNote(t('Сообщение отправлено — проверьте канал'))
      } else {
        setError(res.errors.join('; '))
      }
    })

  const emergency = () =>
    run(async () => {
      const agreed = await confirm({
        title: t('Аварийный архив'),
        text: t(
          'В файл попадут ВСЕ значения всех окружений открытым текстом, защищённые только вашим паролем. Сборка попадёт в журнал и в оповещения. Продолжать?',
        ),
        submit: t('Продолжить'),
        danger: true,
      })
      if (!agreed) return
      // Архив, собранный отправкой из окна.
      const out: { blob?: Blob } = {}
      const answer = await ask({
        title: t('Аварийный архив'),
        submit: t('Собрать'),
        danger: true,
        fields: [
          {
            name: 'password',
            label: t('Пароль архива'),
            type: 'password',
            hint: t('от 12 символов; храните его отдельно от самого архива'),
            // MIN_ARCHIVE_PASSWORD на сервере совпадает с MIN_PASSWORD_LEN.
            check: (v) =>
              v.length < MIN_PASSWORD_LEN
                ? t('Пароль не короче {n} символов', { n: MIN_PASSWORD_LEN })
                : '',
          },
          {
            name: 'repeat',
            label: t('Пароль ещё раз'),
            type: 'password',
            check: (v, all) => (v !== all.password ? t('Пароли не совпали') : ''),
          },
          { name: 'login_password', label: t('Ваш пароль от панели'), type: 'password' },
          {
            name: 'otp',
            label: t('Код второго фактора'),
            placeholder: '123456',
            optional: true,
          },
          {
            name: 'note',
            label: t('Пометка'),
            placeholder: t('например: перед переездом'),
            optional: true,
          },
        ],
        // Неверный пароль от панели или код - ответ в этом же окне: пароль
        // архива не набирается заново.
        send: async (a) => {
          out.blob = await buildEmergencyArchive({
            password: a.password,
            login_password: a.login_password,
            otp: a.otp,
            note: a.note,
          })
        },
      })
      const blob = out.blob
      if (!answer || !blob) return
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      const day = new Date().toISOString().slice(0, 10)
      link.download = `sekvyr-emergency-${day}.sealed`
      link.click()
      URL.revokeObjectURL(url)
      await notify(
        t('Архив собран'),
        t('Открыть его без панели: python3 ops/breakglass.py env <файл> группа/проект/окружение'),
      )
    })

  const backupLine = () => {
    if (!backup) return ''
    if (!backup.configured) return t('Панель не следит за бэкапом')
    if (!backup.at) return t('Отметки о бэкапе ещё не было')
    const when = formatDateTime(backup.at)
    if (!backup.ok) return t('Последний бэкап не удался: {when}', { when })
    return t('Последний бэкап: {when}', { when })
  }

  const backupClass = backup && backup.configured && (backup.stale || !backup.ok) ? 'stale-old' : ''

  // Состояние тремя точками: бэкап, оповещения, копия журнала. Раздел
  // существует ради ответа "все ли в порядке", и ответ должен быть виден
  // сразу, а не вычитываться из абзацев.
  const backupState = !backup?.configured
    ? 'off'
    : !backup.at || !backup.ok || backup.stale
      ? 'bad'
      : 'ok'
  const alertsState = alerts?.enabled ? 'ok' : 'off'

  const dot = (state: string) =>
    `sdot ${state === 'ok' ? 'sdot-up' : state === 'bad' ? 'sdot-stale' : 'sdot-off'}`

  return (
    <div className="stack">
      <div className="row-actions">
        <h2 className="grow">{t('Обслуживание')}</h2>
      </div>
      <ErrorNote text={error} onClose={() => setError('')} />
      {note && <p className="muted small">{note}</p>}

      {/* --- бэкап --- */}
      <div className="card stack ops-card">
        <div className="ops-head">
          <span className={dot(backupState)} />
          <h3>{t('Бэкап')}</h3>
          <span className={`small ${backupClass} ops-state`}>{backupLine()}</span>
        </div>
        {backup?.file && (
          <div className="ops-facts">
            <span className="mono small">{backup.file}</span>
            <span className="muted small">
              {Math.round(backup.size / 1024)} {t('КБ')}
            </span>
          </div>
        )}
        {backup?.detail && <p className="muted small">{serverText(backup.detail)}</p>}
        <p className="muted small">
          {t(
            'Снимает ops/backup.sh по расписанию: дамп шифруется своим паролем, отметка попадает сюда. Корневого ключа в дампе нет и быть не должно — иначе дамп и ключ ездят вместе.',
          )}
        </p>
      </div>

      {/* --- оповещения --- */}
      <div className="card stack ops-card">
        <div className="ops-head">
          <span className={dot(alertsState)} />
          <h3>{t('Оповещения')}</h3>
          <span className="muted small ops-state">
            {alerts?.enabled ? t('включены') : t('не настроены')}
          </span>
          <button className="ghost small-btn" onClick={check} disabled={busy || !alerts?.enabled}>
            {t('Проверить')}
          </button>
          <button className="small-btn" onClick={editAlerts} disabled={busy}>
            {t('Настроить')}
          </button>
        </div>

        <div className="ops-facts">
          {/* Моноширинным - только настоящий адрес: фраза "не настроен" в нем
              выглядит как значение, которого нет. */}
          <span className="muted small">{t('Telegram')}</span>
          {alerts?.telegram_token ? (
            <span className="mono small">
              {alerts.telegram_token} → {alerts.telegram_chat || '?'}
            </span>
          ) : (
            <span className="muted small">{t('не настроен')}</span>
          )}

          <span className="muted small">{t('Вебхук')}</span>
          {alerts?.webhook ? (
            <span className="mono small">{alerts.webhook}</span>
          ) : (
            <span className="muted small">{t('не настроен')}</span>
          )}

          <span className="muted small">{t('Приёмник журнала')}</span>
          {alerts?.audit_webhook ? (
            <span className="mono small">{alerts.audit_webhook}</span>
          ) : (
            <span className="small">
              <span className="stale-warn">{t('не настроен')}</span>
              <span className="muted"> · {t('копии записей вне этой базы нет')}</span>
            </span>
          )}
        </div>

        {alerts?.from_env.length ? (
          <p className="muted small">
            {t('Задано в .env и потому не стирается отсюда: {fields}', {
              fields: alerts.from_env.join(', '),
            })}
          </p>
        ) : (
          <p className="muted small">
            {t('Панель сообщает о том, о чём нельзя узнать позже: сейф заперли или открыли, вход заблокирован после серии попыток, собран аварийный архив, журнал перестал сходиться. Раз в несколько часов она обходит значения и сообщает о новых замечаниях — заготовка вместо пароля в проде найдётся сама.')}
          </p>
        )}
      </div>

      {/* --- аварийный архив --- */}
      <div className="card stack ops-card">
        <div className="ops-head">
          <span className="sdot sdot-off" />
          <h3>{t('Аварийный доступ')}</h3>
          <span className="ops-state" />
          <button className="danger-btn small-btn" onClick={emergency} disabled={busy}>
            {t('Собрать архив')}
          </button>
        </div>
        <p className="muted small">
          {t(
            'Архив отвечает на вопрос «панели нет, корневого ключа нет, а прод надо поднять сейчас». Все значения одним файлом под вашим паролем; открывает его ops/breakglass.py без панели и без сети.',
          )}
        </p>
        <p className="muted small">
          {t(
            'Это единственное место, где секреты выходят из панели все сразу. Храните архив там же, где доли ключа, и пересобирайте после заметных изменений.',
          )}
        </p>
      </div>
    </div>
  )
}
