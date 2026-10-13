import { useCallback, useEffect, useState } from 'react'
import { setLeaveGuard } from './leave'
import {
  vaultInit,
  vaultRotateRoot,
  vaultForgetKey,
  vaultRememberKey,
  vaultSeal,
  vaultStatus,
  vaultUnseal,
  type VaultStatus,
} from './api'
import { useAuth } from './auth'
import { useDialogs } from './Dialogs'
import { ErrorNote, WarnNote } from './Notes'
import { useI18n } from './i18n'
import { serverText } from './serverText'
import { useEscape } from './useEscape'

/* Экран корневого ключа.
 *
 * Раздел отвечает на один вопрос - заперта панель или нет, - и ответ должен
 * стоять первым: когда значения перестают выдаваться, сюда приходят в спешке.
 * Все остальное здесь редкое и потому убрано в меню.
 *
 * Один момент нельзя сделать "удобнее": доли и корневой ключ показываются один
 * раз и больше нигде не хранятся. Поэтому они выводятся крупно, с
 * предупреждением, и не исчезают сами - человек закрывает их сам, когда
 * переписал.
 */

type Secrets = { shares: string[]; rootKey: string; warning: string }

export function VaultPage({ onStatus }: { onStatus?: (s: VaultStatus) => void }) {
  const { t } = useI18n()
  const auth = useAuth()
  const { confirm } = useDialogs()
  const [status, setStatus] = useState<VaultStatus | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [menu, setMenu] = useState(false)
  const [secrets, setSecrets] = useState<Secrets | null>(null)
  // Доли и новый ключ показываются один раз: уход со страницы до "Записал"
  // терял их без следа, а сейф уже перешел на них.
  useEffect(() => {
    if (!secrets) return
    setLeaveGuard(() =>
      confirm({
        title: t('Уйти, не записав?'),
        text: t('Доли и ключ показываются один раз: после ухода со страницы их не увидеть, а сейф уже работает с ними.'),
        submit: t('Уйти'),
        danger: true,
      }),
    )
    const warn = (event: BeforeUnloadEvent) => event.preventDefault()
    window.addEventListener('beforeunload', warn)
    return () => {
      setLeaveGuard(null)
      window.removeEventListener('beforeunload', warn)
    }
  }, [secrets, confirm, t])
  // Три варианта, а не два: режимов криптографии действительно два, но человек
  // выбирает не режим, а способ жить с ключом. "Один ключ" без уточнения, где он
  // лежит, читался как "ключ будет на сервере" - и вариант "ввожу сам" просто не
  // находился, хотя работал.
  const [mode, setMode] = useState<'shares' | 'single' | 'auto'>('shares')
  const [shares, setShares] = useState(5)
  const [threshold, setThreshold] = useState(3)
  const [input, setInput] = useState('')

  useEscape(() => setMenu(false), menu)

  const reload = useCallback(async () => {
    try {
      const fresh = await vaultStatus()
      setStatus(fresh)
      // Баннер состояния замка живет в шапке, а меняется состояние здесь. Без
      // этого человек распечатывал панель и продолжал видеть "панель
      // заперта" - и шел выяснять, почему не помогло.
      onStatus?.(fresh)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [onStatus])

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

  const init = () =>
    run(async () => {
      const res = await vaultInit(
        mode === 'shares' ? 'shares' : 'env',
        shares,
        threshold,
        mode === 'auto',
      )
      setSecrets({
        shares: res.shares,
        rootKey: res.root_key,
        warning:
          mode === 'auto'
            ? t('Ключ показывается один раз. Положите его файлом на сервер и укажите путь в SEKVYR_ROOT_KEY_FILE, иначе после перезапуска панель окажется запертой. Копию храните отдельно от бэкапов.')
            : mode === 'single'
              ? t('Ключ показывается один раз. Положите его в менеджер паролей: после каждого перезапуска панели вы будете вставлять его здесь. На сервере он не хранится, поэтому дамп базы и бэкап без него бесполезны.')
              : serverText(res.warning),
      })
    })

  const unseal = () =>
    run(async () => {
      const value = input.trim()
      // Отличаем долю от корневого ключа по префиксу, а не отдельной галочкой:
      // человек и так копирует то, что ему выдали, и лишний переключатель здесь
      // только повод ошибиться.
      const res = await vaultUnseal(
        value.toUpperCase().startsWith('SEKVYR-') ? { share: value } : { root_key: value },
      )
      setInput('')
      setNote(serverText(res.detail))
    })

  const rotate = () =>
    run(async () => {
      const res = await vaultRotateRoot()
      setSecrets({
        shares: res.shares,
        rootKey: res.root_key,
        warning: t(
          'Корневой ключ сменён. Прежние доли и прежний ключ больше не работают — замените их везде, где они лежат.',
        ),
      })
    })

  // Те же правила, что и на бэкенде, но сказанные до отправки: форма, которая
  // дает нажать кнопку и получить отказ, заставляет угадывать, что не так.
  const intentMismatch =
    !status?.initialized || status.mode !== 'env'
      ? ''
      : status.auto_unseal_intent && !status.root_key_configured
        ? t('Выбран автоматический подъём, но ключ панели не задан: после перезапуска она окажется запертой. Положите ключ файлом и укажите путь в SEKVYR_ROOT_KEY_FILE.')
        : !status.auto_unseal_intent && status.root_key_configured
          ? t('Корневой ключ задан в окружении панели, хотя при заведении выбирался ручной ввод. Панель поднимется сама, и ключ лежит на сервере.')
          : ''

  const sharesProblem =
    mode !== 'shares'
      ? ''
      : shares < 2
        ? t('Долей должно быть хотя бы две — иначе это просто копия ключа.')
        : threshold < 2
          ? t('Порог 1 означает, что каждая доля сама по себе открывает панель. Возьмите от 2.')
          : threshold > shares
            ? t('Порог не может быть больше числа долей.')
            : ''

  if (!status) return <div className="card">{error || '…'}</div>

  // У запертой панели из редких действий остается одно - забыть ключ,
  // сохраненный на сервере. Если и его нет, показывать нечего.
  const hasMenu = !status.sealed || Boolean(status.key_file_path && status.key_file_present)

  const state = !status.initialized ? 'off' : status.sealed ? 'bad' : 'ok'
  const answer = !status.initialized
    ? t('сейф ещё не создан')
    : status.sealed
      ? t('заперта: значения не выдаются')
      : t('открыта')

  return (
    <div className="stack">
      <ErrorNote text={error} onClose={() => setError('')} />
      {note && <p className="muted small">{note}</p>}
      {intentMismatch && <div className="banner">{intentMismatch}</div>}

      <div className="ops-head">
        <span
          className={`sdot ${state === 'ok' ? 'sdot-up' : state === 'bad' ? 'sdot-stale' : 'sdot-off'}`}
        />
        <h2>{t('Сейф')}</h2>
        <span className={`ops-state ${status.sealed ? 'stale-warn' : 'muted'}`}>{answer}</span>
        {status.initialized && auth.isOwner && (
          <>
            {!status.sealed && (
              <button
                className="ghost"
                disabled={busy}
                onClick={async () => {
                  // В режиме долей запертую панель отпирают держатели долей:
                  // случайный щелчок значит собирать людей.
                  const yes = await confirm({
                    title: t('Запереть панель?'),
                    text: t('Значения перестанут читаться и отдаваться серверам, пока панель не отопрут снова.'),
                    submit: t('Запереть'),
                    danger: true,
                  })
                  if (yes) await run(async () => void (await vaultSeal()))
                }}
              >
                {t('Запереть')}
              </button>
            )}
            {/* Все остальное здесь делают раз в год, а половина этого
                необратима: под кнопку такое не выносят. */}
            {hasMenu && (
            <div className="menu-wrap">
              <button className="ghost icon-btn" aria-label={t('Меню')} onClick={() => setMenu(!menu)}>
                ⋯
              </button>
              {menu && (
                <>
                  <div className="menu-catcher" onClick={() => setMenu(false)} />
                  <div className="menu-pop menu-pop-right">
                    {status.key_file_path &&
                      (status.key_file_present ? (
                        <button
                          className="menu-item"
                          onClick={async () => {
                            setMenu(false)
                            const yes = await confirm({
                              title: t('Забыть ключ на сервере?'),
                              text: status.sealed
                                ? t('Панель заперта, и файл ключа на сервере - его единственная копия здесь. Без своей копии ключа или долей значения будут потеряны.')
                                : t('Панель перестанет отпираться сама после перезапуска: ключ придется вводить или собирать из долей.'),
                              submit: t('Забыть'),
                              danger: true,
                            })
                            if (yes) await run(async () => void (await vaultForgetKey()))
                          }}
                        >
                          {t('Забыть ключ на сервере')}
                        </button>
                      ) : (
                        !status.sealed && (
                          <button
                            className="menu-item"
                            onClick={() => {
                              setMenu(false)
                              void run(async () => void (await vaultRememberKey()))
                            }}
                          >
                            {t('Запомнить ключ на сервере')}
                          </button>
                        )
                      ))}
                    {!status.sealed && (
                    <button
                      className="menu-item menu-item-danger"
                      onClick={async () => {
                        setMenu(false)
                        const yes = await confirm({
                          title: t('Сменить корневой ключ?'),
                          text: t('Прежние доли и прежний ключ перестанут подходить.'),
                          submit: t('Сменить'),
                          danger: true,
                        })
                        if (yes) void rotate()
                      }}
                    >
                      {t('Сменить корневой ключ')}
                    </button>
                    )}
                  </div>
                </>
              )}
            </div>
            )}
          </>
        )}
      </div>

      {/* Отпирание идет первым: когда панель заперта, за этим сюда и приходят. */}
      {status.initialized && status.sealed && (
        <div className="card stack">
          <h3>{t('Отпереть')}</h3>
          {status.mode === 'shares' && (
            <p className="muted small">
              {t('Введено долей')}: {status.pending_shares} {t('из')} {status.threshold}
            </p>
          )}
          <label>
            {t('Доля или корневой ключ')}
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder="SEKVYR-1-…"
            />
          </label>
          <div>
            <button onClick={unseal} disabled={busy || !input.trim()}>
              {t('Ввести')}
            </button>
          </div>
        </div>
      )}

      {secrets && (
        <div className="card stack">
          <h3>{t('Запишите это сейчас')}</h3>
          <WarnNote>{secrets.warning}</WarnNote>
          {secrets.shares.map((s, i) => (
            <div key={s} className="mono share-line">
              <span className="muted">{i + 1}.</span> {s}
            </div>
          ))}
          {secrets.rootKey && <div className="mono share-line">{secrets.rootKey}</div>}
          <div className="row-actions">
            <button className="ghost" onClick={() => setSecrets(null)}>
              {t('Записал, скрыть')}
            </button>
          </div>
        </div>
      )}

      {/* Как устроен ключ - парами "что: значение". Это справка, а не действие,
          и место ей под ответом о состоянии. */}
      {status.initialized && (
        <div className="card ops-facts">
          <span className="muted small">{t('Режим ключа')}</span>
          <span className="small">
            {status.mode === 'shares'
              ? `${t('доли')} ${status.threshold} ${t('из')} ${status.shares}`
              : status.auto_unseal_intent
                ? t('один ключ, панель поднимается сама')
                : t('один ключ, вводится вручную')}
          </span>

          <span className="muted small">{t('Поколение ключа')}</span>
          <span className="mono small">{status.root_generation}</span>

          {auth.isOwner && status.key_file_path && (
            <>
              <span className="muted small">{t('Ключ на сервере')}</span>
              <span className="small">
                {status.key_file_present ? (
                  <>
                    <span className="mono">{status.key_file_path}</span>
                    <span className="muted">
                      {' · '}
                      {t('панель поднимается сама, но root на хосте открывает все значения')}
                    </span>
                  </>
                ) : (
                  <span className="muted">
                    {t('не сохранён: после перезапуска панель ждёт ключ')}
                  </span>
                )}
              </span>
            </>
          )}
        </div>
      )}

      {!status.initialized && auth.isOwner && (
        <div className="card stack">
          <h3>{t('Создать сейф')}</h3>
          <p className="muted small">
            {t('Администратор один? Берите один ключ и держите его в менеджере паролей — или доли, разложенные по разным местам, чтобы потеря одного хранилища не была фатальной.')}
          </p>
          <label>
            {t('Режим ключа')}
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as 'shares' | 'single' | 'auto')}
            >
              <option value="shares">{t('Доли: ключ разложен по нескольким местам или людям')}</option>
              <option value="single">{t('Один ключ: ввожу сам после каждого перезапуска')}</option>
              <option value="auto">{t('Один ключ: лежит на сервере, панель поднимается сама')}</option>
            </select>
          </label>
          {mode === 'shares' && (
            <div className="row-actions">
              <label>
                {t('Всего долей')}
                <input
                  type="number"
                  min={2}
                  max={16}
                  value={shares}
                  onChange={(e) => setShares(Number(e.target.value))}
                />
              </label>
              <label>
                {t('Нужно для входа')}
                <input
                  type="number"
                  min={2}
                  max={16}
                  value={threshold}
                  onChange={(e) => setThreshold(Number(e.target.value))}
                />
              </label>
            </div>
          )}
          <p className="muted small">
            {mode === 'shares'
              ? t('Ключа целиком не будет ни у кого. Порог 3 из 5 переживает потерю двух долей; потеря большего числа — потеря всех значений.')
              : mode === 'single'
                ? t('На сервере ключа нет: дамп базы, бэкап и украденный диск без него бесполезны. Плата — панель после каждого перезапуска ждёт, пока вы вставите ключ.')
                : t('Панель поднимается сама после перезагрузки. Плата — ключ лежит рядом с ней, поэтому root на хосте означает доступ ко всем значениям.')}
          </p>
          {sharesProblem && <p className="form-error">{sharesProblem}</p>}
          <div>
            <button onClick={init} disabled={busy || Boolean(sharesProblem)}>
              {t('Создать')}
            </button>
          </div>
        </div>
      )}

      {status.initialized && !status.sealed && (
        <p className="muted small">
          {t('Как только панель заперта, значения перестают выдаваться и людям, и серверам.')}
        </p>
      )}
    </div>
  )
}
