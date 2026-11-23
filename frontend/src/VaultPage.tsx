import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { setLeaveGuard } from './leave'
import {
  isCurrentSession,
  sessionStamp,
  vaultInit,
  vaultPrepareInit,
  vaultPrepareRootRotation,
  vaultRotateRoot,
  vaultForgetKey,
  vaultRememberKey,
  vaultSeal,
  vaultStatus,
  vaultUnseal,
  type RootRotationPreparation,
  type VaultInitOptions,
  type VaultInitPreparation,
  type VaultStatus,
} from './api'
import { useAuth } from './auth'
import { copyToClipboard, forgetLater } from './clipboard'
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
 * При создании сейфа и смене ключа материал показываем заранее. Применяем
 * только после подтверждения, что его сохранили.
 */

type Material = (
  | { kind: 'init'; options: VaultInitOptions; preparation: VaultInitPreparation }
  | { kind: 'rotation'; preparation: RootRotationPreparation }
) & {
  saved: boolean
  uncertain: boolean
  observedGeneration?: number
}

export function VaultPage({ onStatus }: { onStatus?: (s: VaultStatus) => void }) {
  const { t } = useI18n()
  const auth = useAuth()
  const { confirm } = useDialogs()
  const [status, setStatus] = useState<VaultStatus | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState<'action' | 'prepare' | 'issue' | null>(null)
  const [menu, setMenu] = useState(false)
  const [material, setMaterial] = useState<Material | null>(null)
  const issuing = busy === 'issue'
  const hasMaterial = material !== null
  const initMaterial = material?.kind === 'init'
  const uncertain = Boolean(material?.uncertain)
  const confirmLeaving = useCallback(() => confirm({
    title: initMaterial
      ? uncertain ? t('Уйти до подтверждения создания?') : t('Уйти до создания сейфа?')
      : t('Уйти до подтверждения смены?'),
    text: uncertain
      ? initMaterial
        ? t('Сохраните этот комплект: сейф уже мог быть создан с этим ключом.')
        : t('Сохраните комплект и дождитесь подтверждения смены, прежде чем запирать панель.')
      : t('Подготовленный комплект исчезнет с экрана. Без подтверждения он не вступит в силу.'),
    submit: t('Уйти'),
    danger: true,
  }), [confirm, initMaterial, uncertain, t])
  // Сервер может успеть принять новый ключ до ответа браузеру.
  useLayoutEffect(() => {
    if (!issuing && !hasMaterial) return
    setLeaveGuard(async () => {
      if (issuing) return false
      return confirmLeaving()
    })
    const warn = (event: BeforeUnloadEvent) => event.preventDefault()
    window.addEventListener('beforeunload', warn)
    return () => {
      setLeaveGuard(null)
      window.removeEventListener('beforeunload', warn)
    }
  }, [issuing, hasMaterial, confirmLeaving])
  // Три варианта, а не два: режимов криптографии действительно два, но человек
  // выбирает не режим, а способ жить с ключом. "Один ключ" без уточнения, где он
  // лежит, читался как "ключ будет на сервере" - и вариант "ввожу сам" просто не
  // находился, хотя работал.
  const [mode, setMode] = useState<'shares' | 'single' | 'auto'>('shares')
  const [shares, setShares] = useState(5)
  const [threshold, setThreshold] = useState(3)
  const [input, setInput] = useState('')
  const mounted = useRef(false)
  const statusRequest = useRef(0)
  useLayoutEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      statusRequest.current += 1
    }
  }, [])

  useEscape(() => setMenu(false), menu)

  const reload = useCallback(async () => {
    const session = sessionStamp()
    const request = ++statusRequest.current
    const current = () =>
      mounted.current && request === statusRequest.current && isCurrentSession(session)
    try {
      const fresh = await vaultStatus()
      if (!current()) return null
      if (!fresh || typeof fresh.sealed !== 'boolean') {
        throw new Error(t('Панель не вернула состояние сейфа.'))
      }
      setStatus(fresh)
      // Баннер состояния замка живет в шапке, а меняется состояние здесь. Без
      // этого человек распечатывал панель и продолжал видеть "панель
      // заперта" - и шел выяснять, почему не помогло.
      onStatus?.(fresh)
      setError('')
      return fresh
    } catch (err) {
      if (current()) setError(err instanceof Error ? err.message : String(err))
      return null
    }
  }, [onStatus, t])

  useEffect(() => {
    void reload()
  }, [reload])

  async function run(action: (current: () => boolean) => Promise<void>, kind: NonNullable<typeof busy> = 'action') {
    const session = sessionStamp()
    const current = () => mounted.current && isCurrentSession(session)
    if (!current()) return
    setBusy(kind)
    setError('')
    setNote('')
    try {
      await action(current)
      if (kind !== 'prepare' && current()) await reload()
    } catch (err) {
      if (current()) setError(err instanceof Error ? err.message : String(err))
    } finally {
      if (current()) setBusy(null)
    }
  }

  const prepareInit = () =>
    run(async (current) => {
      const options: VaultInitOptions = {
        mode: mode === 'shares' ? 'shares' : 'env',
        shares,
        threshold,
        auto_unseal: mode === 'auto',
      }
      const preparation = await vaultPrepareInit(options)
      if (!current()) return
      if (
        preparation?.mode !== options.mode || !preparation.proof || !Array.isArray(preparation.shares) ||
        (options.mode === 'shares'
          ? preparation.shares.length !== options.shares || preparation.shares.some((share) => !share)
          : !preparation.root_key)
      ) {
        throw new Error(t('Панель не вернула новый ключ или доли.'))
      }
      setMaterial({ kind: 'init', options, preparation, saved: false, uncertain: false })
    }, 'prepare')

  const unseal = () =>
    run(async (current) => {
      const value = input.trim()
      // Отличаем долю от корневого ключа по префиксу, а не отдельной галочкой:
      // человек и так копирует то, что ему выдали, и лишний переключатель здесь
      // только повод ошибиться.
      const res = await vaultUnseal(
        value.toUpperCase().startsWith('SEKVYR-') ? { share: value } : { root_key: value },
      )
      if (!current()) return
      setInput('')
      setNote(serverText(res.detail))
    })

  const prepareRotation = () =>
    run(async (current) => {
      const preparation = await vaultPrepareRootRotation()
      if (!current()) return
      if (
        !preparation || !Number.isSafeInteger(preparation.root_generation) || !preparation.proof ||
        !Array.isArray(preparation.shares) || (!preparation.root_key && !preparation.shares.length)
      ) {
        throw new Error(t('Панель не вернула новый ключ или доли.'))
      }
      setMaterial({ kind: 'rotation', preparation, saved: false, uncertain: false })
    }, 'prepare')

  const commitMaterial = () => {
    if (!material?.saved) return
    return run(async (current) => {
      try {
        if (material.kind === 'init') {
          const result = await vaultInit(material.options, material.preparation)
          if (result?.mode !== material.options.mode || result.shares?.length !== 0 || result.root_key !== '') {
            throw new Error(t('Панель не подтвердила создание сейфа.'))
          }
        } else {
          const result = await vaultRotateRoot(material.preparation)
          if (result?.root_generation !== material.preparation.root_generation + 1) {
            throw new Error(t('Панель не подтвердила смену корневого ключа.'))
          }
        }
      } catch (err) {
        if (!current()) return
        const pending = { ...material, uncertain: true, observedGeneration: undefined }
        setMaterial(pending)
        const fresh = await reload()
        if (current() && fresh && material.kind === 'rotation') {
          setMaterial({ ...pending, observedGeneration: fresh.root_generation })
        }
        throw err
      }
      if (!current()) return
      setMaterial(null)
      setNote(material.kind === 'init'
        ? t('Сейф создан. Для отпирания используйте сохраненный комплект.')
        : t('Корневой ключ сменён. Прежние доли и прежний ключ больше не работают — замените их везде, где они лежат.'))
    }, 'issue')
  }

  async function copyMaterial(text: string) {
    if (await copyToClipboard(text)) {
      forgetLater(text)
      setNote(t('Скопировано в буфер'))
    } else {
      setError(t('Скопировать не вышло'))
    }
  }

  async function closeMaterial() {
    if (!uncertain || await confirmLeaving()) setMaterial(null)
  }

  const initWarning = material?.kind !== 'init'
    ? ''
    : material.options.auto_unseal
      ? t('Сохраните ключ и положите его файлом на сервер. Укажите путь в SEKVYR_ROOT_KEY_FILE, иначе после перезапуска панель будет заперта. Копию храните отдельно от бэкапов.')
      : material.options.mode === 'env'
        ? t('Сохраните ключ в менеджере паролей. После перезапуска панели его нужно будет ввести здесь. Без него значения из резервной копии не открыть.')
        : serverText(material.preparation.warning)

  // Те же правила, что и на бэкенде, но сказанные до отправки: форма, которая
  // дает нажать кнопку и получить отказ, заставляет угадывать, что не так.
  const intentMismatch =
    !status?.initialized || status.mode !== 'env'
      ? ''
      : status.auto_unseal_intent && !status.root_key_configured
        ? t('Для автоматического отпирания нужен действующий ключ. После перезапуска панель будет заперта. Сохраните действующий ключ в файле и укажите путь в SEKVYR_ROOT_KEY_FILE.')
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
  const keyActionsDisabled = Boolean(busy || hasMaterial)

  const state = !status.initialized ? 'off' : status.sealed ? 'bad' : 'ok'
  const answer = !status.initialized
    ? t('сейф ещё не создан')
    : status.sealed
      ? t('заперта: значения не выдаются')
      : t('отперта')

  return (
    <div className="stack">
      <ErrorNote text={error} onClose={() => setError('')} />
      {note && <p className="muted small">{note}</p>}
      {issuing && <p role="status">{t('Оставайтесь на странице до ответа панели.')}</p>}
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
                disabled={keyActionsDisabled}
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
              <button className="ghost icon-btn" aria-label={t('Меню')} disabled={keyActionsDisabled} onClick={() => setMenu(!menu)}>
                ⋯
              </button>
              {menu && !keyActionsDisabled && (
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
                              text: !status.root_key_configured
                                ? t('Файл не подходит к текущему поколению ключа.')
                                : status.sealed
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
                      onClick={() => {
                        setMenu(false)
                        void prepareRotation()
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
              type="password"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder="SEKVYR-1-…"
            />
          </label>
          <div>
            <button onClick={unseal} disabled={busy !== null || !input.trim()}>
              {t('Ввести')}
            </button>
          </div>
        </div>
      )}

      {material && (
        <div className="card stack">
          <h3>{initMaterial ? t('Запишите это сейчас') : t('Сохраните новый ключ или доли')}</h3>
          <WarnNote>
            {material.uncertain
              ? initMaterial
                ? t('Результат создания неизвестен. Сохраните этот комплект. Повторное подтверждение проверит или завершит создание сейфа с этим же ключом.')
                : t('Результат смены неизвестен. Сохраните эти материалы и оставьте панель открытой. Повторное подтверждение проверит или завершит смену с этим же ключом.')
              : initMaterial
                ? initWarning
                : t('Сохраните новый ключ в защищённом хранилище или разложите новые доли по разным местам. После смены прежний ключ и прежние доли перестанут подходить.')}
          </WarnNote>
          {material.observedGeneration !== undefined && (
            <p className="muted small">
              {t('Панель сообщает поколение ключа {n}.', { n: material.observedGeneration })}
            </p>
          )}
          {material.preparation.shares.map((share, index) => (
            <div key={share} className="row-actions">
              <div className="mono share-line"><span className="muted">{index + 1}.</span> {share}</div>
              <button
                className="ghost small-btn"
                aria-label={t('Скопировать долю {n}', { n: index + 1 })}
                onClick={() => void copyMaterial(share)}
              >
                {t('Скопировать')}
              </button>
            </div>
          ))}
          {material.preparation.root_key && (
            <div className="row-actions">
              <div className="mono share-line">{material.preparation.root_key}</div>
              <button className="ghost small-btn" onClick={() => void copyMaterial(material.preparation.root_key)}>
                {t('Скопировать')}
              </button>
            </div>
          )}
          <label className="checkline">
            <input
              type="checkbox"
              checked={material.saved}
              disabled={busy !== null}
              onChange={(event) => setMaterial({ ...material, saved: event.target.checked })}
            />
            {t('Я сохранил новый ключ или все новые доли')}
          </label>
          <div className="row-actions">
            <button disabled={!material.saved || busy !== null} onClick={commitMaterial}>
              {material.uncertain ? t('Повторить подтверждение') : initMaterial ? t('Подтвердить создание') : t('Сменить')}
            </button>
            <button className="ghost" disabled={busy !== null} onClick={closeMaterial}>
              {material.uncertain ? t('Закрыть материалы') : t('Отменить подготовку')}
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
              : status.root_key_configured
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
                      {status.root_key_configured
                        ? t('панель поднимается сама, но root на хосте открывает все значения')
                        : t('Файл не подходит к текущему поколению ключа.')}
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

      {!status.initialized && auth.isOwner && !hasMaterial && (
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
                {t('Нужно для отпирания')}
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
            <button onClick={prepareInit} disabled={keyActionsDisabled || Boolean(sharesProblem)}>
              {t('Подготовить ключ или доли')}
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
