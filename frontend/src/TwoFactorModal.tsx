import QRCode from 'qrcode'
import { useEffect, useState } from 'react'
import { setToken, totpDisable, totpEnable, totpStart } from './api'
import { useI18n } from './i18n'
import { useEscape } from './useEscape'

/* Второй фактор.
 *
 * Порядок шагов не случаен: секрет выдается, но фактор включается только после
 * того, как человек ввел код из приложения. Иначе достаточно закрыть вкладку,
 * не досканировав QR, - и вход в панель потерян.
 */

export function TwoFactorModal({
  enabled,
  onClose,
  onChanged,
}: {
  enabled: boolean
  onClose: () => void
  onChanged: () => void
}) {
  const { t } = useI18n()
  useEscape(onClose)
  const [secret, setSecret] = useState('')
  const [qr, setQr] = useState('')
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (enabled) return
    totpStart()
      .then(async (res) => {
        setSecret(res.secret)
        // QR рисуем сами, в браузере: отправлять секрет второго фактора во
        // внешний генератор картинок - это ровно то, от чего он защищает.
        setQr(await QRCode.toDataURL(res.otpauth_url, { margin: 1, width: 220 }))
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
  }, [enabled])

  // Пароль и при включении, и при выключении: с одной украденной сессией
  // фактор не привязать к чужому телефону и не снять. Сервер закрывает прежние
  // сессии и отдает новый токен, с ним эта вкладка и продолжает.
  async function enable() {
    setBusy(true)
    setError('')
    try {
      const res = await totpEnable(code.trim(), password)
      setToken(res.access_token)
      onChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  async function disable() {
    setBusy(true)
    setError('')
    try {
      const res = await totpDisable(password, code.trim())
      setToken(res.access_token)
      onChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal stack">
        <h3>{t('Двухфакторная аутентификация')}</h3>
        {error && <p className="form-error">{error}</p>}

        {enabled ? (
          <>
            <p className="muted small">
              {t('Второй фактор включен. Чтобы выключить, подтвердите пароль и код из приложения: иначе его снял бы любой, кто дотянется до открытой вкладки.')}
            </p>
            <label>
              {t('Пароль')}
              <input
                type="password"
                value={password}
                autoComplete="current-password"
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <label>
              {t('Код из приложения')}
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
              />
            </label>
            <div className="row-actions">
              <button
                className="ghost"
                onClick={disable}
                disabled={busy || !password || code.trim().length < 6}
              >
                {t('Выключить')}
              </button>
              <button className="ghost" onClick={onClose}>
                {t('Закрыть')}
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small">
              {t('Отсканируйте код приложением-аутентификатором и введите шесть цифр, чтобы включить.')}
            </p>
            {qr && <img className="qr" src={qr} width={220} height={220} alt="" />}
            <p className="muted small">
              {t('Если камера недоступна, введите ключ вручную:')}
            </p>
            <div className="mono share-line">{secret}</div>
            <label>
              {t('Код из приложения')}
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
              />
            </label>
            <label>
              {t('Пароль')}
              <input
                type="password"
                value={password}
                autoComplete="current-password"
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <div className="row-actions">
              <button onClick={enable} disabled={busy || code.trim().length < 6 || !password}>
                {t('Включить')}
              </button>
              <button className="ghost" onClick={onClose}>
                {t('Отмена')}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
