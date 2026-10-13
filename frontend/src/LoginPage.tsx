import { useState, type FormEvent } from 'react'
import { ApiError, login, setToken, type Branding } from './api'
import { EyeIcon, EyeOffIcon } from './icons'
import { BrandLogo } from './BrandLogo'
import { useI18n } from './i18n'

export function LoginPage({
  onLogin,
  branding,
}: {
  onLogin: () => void
  branding: Branding | null
}) {
  const { t } = useI18n()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  // Код запрашиваем вторым шагом, а не сразу: у большинства второго фактора нет,
  // и пустое поле "код" на входе только сбивает.
  const [otp, setOtp] = useState('')
  const [needOtp, setNeedOtp] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [shown, setShown] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const { access_token } = await login(username, password, otp.trim())
      setToken(access_token)
      onLogin()
    } catch (err) {
      // Текст различаем только для "слишком много попыток": он говорит человеку,
      // что ждать, а не подбирать дальше. Все остальное - один ответ на все
      // случаи, чтобы по нему нельзя было выяснить, есть ли такая учетка.
      if (err instanceof ApiError && err.status === 429) {
        setError(t('Слишком много попыток входа — повторите позже'))
      } else if (err instanceof ApiError && err.message === '2fa_required') {
        setNeedOtp(true)
        setError(null)
      } else if (err instanceof ApiError && err.message === '2fa_invalid') {
        setNeedOtp(true)
        setOtp('')
        setError(t('Код не подошёл'))
      } else if (err instanceof ApiError && err.status === 401) {
        setError(t('Неверный логин или пароль'))
      } else {
        setError(err instanceof Error ? err.message : t('Не удалось войти'))
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="card login-card" onSubmit={submit}>
        <div className="login-brand">
          <BrandLogo where="login" branding={branding} />
        </div>

        {/* Второй шаг - отдельный экран, а не еще одно поле под паролем: пароль
            уже принят, и переспрашивать его нечестно, а видеть три поля сразу
            человеку не нужно. */}
        {needOtp ? (
          <>
            <h2>{t('Код из приложения')}</h2>
            <p className="muted small login-note">
              {t('Пароль принят. Осталось подтвердить вход шестизначным кодом.')}{' '}
              <span className="mono">{username}</span>
            </p>
            <label>
              {t('Код')}
              <input
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                autoFocus
              />
            </label>
            {error && <p className="form-error">{error}</p>}
            <button type="submit" disabled={busy || otp.trim().length === 0}>
              {busy ? t('Проверка…') : t('Подтвердить')}
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => {
                setNeedOtp(false)
                setOtp('')
                setError(null)
              }}
            >
              {t('Назад')}
            </button>
          </>
        ) : (
          <>
            <h2>{t('Вход в панель')}</h2>
            <label>
              {t('Логин')}
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus
                required
              />
            </label>
            <label>
              {t('Пароль')}
              <span className="field-with-eye">
                <input
                  type={shown ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                />
                {/* Вслепую пароль набирают с опечаткой чаще, чем угадывают, а
                    третья неудачная попытка здесь запирает вход на время. */}
                <button
                  type="button"
                  className="ghost icon-btn field-eye"
                  aria-label={shown ? t('Скрыть') : t('Показать')}
                  onClick={() => setShown((v) => !v)}
                >
                  {shown ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </span>
            </label>
            {error && <p className="form-error">{error}</p>}
            <button type="submit" disabled={busy}>
              {busy ? t('Проверка…') : t('Войти')}
            </button>
          </>
        )}
      </form>
    </div>
  )
}
