import { useState } from 'react'
import { changeOwnPassword, MIN_PASSWORD_LEN } from './api'
import { useI18n } from './i18n'
import { useEscape } from './useEscape'

export function PasswordModal({
  onClose,
  onChanged,
}: {
  onClose: () => void
  onChanged: () => void
}) {
  const { t } = useI18n()
  useEscape(onClose)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  // Новый пароль вводят вслепую: опечатка в нем запирает человека снаружи до
  // сброса владельцем.
  const [repeat, setRepeat] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit() {
    setBusy(true)
    setError('')
    try {
      await changeOwnPassword(current, next)
      onChanged()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal stack" role="dialog" aria-modal="true" aria-label={t('Сменить пароль')}>
        <h3>{t('Сменить пароль')}</h3>
        <label>
          {t('Текущий пароль')}
          <input
            type="password"
            value={current}
            autoComplete="current-password"
            onChange={(e) => setCurrent(e.target.value)}
          />
        </label>
        <label>
          {t('Новый пароль')}
          <input
            type="password"
            value={next}
            autoComplete="new-password"
            onChange={(e) => setNext(e.target.value)}
            placeholder={t('Пароль не короче {n} символов', { n: MIN_PASSWORD_LEN })}
          />
        </label>
        <label>
          {t('Пароль ещё раз')}
          <input
            type="password"
            value={repeat}
            autoComplete="new-password"
            onChange={(e) => setRepeat(e.target.value)}
          />
          {repeat !== '' && repeat !== next && (
            <span className="small form-error field-hint">{t('Пароли не совпали')}</span>
          )}
        </label>
        {error && <p className="form-error">{error}</p>}
        <div className="row-actions">
          <button
            onClick={submit}
            disabled={busy || next.length < MIN_PASSWORD_LEN || repeat !== next}
          >
            {t('Сохранить')}
          </button>
          <button className="ghost" onClick={onClose}>
            {t('Отмена')}
          </button>
        </div>
      </div>
    </div>
  )
}
