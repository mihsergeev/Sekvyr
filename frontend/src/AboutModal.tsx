import { useEffect, useState } from 'react'
import { getHealth, type Branding } from './api'
import { useAuth } from './auth'
import { BrandingSection } from './BrandingSection'
import { Logo } from './Logo'
import { useI18n } from './i18n'
import { useEscape } from './useEscape'

/* "О панели": что это, какая версия и куда идти за исходниками. Здесь же владелец
 * ставит свой логотип - отдельным пунктом меню эта настройка выглядела бы
 * важнее, чем она есть: её трогают один раз за жизнь установки.
 *
 * Версия - от бэкенда, а не из верстки: при частичном обновлении (собрали фронт,
 * забыли бэкенд) номер в интерфейсе показывал бы то, чего на сервере нет.
 */

export const SEKVYR_URL = 'https://github.com/mihsergeev/Sekvyr'

export function AboutModal({
  onClose,
  branding,
  brandingStatus,
  onRefreshBranding,
  onBranding,
}: {
  onClose: () => void
  branding: Branding | null
  brandingStatus: 'loading' | 'ready' | 'error'
  onRefreshBranding: () => Promise<void>
  onBranding: () => Promise<void>
}) {
  const { t } = useI18n()
  const auth = useAuth()
  useEscape(onClose)
  const [version, setVersion] = useState('')

  useEffect(() => {
    getHealth()
      .then((health) => setVersion(health.version))
      .catch(() => setVersion(''))
  }, [])

  useEffect(() => {
    if (auth.isOwner) void onRefreshBranding()
  }, [auth.isOwner, onRefreshBranding])

  return (
    <div className="modal-backdrop">
      <div className="card modal about-modal">
        <div className="about-top">
          <h3>{t('О панели Sekvyr')}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>

        <div className="about-head">
          <Logo variant="mark" width={84} />
          <div>
            <div className="about-name">Sekvyr</div>
            <div className="muted small">
              {version ? `${t('версия')} ${version} · ` : ''}AGPL-3.0
            </div>
          </div>
        </div>

        <p className="about-lead">
          {t('Панель хранения секретов и переменных окружения. Значения шифруются, ключ живёт только в памяти панели.')}
        </p>

        <div className="about-links">
          <a href={SEKVYR_URL} target="_blank" rel="noopener noreferrer">
            {t('Исходный код на GitHub')}
          </a>
          <a href={`${SEKVYR_URL}/issues`} target="_blank" rel="noopener noreferrer">
            {t('Сообщить о проблеме')}
          </a>
          <a href={`${SEKVYR_URL}/blob/main/LICENSE`} target="_blank" rel="noopener noreferrer">
            {t('Лицензия')}
          </a>
        </div>

        {/* Свой логотип меняет только владелец панели: это вид панели для всех. */}
        {auth.isOwner && branding && <BrandingSection branding={branding} onChanged={onBranding} />}
        {auth.isOwner && (brandingStatus === 'error' ? (
          <div>
            <p className="form-error" role="alert">{t('Не удалось загрузить оформление')}</p>
            <button className="ghost small-btn" onClick={() => void onRefreshBranding()}>
              {t('Повторить')}
            </button>
          </div>
        ) : !branding && <p className="muted small" role="status">{t('Загружаем оформление…')}</p>)}
      </div>
    </div>
  )
}
