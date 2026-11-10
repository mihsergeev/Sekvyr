/* Настройки оформления находятся в "О панели": их меняют редко.
 *
 * Превью сразу на обеих темах и считается тем же кодом, что и шапка: что видно
 * здесь, то и будет в панели. Типовая ошибка - залить логотип, который хорош на
 * белом и пропадает на темном, и узнать об этом, когда панель откроет коллега с
 * другой темой.
 */

import { useState } from 'react'
import {
  ApiError,
  brandingUrl,
  resetBranding,
  saveBranding,
  saveCompanyName,
  type Branding,
} from './api'
import { useLogoViews } from './BrandLogo'
import type { LogoSource } from './logoAdapt'
import { useI18n } from './i18n'

const MAX_KB = 512
const ACCEPT = 'image/png,image/svg+xml,image/webp,image/jpeg,image/gif'

export function BrandingSection({
  branding,
  onChanged,
}: {
  branding: Branding
  onChanged: () => Promise<void>
}) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  // Выбранные, но еще не сохраненные файлы: data-URL и текст, если это SVG.
  const [main, setMain] = useState<LogoSource | null>(null)
  const [dark, setDark] = useState<LogoSource | null>(null)
  const [darkRemove, setDarkRemove] = useState(false)
  const [plateDraft, setPlate] = useState<Branding['plate'] | null>(null)
  const [titleDraft, setTitle] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [reading, setReading] = useState(false)
  const logoLocked = busy || reading
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [companyDraft, setCompanyDraft] = useState<string | null>(null)
  const [companyError, setCompanyError] = useState('')
  const [companySaved, setCompanySaved] = useState(false)

  const plate = plateDraft ?? branding.plate
  const title = titleDraft ?? branding.title
  const supportsCompanyName = typeof branding.company_name === 'string'
  const storedCompany = branding.company_name ?? ''
  const companyName = companyDraft ?? storedCompany
  const canSaveCompany = !busy && supportsCompanyName && companyName.trim() !== storedCompany

  const version = `${branding.version}:${branding.logo_revision ?? ''}:${branding.dark_logo_revision ?? ''}`
  const storedDark = !!branding?.dark_logo && !darkRemove
  const hasDark = !!dark || storedDark
  const mainSrc: LogoSource | null = main ?? (branding.logo ? { url: brandingUrl(branding) } : null)
  const darkSrc: LogoSource | null = dark ?? (storedDark ? { url: brandingUrl(branding, true) } : null)
  const views = useLogoViews(mainSrc, darkSrc, plate)

  async function read(file: File | undefined): Promise<LogoSource | null> {
    setError('')
    setSaved(false)
    if (!file) return null
    if (file.size > MAX_KB * 1024) {
      setError(t('Файл больше {n} КБ — уменьшите логотип', { n: MAX_KB }))
      return null
    }
    setReading(true)
    try {
      const url = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = () => resolve(String(reader.result))
        reader.onerror = () => reject(reader.error)
        reader.readAsDataURL(file)
      })
      // Текст SVG - для перекраски по цветам; у растровой картинки его нет.
      const svg = file.type === 'image/svg+xml' || /\.svg$/i.test(file.name) ? await file.text() : null
      return { url, svg }
    } catch {
      setError(t('Не удалось прочитать файл'))
      return null
    } finally {
      setReading(false)
    }
  }

  async function save() {
    setBusy(true)
    setError('')
    setSaved(false)
    try {
      await saveBranding({
        data: main?.url ?? '',
        dark: dark?.url ?? '',
        dark_remove: darkRemove && !dark,
        plate,
        title: title.trim(),
      })
      setMain(null)
      setDark(null)
      setDarkRemove(false)
      setPlate(null)
      setTitle(null)
      setSaved(true)
      await onChanged()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  async function reset() {
    setBusy(true)
    setError('')
    setSaved(false)
    try {
      await resetBranding()
      setMain(null)
      setDark(null)
      setDarkRemove(false)
      setPlate(null)
      setTitle(null)
      await onChanged()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  async function saveCompany() {
    setBusy(true)
    setCompanyError('')
    setCompanySaved(false)
    try {
      await saveCompanyName(companyName.trim())
      await onChanged()
      setCompanyDraft(null)
      setCompanySaved(true)
    } catch (e) {
      setCompanyError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const previews = [
    { theme: 'dark', label: t('тёмная тема'), view: views.dark, fallback: (darkSrc ?? mainSrc)?.url ?? '' },
    { theme: 'light', label: t('светлая тема'), view: views.light, fallback: mainSrc?.url ?? '' },
  ]

  return (
    <div className="about-branding">
      <button className="ghost small-btn" onClick={() => setOpen(!open)}>
        {open ? t('Свернуть') : t('Поставить свой логотип')}
      </button>

      {open && (
        <div className="brand-form">
          <label className="brand-field">
            <span>
              {t('Файл логотипа')}{' '}
              <span className="muted small">{t('PNG, SVG, WebP или JPEG до {n} КБ', { n: MAX_KB })}</span>
            </span>
            {/* Ключ по версии: после сохранения поле пустеет, а не показывает имя
                уже сохраненного файла, как будто его еще предстоит загрузить. */}
            <input
              key={version}
              type="file"
              accept={ACCEPT}
              disabled={logoLocked}
              onChange={async (e) => {
                const got = await read(e.target.files?.[0])
                if (got) setMain(got)
              }}
            />
          </label>

          {mainSrc && (
            <>
              <div className="brand-previews">
                {previews.map((preview) => (
                  <div key={preview.theme} className={`brand-preview brand-preview-${preview.theme}`}>
                    <span className="brand-preview-label">{preview.label}</span>
                    <span className={`brand-custom${preview.view?.plate ? ' brand-plate' : ''}`}>
                      <img
                        src={preview.view?.src ?? preview.fallback}
                        alt=""
                        style={preview.view ? undefined : { visibility: 'hidden' }}
                      />
                    </span>
                  </div>
                ))}
              </div>

              <label className="brand-field">
                {t('Вариант для тёмной темы')}
                <input
                  key={version}
                  type="file"
                  accept={ACCEPT}
                  disabled={logoLocked}
                  onChange={async (e) => {
                    const got = await read(e.target.files?.[0])
                    if (got) {
                      setDark(got)
                      setDarkRemove(false)
                    }
                  }}
                />
              </label>
              {hasDark && (
                <button
                  className="ghost small-btn brand-dark-remove"
                  disabled={logoLocked}
                  onClick={() => {
                    setDark(null)
                    setDarkRemove(true)
                  }}
                >
                  {t('Убрать вариант для тёмной темы')}
                </button>
              )}
            </>
          )}

          <label className="brand-field">
            {t('Оформление')}
            <select disabled={logoLocked} value={plate} onChange={(e) => setPlate(e.target.value as Branding['plate'])}>
              <option value="auto">{t('авто: подстроить цвета под тему')}</option>
              <option value="always">{t('всегда на плашке')}</option>
              <option value="never">{t('как есть')}</option>
            </select>
          </label>

          <label className="brand-field">
            {t('Подпись на экране входа')}
            <input
              value={title}
              disabled={logoLocked}
              maxLength={64}
              placeholder={t('например, название компании')}
              onChange={(e) => setTitle(e.target.value)}
            />
          </label>

          {error && <p className="form-error">{error}</p>}

          <div className="row-actions">
            <button disabled={logoLocked || !mainSrc} onClick={() => void save()}>
              {t('Сохранить логотип')}
            </button>
            {branding?.logo && (
              <button className="ghost" disabled={logoLocked} onClick={() => void reset()}>
                {t('Вернуть стандартный')}
              </button>
            )}
            {saved && <span className="muted small">{t('сохранено')}</span>}
          </div>
        </div>
      )}
      {supportsCompanyName && <form
        className="brand-form"
        onSubmit={(event) => {
          event.preventDefault()
          if (canSaveCompany) void saveCompany()
        }}
      >
        <label className="brand-field">
          {t('Название компании')}
          <input
            value={companyName}
            maxLength={64}
            disabled={busy}
            aria-describedby="company-name-help"
            onChange={(event) => {
              setCompanyDraft(event.target.value)
              setCompanyError('')
              setCompanySaved(false)
            }}
          />
        </label>
        <span id="company-name-help" className="muted small">
          {t('Показывается во вкладке браузера еще до входа. Пустое поле вернет стандартный заголовок.')}
        </span>
        {companyError && (
          <p className="form-error" role="alert">
            {companyError}
          </p>
        )}
        <div className="row-actions">
          <button type="submit" disabled={!canSaveCompany}>
            {t('Сохранить название')}
          </button>
          {companySaved && (
            <span className="muted small" role="status">
              {t('сохранено')}
            </span>
          )}
        </div>
      </form>}
    </div>
  )
}
