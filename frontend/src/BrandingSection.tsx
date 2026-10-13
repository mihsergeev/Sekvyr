/* Настройка своего логотипа - в "О панели", свернутой: её трогают один раз за
 * жизнь установки, и отдельный пункт меню выглядел бы важнее, чем она есть.
 *
 * Превью сразу на обеих темах и считается тем же кодом, что и шапка: что видно
 * здесь, то и будет в панели. Типовая ошибка - залить логотип, который хорош на
 * белом и пропадает на темном, и узнать об этом, когда панель откроет коллега с
 * другой темой.
 */

import { useState } from 'react'
import { ApiError, brandingUrl, resetBranding, saveBranding, type Branding } from './api'
import { useLogoViews } from './BrandLogo'
import type { LogoSource } from './logoAdapt'
import { useI18n } from './i18n'

const MAX_KB = 512
const ACCEPT = 'image/png,image/svg+xml,image/webp,image/jpeg,image/gif'

export function BrandingSection({
  branding,
  onChanged,
}: {
  branding: Branding | null
  onChanged: (next: Branding) => void
}) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  // Выбранные, но еще не сохраненные файлы: data-URL и текст, если это SVG.
  const [main, setMain] = useState<LogoSource | null>(null)
  const [dark, setDark] = useState<LogoSource | null>(null)
  const [darkRemove, setDarkRemove] = useState(false)
  const [plate, setPlate] = useState<Branding['plate']>(branding?.plate ?? 'auto')
  const [title, setTitle] = useState(branding?.title ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  const version = branding?.version ?? 0
  const storedDark = !!branding?.dark_logo && !darkRemove
  const hasDark = !!dark || storedDark
  const mainSrc: LogoSource | null = main ?? (branding?.logo ? { url: brandingUrl(version) } : null)
  const darkSrc: LogoSource | null = dark ?? (storedDark ? { url: brandingUrl(version, true) } : null)
  const views = useLogoViews(mainSrc, darkSrc, plate)

  async function read(file: File | undefined): Promise<LogoSource | null> {
    setError('')
    setSaved(false)
    if (!file) return null
    if (file.size > MAX_KB * 1024) {
      setError(t('Файл больше {n} КБ — уменьшите логотип', { n: MAX_KB }))
      return null
    }
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
    }
  }

  async function save() {
    setBusy(true)
    setError('')
    setSaved(false)
    try {
      const next = await saveBranding({
        data: main?.url ?? '',
        dark: dark?.url ?? '',
        dark_remove: darkRemove && !dark,
        plate,
        title: title.trim(),
      })
      setMain(null)
      setDark(null)
      setDarkRemove(false)
      setSaved(true)
      onChanged(next)
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
      const next = await resetBranding()
      setMain(null)
      setDark(null)
      setDarkRemove(false)
      setPlate('auto')
      setTitle('')
      onChanged(next)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
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
            <select value={plate} onChange={(e) => setPlate(e.target.value as Branding['plate'])}>
              <option value="auto">{t('авто: подстроить цвета под тему')}</option>
              <option value="always">{t('всегда на плашке')}</option>
              <option value="never">{t('как есть')}</option>
            </select>
          </label>

          <label className="brand-field">
            {t('Подпись на экране входа')}
            <input
              value={title}
              maxLength={64}
              placeholder={t('например, название компании')}
              onChange={(e) => setTitle(e.target.value)}
            />
          </label>

          {error && <p className="form-error">{error}</p>}

          <div className="row-actions">
            <button disabled={busy || !mainSrc} onClick={() => void save()}>
              {t('Сохранить логотип')}
            </button>
            {branding?.logo && (
              <button className="ghost" disabled={busy} onClick={() => void reset()}>
                {t('Вернуть стандартный')}
              </button>
            )}
            {saved && <span className="muted small">{t('сохранено')}</span>}
          </div>
        </div>
      )}
    </div>
  )
}
