/* Логотип панели: свой, если его поставили, иначе стандартный Sekvyr.
 *
 * Чужая картинка приходит любой: от узкой полоски до квадрата, с фоном и без,
 * нарисованная под белый фон или под темный. Высоту держит контейнер, картинка
 * вписывается внутрь - тогда шапка не прыгает от того, какой файл залили. Под
 * тему логотип подстраивает logoAdapt.ts.
 */

import { useEffect, useState } from 'react'
import { brandingUrl, getBranding, type Branding } from './api'
import { Logo } from './Logo'
import { logoView, type LogoMode, type LogoSource, type LogoView } from './logoAdapt'

/** Как показать логотип на обеих темах; null - еще считается. */
export function useLogoViews(
  main: LogoSource | null,
  dark: LogoSource | null,
  mode: LogoMode,
): { dark: LogoView | null; light: LogoView | null } {
  const [views, setViews] = useState<{ key: string; dark: LogoView; light: LogoView } | null>(null)
  const key = main ? `${mode}|${main.url}|${dark?.url ?? ''}` : ''
  useEffect(() => {
    if (!main) return
    let alive = true
    // Свой вариант для темной темы тоже подстраивается: залитый по ошибке темный
    // вариант иначе пропал бы на темном фоне.
    Promise.all([logoView(dark ?? main, 'dark', mode), logoView(main, 'light', mode)])
      .then(([forDark, forLight]) => alive && setViews({ key, dark: forDark, light: forLight }))
      .catch(() => undefined)
    return () => {
      alive = false
    }
    // Источники меняются вместе с ключом, а сами объекты пересоздаются при каждой
    // отрисовке - зависеть от них значило бы считать заново без конца.
  }, [key])
  return views && views.key === key ? views : { dark: null, light: null }
}

/** Логотип в шапке или на экране входа. */
export function BrandLogo({
  where,
  branding,
}: {
  where: 'header' | 'login'
  branding: Branding | null
}) {
  // Картинка могла пропасть из базы (восстановили старый дамп). Битый значок в
  // шапке хуже честного стандартного логотипа.
  const [broken, setBroken] = useState(false)
  const version = branding?.version ?? 0
  useEffect(() => {
    setBroken(false)
  }, [version])

  const has = !!branding?.logo
  const main = has ? { url: brandingUrl(version) } : null
  const dark = has && branding?.dark_logo ? { url: brandingUrl(version, true) } : null
  const views = useLogoViews(main, dark, branding?.plate ?? 'auto')

  if (!branding?.logo || broken) {
    return where === 'header' ? <Logo width={168} /> : <Logo variant="lockup" width={200} />
  }
  // Обе темы сразу, лишнюю прячет CSS - как у стандартного логотипа: переключение
  // темы не ждет перерисовки. Пока перекраска считается, место держим пустым:
  // мелькнуть темной надписью на темной шапке хуже, чем появиться чуть позже.
  const variants = [
    { theme: 'brand-when-dark', view: views.dark, fallback: (dark ?? main)?.url ?? '' },
    { theme: 'brand-when-light', view: views.light, fallback: main?.url ?? '' },
  ]
  return (
    <span className={`brand-own brand-${where}`}>
      {variants.map((variant) => (
        <span
          key={variant.theme}
          className={`brand-custom ${variant.theme}${variant.view?.plate ? ' brand-plate' : ''}`}
        >
          <img
            src={variant.view?.src ?? variant.fallback}
            alt={branding.title || 'logo'}
            style={variant.view ? undefined : { visibility: 'hidden' }}
            onError={() => setBroken(true)}
          />
        </span>
      ))}
      {where === 'login' && branding.title && <span className="brand-title">{branding.title}</span>}
    </span>
  )
}

/** Настройки логотипа. Грузятся до входа: они нужны экрану входа. */
export function useBranding(): [Branding | null, (next: Branding) => void] {
  const [branding, setBranding] = useState<Branding | null>(null)
  useEffect(() => {
    let alive = true
    getBranding()
      .then((next) => alive && setBranding(next))
      // Молча: без настроек просто остается стандартный логотип.
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [])
  return [branding, setBranding]
}
