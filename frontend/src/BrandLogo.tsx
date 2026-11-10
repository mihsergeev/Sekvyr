/* Логотип панели: свой, если его поставили, иначе стандартный Sekvyr.
 *
 * Чужая картинка приходит любой: от узкой полоски до квадрата, с фоном и без,
 * нарисованная под белый фон или под темный. Высоту держит контейнер, картинка
 * вписывается внутрь - тогда шапка не прыгает от того, какой файл залили. Под
 * тему логотип подстраивает logoAdapt.ts.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { brandingUrl, getBranding, type Branding } from './api'
import { Logo } from './Logo'
import { evictLogoView, logoView, type LogoMode, type LogoSource, type LogoView } from './logoAdapt'

function useLogoView(source: LogoSource | null, theme: 'dark' | 'light', mode: LogoMode) {
  const [result, setResult] = useState<{ key: string; view: LogoView } | null>(null)
  const url = source?.url ?? ''
  const svg = source?.svg
  const key = JSON.stringify([url, mode, svg])
  useEffect(() => {
    if (!url) return
    let active = true
    void logoView({ url, svg }, theme, mode)
      .catch(() => ({ src: url, adapted: false, plate: mode === 'always' }))
      .then((view) => {
        if (active) setResult({ key, view })
      })
    return () => {
      active = false
    }
  }, [key, url, svg, theme, mode])
  return result?.key === key ? result.view : null
}

/** Как показать логотип на обеих темах; null - еще считается. */
export function useLogoViews(main: LogoSource | null, dark: LogoSource | null, mode: LogoMode) {
  const forDark = useLogoView(dark ?? main, 'dark', mode)
  const forLight = useLogoView(main, 'light', mode)
  return { dark: forDark, light: forLight }
}

function LogoVariant({ primary, fallback, mode, theme, title, where }: {
  primary: string
  fallback?: string
  mode: LogoMode
  theme: 'dark' | 'light'
  title: string
  where: 'header' | 'login'
}) {
  const [failed, setFailed] = useState<string[]>([])
  const source = [primary, fallback].find((url) => url && !failed.includes(url))
  const view = useLogoView(source ? { url: source } : null, theme, mode)

  useEffect(() => {
    if (!failed.length) return
    const retry = () => {
      failed.forEach((url) => evictLogoView(url, theme, mode))
      setFailed([])
    }
    window.addEventListener('focus', retry)
    return () => window.removeEventListener('focus', retry)
  }, [failed, mode, theme])

  if (!source) {
    return <span className={`brand-when-${theme}`}>
      {where === 'header' ? <Logo width={168} /> : <Logo variant="lockup" width={200} />}
    </span>
  }
  return (
    <span className={`brand-custom brand-when-${theme}${view?.plate ? ' brand-plate' : ''}`}>
      {view && <img
        key={source}
        src={view.src}
        alt={title || 'logo'}
        onError={() => setFailed((previous) => [...previous, source])}
      />}
    </span>
  )
}

/** Логотип в шапке или на экране входа. */
export function BrandLogo({ where, branding }: {
  where: 'header' | 'login'
  branding: Branding | null
}) {
  if (!branding?.logo) {
    return where === 'header' ? <Logo width={168} /> : <Logo variant="lockup" width={200} />
  }
  const main = brandingUrl(branding)
  const dark = branding.dark_logo ? brandingUrl(branding, true) : main
  return (
    <span className={`brand-own brand-${where}`}>
      <LogoVariant key={dark} primary={dark} fallback={dark === main ? undefined : main}
        theme="dark" mode={branding.plate} title={branding.title} where={where} />
      <LogoVariant key={`light:${main}`} primary={main}
        theme="light" mode={branding.plate} title={branding.title} where={where} />
      {where === 'login' && branding.title && <span className="brand-title">{branding.title}</span>}
    </span>
  )
}

/** Настройки логотипа. Грузятся до входа: они нужны экрану входа. */
export function useBranding() {
  const [branding, setBranding] = useState<Branding | null>(null)
  const [brandingStatus, setStatus] = useState<'loading' | 'ready' | 'error'>('loading')
  const generation = useRef(0)
  const channel = useRef<BroadcastChannel | null>(null)
  const refreshBranding = useCallback(async () => {
    const request = ++generation.current
    setStatus('loading')
    try {
      const next = await getBranding()
      if (request !== generation.current) return
      setBranding(next)
      setStatus('ready')
    } catch {
      if (request === generation.current) setStatus('error')
    }
  }, [])
  const changeBranding = useCallback(() => {
    // Ответ на запись может прийти позже правки из соседней вкладки.
    channel.current?.postMessage('changed')
    return refreshBranding()
  }, [refreshBranding])
  useEffect(() => {
    void refreshBranding()
    window.addEventListener('focus', refreshBranding)
    if (typeof BroadcastChannel !== 'undefined') {
      channel.current = new BroadcastChannel('sekvyr-branding')
      channel.current.onmessage = () => void refreshBranding()
    }
    return () => {
      ++generation.current
      window.removeEventListener('focus', refreshBranding)
      channel.current?.close()
      channel.current = null
    }
  }, [refreshBranding])
  return { branding, brandingStatus, refreshBranding, changeBranding }
}
