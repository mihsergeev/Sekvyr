import type { ReactNode } from 'react'
import { useI18n } from './i18n'

/* Ошибка и предупреждение выглядят одинаково во всей панели.
 *
 * Раньше каждая страница печатала ошибку своим абзацем: где-то красным, где-то
 * серым, в разном месте экрана и без возможности убрать. Ошибка, которую нельзя
 * закрыть, висит до перезагрузки и потом мешает читать то, ради чего пришли.
 */

export function ErrorNote({ text, onClose }: { text: string; onClose?: () => void }) {
  const { t } = useI18n()
  if (!text) return null
  return (
    <div className="note note-error" role="alert">
      <span className="note-text">{text}</span>
      {onClose && (
        <button className="ghost small-btn note-close" onClick={onClose} aria-label={t('Закрыть')}>
          ✕
        </button>
      )}
    </div>
  )
}

/** То, что нужно прочитать сейчас: ключ показывается один раз, доступ выдан. */
export function WarnNote({ children }: { children: ReactNode }) {
  return <div className="note note-warn">{children}</div>
}

/** Полосы вместо списка, пока идет первый запрос.
 *
 * Пустое состояние до ответа сервера врет: "проектов пока нет" и через миг -
 * список из тринадцати. Полосы говорят честно: содержимое еще едет. */
export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="skeleton" aria-hidden>
      {Array.from({ length: rows }, (_, index) => (
        <span key={index} className="skeleton-row" />
      ))}
    </div>
  )
}
