/* Адреса сервера: внешний (глобус) и локальный (домик).
 *
 * Внешний панель видит сама - это адрес, с которого пришел агент. Локальный
 * знает только сам сервер, и присылает его отчетом: на вопрос "куда я сейчас
 * зайду" отвечает именно он, а не публичный адрес балансировщика.
 *
 * Локальный показываем, только если он отличается от внешнего: у машины с белым
 * адресом это одно и то же число, и печатать его дважды незачем.
 */

import { useI18n } from './i18n'

function AddrIcon({ kind }: { kind: 'ext' | 'loc' }) {
  return (
    <svg
      className="srv-addr-ic"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {kind === 'ext' ? (
        <>
          <circle cx="12" cy="12" r="9" />
          <path d="M3 12h18" />
          <path d="M12 3c2.6 2.6 2.6 15.4 0 18" />
          <path d="M12 3c-2.6 2.6-2.6 15.4 0 18" />
        </>
      ) : (
        <>
          <path d="M3 11l9-7 9 7" />
          <path d="M5 10.5V20h14v-9.5" />
        </>
      )}
    </svg>
  )
}

export function ServerAddr({ external, local }: { external?: string; local?: string }) {
  const { t } = useI18n()
  const ext = (external || '').trim()
  const loc = (local || '').trim()
  const showLocal = loc && loc !== ext
  if (!ext && !showLocal) return null
  return (
    <span className="srv-addr mono small muted">
      {ext && (
        <span className="srv-addr-part" title={t('внешний адрес: с него приходит агент')}>
          <AddrIcon kind="ext" />
          {ext}
        </span>
      )}
      {showLocal && (
        <span className="srv-addr-part" title={t('локальный адрес во внутренней сети')}>
          <AddrIcon kind="loc" />
          {loc}
        </span>
      )}
    </span>
  )
}
