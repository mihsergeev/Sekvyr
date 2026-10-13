import { Fragment } from 'react'
import { useI18n } from './i18n'
import { useEscape } from './useEscape'

/* Что умеет клавиатура.
 *
 * Сочетания были, но узнать о них можно было только из подсказки на вкладке -
 * то есть случайно. Список открывается по "?" и живет одним экраном: их
 * немного, и все помещаются.
 */

// i18n
const ROWS: [string, string][] = [
  ['Ctrl K', 'перейти куда угодно'],
  ['/', 'поиск на странице'],
  ['g p', 'проекты'],
  ['g v', 'сейф'],
  ['g a', 'доступ'],
  ['g u', 'учётные записи'],
  ['g s', 'серверы'],
  ['g l', 'журнал'],
  ['g o', 'обслуживание'],
  ['g m', 'перенос'],
  ['↑ ↓', 'по списку ключей'],
  ['Enter', 'открыть строку'],
  ['Ctrl+Enter', 'сохранить значение'],
  ['Esc', 'закрыть окно или меню'],
]

export function Hotkeys({ onClose }: { onClose: () => void }) {
  const { t } = useI18n()
  useEscape(onClose)

  return (
    <div className="modal-backdrop">
      <div className="card modal stack">
        <h3>{t('Сочетания клавиш')}</h3>
        <p className="muted small">
          {t('Работают, пока курсор не стоит в поле ввода. Буквы можно набирать в любой раскладке.')}
        </p>
        <div className="ops-facts">
          {ROWS.map(([keys, what]) => (
            <Fragment key={keys}>
              <span className="mono small">{keys}</span>
              <span className="muted small">{t(what)}</span>
            </Fragment>
          ))}
        </div>
        <div className="row-actions dialog-actions">
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>
      </div>
    </div>
  )
}
