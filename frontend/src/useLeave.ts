import { useCallback, useEffect, useRef } from 'react'
import { useDialogs } from './Dialogs'
import { useI18n } from './i18n'
import { holdLeave } from './leave'

/* Окно с набранным, но не сохраненным.
 *
 * Escape, "Отмена" и переход по разделам ("g p", палитра, "назад") раньше
 * молча выбрасывали набранное: значение, которое человек полчаса собирал из
 * трех мест, пропадало от одной клавиши. Теперь сначала вопрос. Пустое окно и
 * окно без правок закрываются, как раньше, без вопросов.
 *
 * Возвращает то, что надо звать вместо onClose.
 */
export function useLeave(dirty: boolean, onClose: () => void): () => void {
  const { confirm } = useDialogs()
  const { t } = useI18n()

  const ask = useCallback(
    () =>
      confirm({
        title: t('Закрыть без сохранения?'),
        text: t('Набранное не сохранено и пропадет.'),
        submit: t('Закрыть'),
        danger: true,
      }),
    [confirm, t],
  )

  useEffect(() => {
    if (!dirty) return
    return holdLeave(ask)
  }, [dirty, ask])

  const latest = useRef({ dirty, onClose })
  latest.current = { dirty, onClose }

  return useCallback(() => {
    if (!latest.current.dirty) return latest.current.onClose()
    void ask().then((ok) => {
      if (ok) latest.current.onClose()
    })
  }, [ask])
}
