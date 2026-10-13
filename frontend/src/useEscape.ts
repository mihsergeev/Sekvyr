import { useEffect, useRef } from 'react'

/* Esc закрывает окно.
 *
 * Клик мимо окна не закрывает ничего: в этих окнах набирают значения руками, и
 * промах мышью не повод потерять набранное. Значит, у клавиатуры должен быть
 * привычный выход - иначе единственный способ уйти это найти кнопку.
 *
 * Закрывается только верхнее окно. Слушатель у каждого окна свой, и раньше
 * Escape в вопросе поверх настроек проекта закрывал оба: вопрос и настройки
 * под ним вместе с набранным. Теперь окна стоят стопкой в порядке открытия, и
 * клавиша достается последнему.
 */
const stack: { close: () => void }[] = []

function onKey(e: KeyboardEvent) {
  if (e.key !== 'Escape') return
  stack[stack.length - 1]?.close()
}

export function useEscape(onClose: () => void, active = true): void {
  const latest = useRef(onClose)
  useEffect(() => {
    latest.current = onClose
  })

  useEffect(() => {
    // Выпадающее меню тоже закрывается Escape, но в стопку оно попадает только
    // пока открыто: иначе каждое меню на странице ловило бы чужой Escape.
    if (!active) return
    const entry = { close: () => latest.current() }
    stack.push(entry)
    if (stack.length === 1) window.addEventListener('keydown', onKey)
    return () => {
      const at = stack.indexOf(entry)
      if (at >= 0) stack.splice(at, 1)
      if (stack.length === 0) window.removeEventListener('keydown', onKey)
    }
  }, [active])
}
