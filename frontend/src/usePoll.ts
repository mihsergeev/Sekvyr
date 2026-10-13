import { useEffect } from 'react'

/* Тихое обновление списка.
 *
 * Панель показывает состояние, которое меняется без участия того, кто смотрит:
 * агент отчитался, кто-то записал значение, кому-то отказали во входе. Открытая
 * страница застывала в том виде, в каком загрузилась, а "минуту назад" под
 * именем сервера через полчаса - уже неправда.
 *
 * В фоновой вкладке не тикаем: обновлять то, чего никто не видит, значит
 * держать соединение и будить сервер без причины. Зато при возвращении в
 * вкладку обновляем сразу - именно в этот момент на экран и смотрят.
 */
export function usePoll(action: () => void, ms: number, active = true): void {
  useEffect(() => {
    if (!active || ms <= 0) return

    // Помним, когда обновляли: вкладку показывают и прячут десятки раз за
    // минуту (переключение окон, снимок экрана), и каждый такой переход не
    // повод идти в сеть.
    let last = Date.now()
    const tick = () => {
      if (document.hidden) return
      if (Date.now() - last < ms) return
      last = Date.now()
      action()
    }
    const timer = window.setInterval(tick, Math.max(1000, Math.floor(ms / 3)))
    document.addEventListener('visibilitychange', tick)
    return () => {
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', tick)
    }
  }, [action, ms, active])
}
