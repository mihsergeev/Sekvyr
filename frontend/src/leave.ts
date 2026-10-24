/* Уход со страницы, на которой осталось то, что второй раз не покажут: новые
 * доли и ключ сейфа. Страница ставит проверку, навигация панели спрашивает ее
 * перед переходом. Закрытие вкладки ловит beforeunload самой страницы. */

type Guard = () => Promise<boolean>

let guard: Guard | null = null

// Окна с несохраненной правкой. Их может быть несколько сразу, и снимает
// каждое только свою проверку, поэтому они не делят слот страницы: окно,
// закрывшись, снимало бы защиту долей сейфа.
const held: Guard[] = []

export function setLeaveGuard(next: Guard | null): void {
  guard = next
}

/** Поставить проверку на время, пока окно держит набранное. Возвращает
 *  функцию, которая ее снимает. */
export function holdLeave(next: Guard): () => void {
  held.push(next)
  return () => {
    const at = held.indexOf(next)
    if (at >= 0) held.splice(at, 1)
  }
}

export function leaveGuard(): Guard | null {
  // Набранное спрашивает один раз, верхним окном: окно правки поверх строки с
  // черновиком давало два вопроса "не сохранено" на один переход. Защита
  // страницы (доли сейфа) спрашивает отдельно, у нее свой текст.
  const top = held.at(-1) ?? null
  const page = guard
  if (!top) return page
  if (!page) return top
  return async () => (await top()) && (await page())
}
