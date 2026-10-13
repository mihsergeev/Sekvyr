/* Уход со страницы, на которой осталось то, что второй раз не покажут: новые
 * доли и ключ сейфа. Страница ставит проверку, навигация панели спрашивает ее
 * перед переходом. Закрытие вкладки ловит beforeunload самой страницы. */

type Guard = () => Promise<boolean>

let guard: Guard | null = null

export function setLeaveGuard(next: Guard | null): void {
  guard = next
}

export function leaveGuard(): Guard | null {
  return guard
}
