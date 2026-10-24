/* Копирование в буфер обмена.
 *
 * Современный путь (`navigator.clipboard`) работает не везде: в незащищенном
 * контексте и в некоторых встроенных браузерах его просто нет, а иногда он есть
 * и отказывает без объяснений. Поэтому запасной путь - временное поле и
 * `execCommand`: он старый, но работает там, где новый молчит.
 *
 * Возвращаем честный ответ, скопировалось или нет: тому, кто копирует секрет,
 * нельзя показывать "готово", если в буфере пусто.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // Падаем в запасной путь: причина отказа нам не поможет.
  }

  try {
    const field = document.createElement('textarea')
    field.value = text
    // Вне экрана, но в документе: невидимое поле не выделяется.
    field.style.position = 'fixed'
    field.style.opacity = '0'
    field.style.pointerEvents = 'none'
    document.body.appendChild(field)
    field.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(field)
    return ok
  } catch {
    return false
  }
}

/** Сколько скопированный секрет живет в буфере обмена. */
export const CLIPBOARD_FORGET_MS = 45_000

let pending: (() => void) | null = null

/* Скопированный секрет не остается в буфере навсегда.
 *
 * Через время буфер чистится, но только если там все еще наш секрет: затереть
 * то, что человек скопировал после, хуже, чем оставить пароль. Узнать это,
 * не прочитав буфер, нельзя, а чтение спрашивает разрешение, поэтому:
 *
 * - чтение уже разрешено (браузер не спросит) - читаем и сравниваем;
 * - иначе чистим, только если вкладка все это время не теряла фокус и в ней
 *   ничего не копировали: тогда положить в буфер другое было нечем;
 * - вкладку покидали - не трогаем. Обычно так и бывает: секрет копируют,
 *   чтобы вставить в другом окне, и после этого буфер уже не наш.
 *
 * Без navigator.clipboard (панель по http) чистить нечем: запасной путь через
 * execCommand работает только по нажатию. */
export function forgetLater(text: string, after = CLIPBOARD_FORGET_MS): void {
  pending?.()
  if (!navigator.clipboard?.writeText) return
  let left = false
  const away = () => {
    left = true
  }
  window.addEventListener('blur', away)
  document.addEventListener('copy', away)
  document.addEventListener('cut', away)
  const timer = window.setTimeout(() => {
    stop()
    void clearIfOurs(text, left)
  }, after)
  const stop = () => {
    window.clearTimeout(timer)
    window.removeEventListener('blur', away)
    document.removeEventListener('copy', away)
    document.removeEventListener('cut', away)
    if (pending === stop) pending = null
  }
  // Следующее копирование ставит свой таймер: два секрета подряд не должны
  // чистить буфер дважды, второй раз уже по чужому значению.
  pending = stop
}

async function clearIfOurs(text: string, left: boolean): Promise<void> {
  try {
    if (await mayRead()) {
      if ((await navigator.clipboard.readText()) === text) {
        await navigator.clipboard.writeText('')
      }
      return
    }
    if (!left && document.hasFocus()) await navigator.clipboard.writeText('')
  } catch {
    // Браузер отказал (вкладка не в фокусе, разрешение отозвали): оставляем.
  }
}

async function mayRead(): Promise<boolean> {
  try {
    const state = await navigator.permissions?.query({ name: 'clipboard-read' as PermissionName })
    return state?.state === 'granted' && Boolean(navigator.clipboard.readText)
  } catch {
    // Firefox и Safari такого имени разрешения не знают.
    return false
  }
}
