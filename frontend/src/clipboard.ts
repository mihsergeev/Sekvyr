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
