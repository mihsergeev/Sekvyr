/* Сравнение версий агента.
 *
 * Числами, а не строками: как строки "0.9.0" больше "0.10.0", и панель
 * показывала бы "устарел" тем, кто уже на свежем. Непонятная версия считается
 * не новее - молчание здесь честнее выдумки.
 *
 * Та же логика живет в агенте (agent/main.go): там она решает, ставить ли
 * обновление, здесь - показывать ли пометку. Одно правило на два места.
 */

function parts(version: string): number[] | null {
  let text = version.trim()
  const tail = text.search(/[-+]/)
  if (tail >= 0) text = text.slice(0, tail)
  if (!text) return null
  const out: number[] = []
  for (const chunk of text.split('.')) {
    if (!/^\d+$/.test(chunk)) return null
    out.push(Number(chunk))
  }
  return out
}

/** Строго ли версия a новее b. */
export function newerVersion(a: string, b: string): boolean {
  const x = parts(a)
  const y = parts(b)
  if (!x || !y) return false
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const xi = x[i] ?? 0
    const yi = y[i] ?? 0
    if (xi !== yi) return xi > yi
  }
  return false
}
