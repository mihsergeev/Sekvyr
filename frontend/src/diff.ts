/* Построчная разница двух значений - как в git.
 *
 * Свой алгоритм вместо библиотеки: нужен ровно один десяток строк, а каждая
 * зависимость в панели с секретами - это еще один автор, которому приходится
 * доверять на глаз.
 */

export type DiffLine = { sign: ' ' | '-' | '+'; text: string }

// Матрица наибольшей общей подпоследовательности квадратична по числу строк.
// На значении в тысячу строк её незачем считать: там и читать построчно уже
// нечего, достаточно показать "было" и "стало".
const MAX_LINES = 400

export function lineDiff(before: string, after: string): DiffLine[] {
  const a = before === '' ? [] : before.split('\n')
  const b = after === '' ? [] : after.split('\n')

  if (a.length > MAX_LINES || b.length > MAX_LINES) {
    return [
      ...a.map((text) => ({ sign: '-' as const, text })),
      ...b.map((text) => ({ sign: '+' as const, text })),
    ]
  }

  const n = a.length
  const m = b.length
  const lcs: number[][] = Array.from({ length: n + 1 }, () =>
    Array.from<number>({ length: m + 1 }).fill(0),
  )
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1])
    }
  }

  const out: DiffLine[] = []
  let i = 0
  let j = 0
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ sign: ' ', text: a[i] })
      i++
      j++
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ sign: '-', text: a[i] })
      i++
    } else {
      out.push({ sign: '+', text: b[j] })
      j++
    }
  }
  while (i < n) out.push({ sign: '-', text: a[i++] })
  while (j < m) out.push({ sign: '+', text: b[j++] })
  return out
}

/** Коротко: сколько строк добавлено и убрано. Для подписи вида "+1 -1". */
export function diffCounts(lines: DiffLine[]): { added: number; removed: number } {
  let added = 0
  let removed = 0
  for (const line of lines) {
    if (line.sign === '+') added++
    if (line.sign === '-') removed++
  }
  return { added, removed }
}
