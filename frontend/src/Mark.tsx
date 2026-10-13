import type { ReactNode } from 'react'

/* Подсветка совпадения в результате поиска.
 *
 * Выдача в три десятка строк, где все строки похожи, читается плохо: глазу не
 * за что зацепиться, а совпало обычно два символа из двадцати.
 */
export function Mark({ text, needle }: { text: string; needle: string }): ReactNode {
  const query = needle.trim().toLowerCase()
  if (!query) return text
  const at = text.toLowerCase().indexOf(query)
  if (at < 0) return text
  return (
    <>
      {text.slice(0, at)}
      <mark className="hit">{text.slice(at, at + query.length)}</mark>
      {text.slice(at + query.length)}
    </>
  )
}
