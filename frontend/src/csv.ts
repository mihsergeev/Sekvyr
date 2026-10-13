// Текст ячейки CSV, который таблица не примет за формулу. Ячейка, что
// начинается с = + - @ или табуляции, в Excel и LibreOffice становится
// формулой, а имя пользователя в журнал может записать кто угодно, просто
// попытавшись войти. Апостроф впереди оставляет ее текстом.
export function csvText(value: string | null | undefined): string {
  const text = value ?? ''
  return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text
}
