/* Значки рисуем сами: их всего пара, а библиотека иконок - это еще одна
 * зависимость в панели, которая хранит чужие секреты, ради двух путей.
 *
 * Цвет берется от текста (currentColor), размер задается кеглем: значок рядом с
 * подписью должен меняться вместе с ней, а не жить своей жизнью.
 */

type Props = { size?: number }

export function EyeIcon({ size = 16 }: Props) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M2 12s3.5-6.5 10-6.5S22 12 22 12s-3.5 6.5-10 6.5S2 12 2 12Z" />
      <circle cx="12" cy="12" r="2.8" />
    </svg>
  )
}

export function EyeOffIcon({ size = 16 }: Props) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M10.7 6.1A9.9 9.9 0 0 1 12 5.5c6.5 0 10 6.5 10 6.5a17 17 0 0 1-3.3 4.1" />
      <path d="M6.3 7.9A17 17 0 0 0 2 12s3.5 6.5 10 6.5c1.4 0 2.6-.2 3.7-.6" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
      <path d="m3.5 3.5 17 17" />
    </svg>
  )
}
