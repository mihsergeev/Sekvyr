/* Логотип из бренд-кита. Рендерим обе версии сразу, а тема прячет лишнюю:
 * подменять src по текущей теме - значит моргать логотипом при переключении и
 * ловить рассинхрон, когда тема применяется до загрузки картинки.
 *
 * Суффикс light - светлый знак для темного фона, dark - наоборот: так подписан
 * сам бренд-кит.
 */

import horizontalDark from './assets/sekvyr-horizontal-dark.svg'
import horizontalLight from './assets/sekvyr-horizontal-light.svg'
import lockupDark from './assets/sekvyr-lockup-dark.svg'
import lockupLight from './assets/sekvyr-lockup-light.svg'
import markDark from './assets/sekvyr-mark-dark.svg'
import markLight from './assets/sekvyr-mark-light.svg'

// Минимальные ширины из бренд-кита: ниже знак теряет читаемость.
const MIN = { horizontal: 140, lockup: 96, mark: 40 } as const

// Размеры по умолчанию. Файлы для панели обрезаны по рисунку, поэтому ширина
// здесь - это ширина самого логотипа, а не холста с полями вокруг него.
const SIZE = { horizontal: 240, lockup: 190, mark: 84 } as const

type Props = {
  /** horizontal - в шапке, lockup - на карточке входа, mark - знак без надписи */
  variant?: 'horizontal' | 'lockup' | 'mark'
  width?: number
}

export function Logo({ variant = 'horizontal', width }: Props) {
  const w = Math.max(width ?? SIZE[variant], MIN[variant])
  // Высоту не считаем: пропорцию знает сам файл. Раньше она была вписана сюда
  // числом, и стоило кадру в файле измениться - логотип плющило.
  const style = { width: w, height: 'auto' } as const
  return (
    <span className="brand-img" style={{ width: w }}>
      <img
        className="brand-when-dark"
        src={{ horizontal: horizontalLight, lockup: lockupLight, mark: markLight }[variant]}
        style={style}
        alt="Sekvyr"
      />
      <img
        className="brand-when-light"
        src={{ horizontal: horizontalDark, lockup: lockupDark, mark: markDark }[variant]}
        style={style}
        alt="Sekvyr"
      />
    </span>
  )
}
