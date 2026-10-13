import { useEffect, useMemo, useRef, useState } from 'react'
import { useI18n } from './i18n'

/* Поле с подсказками: выбрать существующее или ввести свое.
 *
 * Нативный `datalist` умеет то же самое, но выпадающий список рисует браузер -
 * в темной теме он белый и выглядит ровно как те системные окна, от которых мы
 * ушли. Поэтому свой: тридцать строк, зато список в оформлении панели.
 *
 * Свободный ввод остается: список - это подсказка, а не ограничение. Первая
 * группа в проекте иначе не появилась бы никогда.
 */

export function ComboInput({
  value,
  options,
  placeholder,
  onChange,
  autoFocus,
}: {
  value: string
  options: string[]
  placeholder?: string
  onChange: (value: string) => void
  autoFocus?: boolean
}) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  // Подсветка стрелками: без нее подсказку можно было выбрать только мышью.
  const [active, setActive] = useState(-1)
  const box = useRef<HTMLDivElement | null>(null)

  const matches = useMemo(() => {
    const unique = [...new Set(options.filter(Boolean))].sort((a, b) => a.localeCompare(b))
    const needle = value.trim().toLowerCase()
    if (!needle) return unique
    // Значение уже совпадает с одним из вариантов - показываем весь список:
    // человек открыл подсказки, чтобы СМЕНИТЬ группу, а не подтвердить текущую.
    // Прежняя версия в этом случае не показывала ничего, и поле выглядело
    // сломанным ровно у тех проектов, где группа уже была проставлена.
    if (unique.some((o) => o.toLowerCase() === needle)) return unique
    return unique.filter((o) => o.toLowerCase().includes(needle))
  }, [options, value])

  const shown = matches.slice(0, 8)

  // Подсветка сбрасывается при наборе и при закрытии списка. Открытие ее не
  // трогает: стрелка вниз открывает список и сразу подсвечивает первую строку.
  useEffect(() => {
    setActive(-1)
  }, [value])
  useEffect(() => {
    if (!open) setActive(-1)
  }, [open])

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [open])

  return (
    <div className="combo" ref={box}>
      <input
        value={value}
        placeholder={placeholder}
        autoFocus={autoFocus}
        autoComplete="off"
        onChange={(e) => {
          onChange(e.target.value)
          setOpen(true)
        }}
        onFocus={() => setOpen(true)}
        role="combobox"
        aria-expanded={open && shown.length > 0}
        onKeyDown={(e) => {
          // Первым Escape закрывают список, вторым - окно, как в PickInput.
          if (e.key === 'Escape' && open && matches.length > 0) {
            e.stopPropagation()
            setOpen(false)
          }
          if (e.key === 'ArrowDown' && shown.length > 0) {
            e.preventDefault()
            setOpen(true)
            setActive((i) => Math.min(i + 1, shown.length - 1))
          }
          if (e.key === 'ArrowUp' && open) {
            e.preventDefault()
            setActive((i) => Math.max(i - 1, -1))
          }
          // Enter по подсвеченной подсказке выбирает ее, а не отправляет окно.
          if (e.key === 'Enter' && open && active >= 0 && active < shown.length) {
            e.preventDefault()
            e.stopPropagation()
            onChange(shown[active])
            setOpen(false)
          }
        }}
      />
      {open && matches.length > 0 && (
        <div className="combo-list" role="listbox">
          {shown.map((option, index) => (
            <button
              key={option}
              type="button"
              role="option"
              aria-selected={index === active}
              className="menu-item"
              onMouseDown={(e) => {
                // mousedown, а не click: клик приходит после потери фокуса, и
                // список успевает закрыться раньше, чем сработает выбор.
                e.preventDefault()
                onChange(option)
                setOpen(false)
              }}
            >
              {option}
            </button>
          ))}
          {value.trim() && !options.includes(value.trim()) && (
            <div className="combo-hint muted small">{t('или оставьте своё — будет новая группа')}</div>
          )}
        </div>
      )}
    </div>
  )
}
