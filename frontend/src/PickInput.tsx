/* Выбор одного варианта из длинного списка - с поиском.
 *
 * Обычный `select` хорош, пока вариантов десяток. На двух сотнях окружений он
 * превращается в простыню, где нужное ищут глазами и прокруткой: имя проекта
 * известно, а найти его нельзя ничем, кроме первой буквы.
 *
 * Поэтому здесь поле ввода: набирают часть имени, список сужается. Клавиатура
 * работает как везде - стрелки, Enter, Escape. Свободного ввода нет: значение
 * всегда одно из выданных, поле только ищет по ним.
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import { useI18n } from './i18n'

export type PickOption = { value: string; label: string }

// Сколько строк рисуем разом: список на две сотни все равно не читают, а
// прокрутка до конца ничего не находит быстрее, чем еще одна буква в поиске.
const SHOWN = 50

// Со скольких вариантов список превращается в поиск. Десяток еще читается
// целиком, дальше начинается прокрутка вслепую.
export const LONG_LIST = 10

export function PickInput({
  options,
  value,
  onChange,
  autoFocus,
  placeholder,
}: {
  options: PickOption[]
  value: string
  onChange: (value: string) => void
  autoFocus?: boolean
  placeholder?: string
}) {
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const box = useRef<HTMLDivElement | null>(null)
  const list = useRef<HTMLDivElement | null>(null)

  const current = options.find((o) => o.value === value)

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return options
    // По кускам: "glob bot" находит "globex/bot/prod", а порядок слов при
    // этом неважен - в голове держат имя проекта и стенд, а не полный путь.
    const parts = needle.split(/\s+/)
    return options.filter((o) => {
      const label = o.label.toLowerCase()
      return parts.every((part) => label.includes(part))
    })
  }, [options, query])

  // Закрывается щелчком мимо, а не нажатием кнопки мыши. Список стоит в
  // потоке, и окно без него становится ниже и съезжает к центру: закрытый на
  // нажатии, он уводил из-под курсора то, по чему щелкали, - "Дальше" или
  // галочку над полем, и щелчок пропадал.
  useEffect(() => {
    if (!open) return
    // Нажали внутри (на полосу прокрутки списка), отпустили снаружи - это
    // прокрутка, а не щелчок мимо.
    let pressedInside = false
    const onDown = (e: MouseEvent) => {
      pressedInside = Boolean(box.current?.contains(e.target as Node))
    }
    const onClick = (e: MouseEvent) => {
      if (!pressedInside && box.current && !box.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('click', onClick)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('click', onClick)
    }
  }, [open])

  // Активная строка держится в видимой части списка: со стрелками иначе
  // "уезжаешь" за нижний край и не понимаешь, где находишься.
  useEffect(() => {
    if (!open) return
    const node = list.current?.querySelector<HTMLElement>('[data-active="1"]')
    // Необязательный вызов: метод есть не везде (тестовая среда, старые
    // браузеры), и падать из-за прокрутки списку незачем.
    node?.scrollIntoView?.({ block: 'nearest' })
  }, [open, active])

  function show() {
    // Уже открыт - не трогаем набранное: клик по полю посреди ввода не должен
    // стирать то, что человек печатает.
    if (open) return
    setOpen(true)
    setQuery('')
    const at = options.findIndex((o) => o.value === value)
    setActive(at < 0 ? 0 : at)
  }

  // Поле, на котором стоит фокус при открытии окна, сразу показывает варианты:
  // иначе видно только заполненное значение, и что здесь можно искать - не
  // видно вовсе.
  useEffect(() => {
    if (autoFocus) {
      setOpen(true)
      const at = options.findIndex((o) => o.value === value)
      setActive(at < 0 ? 0 : at)
    }
    // Только при появлении поля: дальше список открывают руками.
  }, [])

  function choose(option: PickOption) {
    onChange(option.value)
    setOpen(false)
    setQuery('')
  }

  return (
    <div className="combo pick" ref={box}>
      <input
        role="combobox"
        aria-expanded={open}
        aria-autocomplete="list"
        autoComplete="off"
        autoFocus={autoFocus}
        placeholder={placeholder ?? t('начните вводить имя')}
        value={open ? query : current?.label ?? ''}
        onFocus={show}
        onClick={show}
        onChange={(e) => {
          setQuery(e.target.value)
          setOpen(true)
          setActive(0)
        }}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault()
            if (!open) {
              show()
              return
            }
            const step = e.key === 'ArrowDown' ? 1 : -1
            const last = Math.min(matches.length, SHOWN) - 1
            if (last < 0) return
            setActive((n) => Math.min(Math.max(n + step, 0), last))
            return
          }
          if (e.key === 'Enter' && open) {
            const hit = matches[active]
            if (hit) {
              e.preventDefault()
              // Останавливаем здесь: иначе Enter уйдет дальше и отправит окно
              // тем значением, которое было до выбора.
              e.stopPropagation()
              choose(hit)
            }
            return
          }
          if (e.key === 'Escape' && open) {
            // Первым Escape закрывают список, вторым - окно. Без остановки
            // всплытия окно закрылось бы сразу, вместе со списком.
            e.stopPropagation()
            setOpen(false)
          }
        }}
      />
      {open && (
        <div className="combo-list pick-list" role="listbox" ref={list}>
          {matches.length === 0 && <div className="pick-empty muted small">{t('ничего не нашлось')}</div>}
          {matches.slice(0, SHOWN).map((option, index) => (
            <button
              key={option.value}
              type="button"
              role="option"
              aria-selected={option.value === value}
              data-active={index === active ? '1' : undefined}
              className={`menu-item${index === active ? ' pick-item-on' : ''}`}
              onMouseEnter={() => setActive(index)}
              onMouseDown={(e) => {
                // mousedown, а не click: клик приходит после потери фокуса, и
                // список успевает закрыться раньше, чем сработает выбор.
                e.preventDefault()
                choose(option)
              }}
            >
              {option.label}
            </button>
          ))}
          {matches.length > SHOWN && (
            <div className="pick-empty muted small">
              {t('и ещё')} {matches.length - SHOWN} — {t('уточните поиск')}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/** Выбор из списка: короткий остается обычным списком, длинный ищется.

Решение по длине, а не по месту вызова: список знает про себя больше, чем тот,
кто его показывает, и "здесь бывает много" однажды забудут написать. */
export function Choice({
  options,
  value,
  onChange,
  disabled,
  autoFocus,
}: {
  options: PickOption[]
  value: string
  onChange: (value: string) => void
  disabled?: boolean
  autoFocus?: boolean
}) {
  if (options.length > LONG_LIST && !disabled) {
    return (
      <PickInput options={options} value={value} onChange={onChange} autoFocus={autoFocus} />
    )
  }
  return (
    <select
      value={value}
      disabled={disabled}
      autoFocus={autoFocus}
      onChange={(e) => onChange(e.target.value)}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  )
}
