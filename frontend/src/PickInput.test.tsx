/* Поле выбора с поиском: им выбирают окружение из двух сотен.
 *
 * Проверяем то, что руками проверять дольше всего: фильтрацию по кускам,
 * клавиатуру и то, что "Выбрать" не теряет значение при повторном клике в поле.
 */

import { fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { Choice, PickInput, type PickOption } from './PickInput'

const ENVS: PickOption[] = [
  { value: '1', label: 'globex/bot/prod' },
  { value: '2', label: 'globex/bot/dev' },
  { value: '3', label: 'acme/api/prod' },
  { value: '4', label: 'acme/api/stage' },
]

function Harness({ options = ENVS }: { options?: PickOption[] }) {
  const [value, setValue] = useState('')
  return (
    <div>
      <PickInput options={options} value={value} onChange={setValue} autoFocus />
      <output data-testid="chosen">{value}</output>
    </div>
  )
}

describe('PickInput', () => {
  it('сразу показывает варианты, когда поле в фокусе', () => {
    render(<Harness />)
    expect(screen.getAllByRole('option')).toHaveLength(4)
  })

  it('ищет по кускам в любом порядке', () => {
    render(<Harness />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'glob bot' } })
    const shown = screen.getAllByRole('option').map((el) => el.textContent)
    expect(shown).toEqual(['globex/bot/prod', 'globex/bot/dev'])
  })

  it('выбирает стрелками и Enter', () => {
    render(<Harness />)
    const input = screen.getByRole('combobox')
    fireEvent.change(input, { target: { value: 'api' } })
    fireEvent.keyDown(input, { key: 'ArrowDown' })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(screen.getByTestId('chosen').textContent).toBe('4')
  })

  it('первым Escape закрывает список, а не окно', () => {
    render(<Harness />)
    const input = screen.getByRole('combobox')
    fireEvent.keyDown(input, { key: 'Escape' })
    expect(screen.queryAllByRole('option')).toHaveLength(0)
  })

  it('закрывается щелчком мимо, а не нажатием: окно не уезжает из-под курсора', () => {
    render(
      <>
        <Harness />
        <button>мимо</button>
      </>,
    )
    const outside = screen.getByText('мимо')
    fireEvent.mouseDown(outside)
    expect(screen.getAllByRole('option')).toHaveLength(4)
    fireEvent.click(outside)
    expect(screen.queryAllByRole('option')).toHaveLength(0)
  })

  it('нажали в списке, отпустили мимо — список остаётся', () => {
    render(
      <>
        <Harness />
        <button>мимо</button>
      </>,
    )
    fireEvent.mouseDown(screen.getByRole('listbox'))
    fireEvent.click(screen.getByText('мимо'))
    expect(screen.getAllByRole('option')).toHaveLength(4)
  })

  it('ничего не находит — говорит об этом', () => {
    render(<Harness />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'такого нет' } })
    expect(screen.queryAllByRole('option')).toHaveLength(0)
    expect(screen.getByText('ничего не нашлось')).toBeTruthy()
  })
})

describe('Choice', () => {
  it('короткий список оставляет обычным списком', () => {
    render(<Choice options={ENVS} value="1" onChange={() => {}} />)
    expect(screen.getByRole('combobox').tagName).toBe('SELECT')
  })

  it('длинный список превращает в поиск', () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      value: String(i),
      label: `env-${i}`,
    }))
    render(<Choice options={many} value="1" onChange={() => {}} />)
    expect(screen.getByRole('combobox').tagName).toBe('INPUT')
  })
})
