import { act, fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, describe, expect, it } from 'vitest'
import { ComboInput } from './ComboInput'
import { DialogProvider, useDialogs } from './Dialogs'
import { useEscape } from './useEscape'

let release: () => void = () => {}

// Окно под диалогом, как настройки проекта: свой useEscape.
function Settings({ onClose }: { onClose: () => void }) {
  useEscape(onClose)
  const { ask } = useDialogs()
  const [answer, setAnswer] = useState('')
  return (
    <div>
      <span>настройки открыты</span>
      <button
        onClick={async () => {
          const a = await ask({
            title: 'Включить шифрование',
            fields: [{ name: 'password', label: 'Пароль', type: 'password' }],
            send: () => new Promise<void>((r) => (release = r)),
          })
          setAnswer(JSON.stringify(a))
        }}
      >
        включить
      </button>
      <output data-testid="answer">{answer}</output>
    </div>
  )
}

function Page() {
  const [open, setOpen] = useState(true)
  return open ? <Settings onClose={() => setOpen(false)} /> : <span>настройки закрыты</span>
}

afterEach(() => {
  document.body.innerHTML = ''
})

describe('Dialogs.send', () => {
  it('Escape во время отправки не закрывает окно под диалогом', async () => {
    render(
      <DialogProvider>
        <Page />
      </DialogProvider>,
    )
    fireEvent.click(screen.getByText('включить'))
    fireEvent.change(screen.getByLabelText('Пароль'), { target: { value: 'secret-password' } })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    })
    // идет отправка
    expect((screen.getByRole('button', { name: 'Отмена' }) as HTMLButtonElement).disabled).toBe(true)
    await act(async () => {
      fireEvent.keyDown(window, { key: 'Escape' })
    })
    expect(screen.queryByText('настройки открыты')).toBeTruthy()
    await act(async () => {
      release()
    })
  })
})

describe('ComboInput', () => {
  function Combo() {
    const [v, setV] = useState('')
    return <ComboInput value={v} onChange={setV} options={['alpha', 'beta']} />
  }
  it('первая стрелка вниз после закрытия списка подсвечивает строку', async () => {
    render(<Combo />)
    const input = screen.getByRole('combobox')
    fireEvent.focus(input)
    fireEvent.keyDown(input, { key: 'Escape' })
    expect(screen.queryByRole('listbox')).toBeNull()
    fireEvent.keyDown(input, { key: 'ArrowDown' })
    const selected = screen.queryAllByRole('option').filter((o) => o.getAttribute('aria-selected') === 'true')
    expect(selected.length).toBe(1)
  })
  it('после выбора Enter первая стрелка тоже подсвечивает', async () => {
    render(<Combo />)
    const input = screen.getByRole('combobox')
    fireEvent.focus(input)
    fireEvent.keyDown(input, { key: 'ArrowDown' })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect((input as HTMLInputElement).value).toBe('alpha')
    fireEvent.keyDown(input, { key: 'ArrowDown' })
    const selected = screen.queryAllByRole('option').filter((o) => o.getAttribute('aria-selected') === 'true')
    expect(selected.length).toBe(1)
  })
})

describe('dismiss во время отправки', () => {
  it('поздний ответ закрытого окна не трогает следующее', async () => {
    let finishSend: () => void = () => {}
    let failSend: (e: Error) => void = () => {}
    const results: unknown[] = []
    function Page() {
      const { ask, confirm, dismiss } = useDialogs()
      return (
        <>
          <button
            onClick={async () => {
              results.push(
                await ask({
                  title: 'Первое',
                  fields: [{ name: 'n', label: 'Имя' }],
                  send: () =>
                    new Promise<void>((ok, bad) => {
                      finishSend = ok
                      failSend = bad
                    }),
                }),
              )
            }}
          >
            первое
          </button>
          <button onClick={() => dismiss()}>закрыть</button>
          <button onClick={async () => results.push(await confirm({ title: 'Второе', submit: 'Удалить' }))}>
            второе
          </button>
        </>
      )
    }
    render(
      <DialogProvider>
        <Page />
      </DialogProvider>,
    )
    fireEvent.click(screen.getByText('первое'))
    fireEvent.change(screen.getByLabelText('Имя'), { target: { value: 'x' } })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    })
    await act(async () => {
      fireEvent.click(screen.getByText('закрыть'))
    })
    await act(async () => {
      fireEvent.click(screen.getByText('второе'))
    })
    // Старая отправка падает: ошибка не попадает во второе окно.
    await act(async () => {
      failSend(new Error('Недействительный или отсутствующий токен'))
    })
    expect(screen.getByText('Второе')).toBeTruthy()
    expect(document.querySelector('.form-error')).toBeNull()
    // Кнопки второго окна доступны: "отправка" первого его не держит.
    expect((screen.getByRole('button', { name: 'Отмена' }) as HTMLButtonElement).disabled).toBe(false)
    finishSend()
    expect(results).toEqual([null])
  })
})

describe('окно поверх идущей отправки', () => {
  it('не наследует флаг отправки', async () => {
    let api: ReturnType<typeof useDialogs> | null = null
    function Grab() {
      api = useDialogs()
      return null
    }
    render(
      <DialogProvider>
        <Grab />
      </DialogProvider>,
    )
    let done: () => void = () => {}
    await act(async () => {
      void api!.ask({
        title: 'Первое',
        fields: [{ name: 'n', label: 'Имя' }],
        send: () => new Promise<void>((ok) => (done = ok)),
      })
    })
    fireEvent.change(screen.getByLabelText('Имя'), { target: { value: 'x' } })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    })
    await act(async () => {
      void api!.confirm({ title: 'Второе', submit: 'Удалить', danger: true })
    })
    expect((screen.getByRole('button', { name: 'Отмена' }) as HTMLButtonElement).disabled).toBe(false)
    await act(async () => done())
    expect(screen.getByText('Второе')).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Отмена' }) as HTMLButtonElement).disabled).toBe(false)
  })
})
