/* Общее окно ask(): поле, которое прячется по ответу в другом поле.
 *
 * Так устроено подключение сервера: галочка "Без проекта" прячет выбор проекта,
 * показывает срок действия токена и меняет кнопку. Проверяем, что спрятанное поле не
 * мешает отправить окно и не получает фокус.
 */

import { act, fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { DialogProvider, useDialogs } from './Dialogs'
import { useEscape } from './useEscape'

function Harness({ projects = ['billing'] }: { projects?: string[] }) {
  const { ask } = useDialogs()
  const [answer, setAnswer] = useState('')
  const open = async () => {
    const result = await ask({
      title: 'Подключить сервер',
      submit: (v) => (v.bare ? 'Создать токен' : 'Дальше'),
      fields: [
        {
          name: 'bare',
          label: 'Без проекта',
          type: 'check',
          optional: true,
          value: projects.length > 0 ? '' : '1',
        },
        {
          name: 'project',
          label: 'Проект',
          type: 'select',
          options: projects.map((p) => ({ value: p, label: p })),
          value: projects[0] ?? '',
          hide: (v) => Boolean(v.bare),
        },
        { name: 'minutes', label: 'Минут', value: '15', hide: (v) => !v.bare },
      ],
    })
    setAnswer(JSON.stringify(result))
  }
  return (
    <>
      <button onClick={() => void open()}>открыть</button>
      <output data-testid="answer">{answer}</output>
    </>
  )
}

function start(projects?: string[]) {
  render(
    <DialogProvider>
      <Harness projects={projects} />
    </DialogProvider>,
  )
  fireEvent.click(screen.getByText('открыть'))
}

describe('ask: спрятанные поля', () => {
  it('галочка прячет выбор, показывает срок и меняет кнопку', () => {
    start()
    expect(screen.getByRole('combobox')).toBeTruthy()
    expect(screen.queryByRole('textbox')).toBeNull()
    expect(screen.getByRole('button', { name: 'Дальше' })).toBeTruthy()

    fireEvent.click(screen.getByRole('checkbox', { name: 'Без проекта' }))

    expect(screen.queryByRole('combobox')).toBeNull()
    expect(screen.getByRole('textbox')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Создать токен' })).toBeTruthy()
  })

  it('спрятанное пустое поле не мешает отправить окно', async () => {
    start([])
    const submit = screen.getByRole('button', { name: 'Создать токен' })
    expect((submit as HTMLButtonElement).disabled).toBe(false)
    await act(async () => {
      fireEvent.click(submit)
    })
    expect(JSON.parse(screen.getByTestId('answer').textContent ?? '')).toMatchObject({
      bare: '1',
      minutes: '15',
    })
  })

  it('фокус получает первое видимое поле, а не галочка', () => {
    start()
    expect(document.activeElement?.tagName).toBe('SELECT')
  })
})

/* Окно настроек с вопросом поверх: Escape закрывает только вопрос. Раньше у
 * каждого окна был свой слушатель, и закрывались оба вместе с набранным. */
function Stacked() {
  const { ask } = useDialogs()
  const [settings, setSettings] = useState(true)
  useEscape(() => setSettings(false), settings)
  return (
    <>
      {settings && <p>настройки</p>}
      <button onClick={() => void ask({ title: 'Вопрос', fields: [{ name: 'x', label: 'Икс' }] })}>
        спросить
      </button>
    </>
  )
}

describe('Escape', () => {
  it('закрывает только верхнее окно', () => {
    render(
      <DialogProvider>
        <Stacked />
      </DialogProvider>,
    )
    fireEvent.click(screen.getByText('спросить'))
    expect(screen.getByText('Вопрос')).toBeTruthy()

    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByText('Вопрос')).toBeNull()
    expect(screen.getByText('настройки')).toBeTruthy()

    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByText('настройки')).toBeNull()
  })
})

function Checked() {
  const { ask } = useDialogs()
  return (
    <button
      onClick={() =>
        void ask({
          title: 'Новая учетка',
          submit: 'Завести',
          fields: [
            {
              name: 'login',
              label: 'Логин',
              check: (v) => (/^[a-z]+$/.test(v) ? '' : 'только латиница'),
            },
          ],
        })
      }
    >
      открыть
    </button>
  )
}

describe('ask: проверка поля', () => {
  it('причина видна под полем, а кнопка не нажимается', () => {
    render(
      <DialogProvider>
        <Checked />
      </DialogProvider>,
    )
    fireEvent.click(screen.getByText('открыть'))
    const submit = screen.getByRole('button', { name: 'Завести' }) as HTMLButtonElement
    // Пустое поле - без красной надписи, просто не заполнено.
    expect(screen.queryByText('только латиница')).toBeNull()
    expect(submit.disabled).toBe(true)

    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'иван' } })
    expect(screen.getByText('только латиница')).toBeTruthy()
    expect(submit.disabled).toBe(true)

    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'ivan' } })
    expect(screen.queryByText('только латиница')).toBeNull()
    expect(submit.disabled).toBe(false)
  })
})

function Sender({ fail }: { fail: () => boolean }) {
  const { ask } = useDialogs()
  const [answer, setAnswer] = useState('')
  const open = async () => {
    const result = await ask({
      title: 'Архив',
      submit: 'Собрать',
      fields: [
        { name: 'password', label: 'Пароль', type: 'password' },
        {
          name: 'repeat',
          label: 'Ещё раз',
          type: 'password',
          check: (v, all) => (v !== all.password ? 'не совпали' : ''),
        },
      ],
      send: async () => {
        if (fail()) throw new Error('неверный пароль от панели')
      },
    })
    setAnswer(JSON.stringify(result))
  }
  return (
    <>
      <button onClick={() => void open()}>открыть</button>
      <output data-testid="answer">{answer}</output>
    </>
  )
}

describe('ask: отправка из окна', () => {
  it('повтор сверяется с первым полем, отказ сервера не закрывает окно', async () => {
    let refuse = true
    render(
      <DialogProvider>
        <Sender fail={() => refuse} />
      </DialogProvider>,
    )
    fireEvent.click(screen.getByText('открыть'))
    const [first, second] = screen.getAllByLabelText(/Пароль|Ещё раз/) as HTMLInputElement[]
    fireEvent.change(first, { target: { value: 'archive-pass-1' } })
    fireEvent.change(second, { target: { value: 'archive-pass-2' } })
    const submit = screen.getByRole('button', { name: 'Собрать' }) as HTMLButtonElement
    expect(submit.disabled).toBe(true)
    expect(screen.getByText('не совпали')).toBeTruthy()

    fireEvent.change(second, { target: { value: 'archive-pass-1' } })
    expect(submit.disabled).toBe(false)
    await act(async () => {
      fireEvent.click(submit)
    })
    // Окно на месте, ошибка видна, набранное не пропало.
    expect(screen.getByText('неверный пароль от панели')).toBeTruthy()
    expect(first.value).toBe('archive-pass-1')
    expect(screen.getByTestId('answer').textContent).toBe('')

    refuse = false
    await act(async () => {
      fireEvent.click(submit)
    })
    expect(screen.queryByText('Архив')).toBeNull()
    expect(JSON.parse(screen.getByTestId('answer').textContent ?? '')).toMatchObject({
      password: 'archive-pass-1',
    })
  })
})
