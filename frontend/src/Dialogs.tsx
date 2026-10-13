import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { ComboInput } from './ComboInput'
import { LONG_LIST, PickInput } from './PickInput'
import { copyToClipboard } from './clipboard'
import { EyeIcon, EyeOffIcon } from './icons'
import { useI18n } from './i18n'
import { useEscape } from './useEscape'

/* Свои окна вместо браузерных prompt/confirm/alert.
 *
 * Дело не только во внешнем виде. Браузерное окно не умеет ничего, что здесь
 * нужно каждый день: несколько полей сразу, подсказку под полем, выбор из
 * списка, тип "пароль", понятную кнопку вместо безымянного "OK". Плюс оно
 * блокирует вкладку и в разных браузерах выглядит по-разному.
 *
 * Пользоваться так же просто, как раньше:
 *
 *     const answer = await ask({ title: 'Новый ключ', fields: [...] })
 *     if (!answer) return            // человек отказался
 *     answer.name                    // введенные значения
 */

export type DialogField = {
  name: string
  label: string
  value?: string
  placeholder?: string
  hint?: string
  type?: 'text' | 'password' | 'textarea' | 'select' | 'combo' | 'check' | 'cards'
  /** hint у варианта показывается только в карточках: там у каждого варианта
   *  есть строка о том, что он значит. */
  options?: { value: string; label: string; hint?: string }[]
  /** Подсказки для типа combo: выбрать существующее или ввести свое. */
  suggestions?: string[]
  /** Слова, которые дописываются в поле кнопкой: "+ dev", "+ stage". Уже
   *  набранное слово кнопку прячет. */
  quick?: string[]
  required?: boolean
  optional?: boolean
  /** Поле, ненужное при других ответах: "Без проекта" прячет выбор проекта.
   *  Спрятанное поле не обязательно к заполнению. */
  hide?: (values: Record<string, string>) => boolean
  /** Что не так с введенным: пустая строка - все в порядке. Сервер проверит
   *  то же самое, но его отказ приходит, когда окно уже закрыто и набранное
   *  потеряно; здесь кнопка просто не нажимается, а причина видна под полем. */
  check?: (value: string, values: Record<string, string>) => string
}

type AskOptions = {
  title: string
  text?: string
  /** Надпись может зависеть от ответов: без проекта "Дальше" становится
   *  "Создать токен" - следующего шага нет. */
  submit?: string | ((values: Record<string, string>) => string)
  danger?: boolean
  fields: DialogField[]
  /** Отправка прямо из окна. Отказ сервера (неверный пароль, занятое имя,
   *  битый JWKS) показывается здесь же, и набранное не теряется: раньше окно
   *  закрывалось до ответа, и пароль архива или JWKS приходилось вводить
   *  заново. Окно закрывается, только когда отправка прошла. */
  send?: (values: Record<string, string>) => Promise<void>
}

type ConfirmOptions = {
  title: string
  text?: string
  submit?: string
  danger?: boolean
}

type Dialogs = {
  ask: (options: AskOptions) => Promise<Record<string, string> | null>
  confirm: (options: ConfirmOptions) => Promise<boolean>
  notify: (title: string, text?: string) => Promise<boolean>
  /** Сообщение "готово", которое не требует ответа: всплывает и уходит само.
   *  Модальное окно ради "скопировано" отнимает у человека лишний клик. */
  toast: (text: string) => void
  /** Закрыть открытое окно как отмену: выход по бездействию и конец сессии
   *  не оставляют вопрос висеть над экраном входа. */
  dismiss: () => void
}

const DialogContext = createContext<Dialogs>({
  ask: async () => null,
  confirm: async () => false,
  notify: async () => true,
  toast: () => {},
  dismiss: () => {},
})

type Toast = { id: number; text: string }

type State =
  | { kind: 'ask'; options: AskOptions }
  | { kind: 'confirm'; options: ConfirmOptions }
  | { kind: 'notify'; options: ConfirmOptions }
  | null

// Строки, которые набирают в терминале. Их отличают не "по смыслу", а по
// первому слову: этого хватает и не требует от вызывающего кода разметки.
const COMMAND = /^(curl|wget|sudo|ssh|bash|sh|docker|kubectl|systemctl|apt|python|sekvyr)\b/

// "Что: значение", где значение - одно слово: идентификатор, секрет, имя
// окружения. Такое копируют целиком, и ради этого его стоит отделить.
const FACT = /^([^:]{2,40}):\s*(\S{10,})$/

type Block = { kind: 'text' | 'code' | 'fact'; text: string; label?: string }

function split(text: string): Block[] {
  const blocks: Block[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line) continue
    if (COMMAND.test(line) || line.includes('| sh')) {
      blocks.push({ kind: 'code', text: line })
      continue
    }
    const fact = FACT.exec(line)
    if (fact) {
      blocks.push({ kind: 'fact', label: fact[1], text: fact[2] })
      continue
    }
    blocks.push({ kind: 'text', text: line })
  }
  return blocks
}

/** Текст окна: объяснения абзацами, команды и значения - блоками с копированием. */
function DialogText({ text, onCopied }: { text: string; onCopied: (ok: boolean) => void }) {
  const { t } = useI18n()
  const blocks = split(text)

  const copy = async (value: string) => onCopied(await copyToClipboard(value))

  return (
    <div className="dialog-text">
      {blocks.map((block, index) =>
        block.kind === 'code' ? (
          <div key={index} className="dialog-code">
            <code className="mono">{block.text}</code>
            <button className="ghost small-btn" onClick={() => void copy(block.text)}>
              {t('Скопировать')}
            </button>
          </div>
        ) : block.kind === 'fact' ? (
          <div key={index} className="dialog-fact">
            <span className="muted small">{block.label}</span>
            <code className="mono small">{block.text}</code>
            <button className="ghost small-btn" onClick={() => void copy(block.text)}>
              {t('Скопировать')}
            </button>
          </div>
        ) : (
          <p key={index} className="muted small">
            {block.text}
          </p>
        ),
      )}
    </div>
  )
}

export function DialogProvider({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const [state, setState] = useState<State>(null)
  const [values, setValues] = useState<Record<string, string>>({})
  const [toasts, setToasts] = useState<Toast[]>([])
  const [shown, setShown] = useState<Record<string, boolean>>({})
  const [sending, setSending] = useState(false)
  const [failure, setFailure] = useState('')
  const nextToast = useRef(1)
  // Обещание держим в ref, а не в состоянии: перерисовка не должна его терять,
  // иначе вызвавший код повиснет навсегда.
  const resolve = useRef<((value: unknown) => void) | null>(null)
  // Номер открытого окна: отправка, начатая в одном окне, не закрывает и не
  // помечает ошибкой другое, открытое после (dismiss при конце сессии).
  const serial = useRef(0)

  const finish = useCallback((value: unknown) => {
    resolve.current?.(value)
    resolve.current = null
    serial.current += 1
    setState(null)
    setValues({})
    setFailure('')
    setSending(false)
  }, [])

  const ask = useCallback<Dialogs['ask']>(
    (options) =>
      new Promise((done) => {
        resolve.current = done as (value: unknown) => void
        serial.current += 1
        setSending(false)
        setValues(
          Object.fromEntries(options.fields.map((f) => [f.name, f.value ?? ''])),
        )
        setShown({})
        setFailure('')
        setState({ kind: 'ask', options })
      }),
    [],
  )

  const confirm = useCallback<Dialogs['confirm']>(
    (options) =>
      new Promise((done) => {
        resolve.current = done as (value: unknown) => void
        serial.current += 1
        setSending(false)
        setFailure('')
        setState({ kind: 'confirm', options })
      }),
    [],
  )

  const notify = useCallback<Dialogs['notify']>(
    (title, text) =>
      new Promise((done) => {
        resolve.current = done as (value: unknown) => void
        serial.current += 1
        setSending(false)
        setFailure('')
        setState({ kind: 'notify', options: { title, text } })
      }),
    [],
  )

  const dismiss = useCallback(() => {
    if (resolve.current) finish(null)
  }, [finish])

  const toast = useCallback<Dialogs['toast']>((text) => {
    const id = nextToast.current++
    setToasts((list) => [...list, { id, text }])
    // Три секунды: успеть прочитать короткую фразу и не мешать дальше.
    window.setTimeout(() => setToasts((list) => list.filter((item) => item.id !== id)), 3000)
  }, [])

  // Пока идет отправка, Escape остается у окна и ничего не делает: снять окно
  // со стопки значило отдать Escape окну под ним, и закрывалось оно, а
  // отправка шла дальше.
  useEscape(() => {
    if (!sending) finish(state?.kind === 'ask' ? null : false)
  }, Boolean(state))

  // Замечание к полю показываем, когда в нем уже что-то есть: пустое поле с
  // красной надписью до первой буквы выглядит как ошибка, которой не было.
  const problem = (f: DialogField): string => {
    const value = values[f.name] ?? ''
    if (!f.check || f.hide?.(values) || (f.optional && !value.trim())) return ''
    return f.check(value, values)
  }

  const canSubmit =
    state?.kind !== 'ask' ||
    state.options.fields.every(
      (f) =>
        (f.optional || f.hide?.(values) || (values[f.name] ?? '').trim().length > 0) &&
        !problem(f),
    ) &&
    !sending

  const submit = async () => {
    if (!state || !canSubmit) return
    if (state.kind !== 'ask') {
      finish(true)
      return
    }
    const answer = { ...values }
    const send = state.options.send
    if (!send) {
      finish(answer)
      return
    }
    setSending(true)
    setFailure('')
    const mine = serial.current
    try {
      await send(answer)
      if (serial.current === mine) finish(answer)
    } catch (e) {
      if (serial.current === mine) setFailure(e instanceof Error ? e.message : String(e))
    } finally {
      if (serial.current === mine) setSending(false)
    }
  }

  // Фокус - в первое видимое поле ввода. Галочку пропускаем: "Без проекта" над
  // выбором проекта не должна отнимать фокус у самого выбора.
  const focusFirst =
    state?.kind === 'ask'
      ? state.options.fields.find((f) => f.type !== 'check' && !f.hide?.(values))?.name
      : undefined

  // Окно с командой шире обычного: в 380 пикселей строка установки агента
  // разрывается на семь кусков и перестает читаться как одна команда.
  const roomy = Boolean(
    state?.options.text && split(state.options.text).some((b) => b.kind === 'code'),
  )

  return (
    <DialogContext.Provider value={{ ask, confirm, notify, toast, dismiss }}>
      {children}
      {toasts.length > 0 && (
        <div className="toasts" role="status" aria-live="polite">
          {toasts.map((item) => (
            <div key={item.id} className="toast">
              {item.text}
            </div>
          ))}
        </div>
      )}
      {state && (
        <div className="modal-backdrop">
          <div
            className={`card modal stack${roomy ? ' modal-roomy' : ''}`}
            role={state.kind === 'ask' ? 'dialog' : 'alertdialog'}
            aria-modal="true"
            aria-labelledby="dialog-title"
          >
            <h3 id="dialog-title">{state.options.title}</h3>
            {state.options.text && (
              <DialogText
                text={state.options.text}
                onCopied={(ok) => toast(ok ? t('Скопировано') : t('Скопировать не вышло'))}
              />
            )}

            {state.kind === 'ask' &&
              state.options.fields.map((field) => (
                // Спрятанное поле остается в окне, а не выпадает из него:
                // возвращаясь, оно не выхватывает фокус у галочки, которой его
                // вернули.
                <label
                  key={field.name}
                  className={field.type === 'check' ? 'checkline' : undefined}
                  hidden={field.hide?.(values)}
                >
                  {field.type !== 'check' && field.label}
                  {field.type === 'check' ? (
                    // Значение хранится строкой, как у остальных полей: "1" или
                    // пусто. Так вызывающему не нужно знать про типы вовсе.
                    // Галочка перед подписью - как во всех формах панели.
                    <>
                      <input
                        type="checkbox"
                        className="dialog-check"
                        checked={Boolean(values[field.name])}
                        onChange={(e) =>
                          setValues((v) => ({ ...v, [field.name]: e.target.checked ? '1' : '' }))
                        }
                      />
                      {field.label}
                    </>
                  ) : field.type === 'cards' ? (
                    // Выбор, где варианты надо понимать, а не узнавать по
                    // названию: роль, режим. Кнопками карточки быть не могут -
                    // подпись поля переадресовала бы щелчок на первую из них.
                    <span className="choice-cards" role="radiogroup" aria-label={field.label}>
                      {field.options?.map((option) => {
                        const on = values[field.name] === option.value
                        const pick = () =>
                          setValues((v) => ({ ...v, [field.name]: option.value }))
                        return (
                          <span
                            key={option.value}
                            role="radio"
                            aria-checked={on}
                            tabIndex={0}
                            className={`choice-card${on ? ' choice-card-on' : ''}`}
                            onClick={(e) => {
                              e.preventDefault()
                              pick()
                            }}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault()
                                pick()
                              }
                            }}
                          >
                            <span className="choice-card-title">{option.label}</span>
                            {option.hint && (
                              <span className="choice-card-hint">{option.hint}</span>
                            )}
                          </span>
                        )
                      })}
                    </span>
                  ) : field.type === 'select' && (field.options?.length ?? 0) > LONG_LIST ? (
                    // Длинный список глазами не читают: в нем ищут. Порог
                    // выбран так, чтобы обычные "роль" и "кластер" остались
                    // привычным списком, а две сотни окружений - полем поиска.
                    <PickInput
                      options={field.options ?? []}
                      value={values[field.name] ?? ''}
                      autoFocus={field.name === focusFirst}
                      onChange={(next) => setValues((v) => ({ ...v, [field.name]: next }))}
                    />
                  ) : field.type === 'select' ? (
                    <select
                      value={values[field.name] ?? ''}
                      autoFocus={field.name === focusFirst}
                      onChange={(e) =>
                        setValues((v) => ({ ...v, [field.name]: e.target.value }))
                      }
                    >
                      {field.options?.map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
                        </option>
                      ))}
                    </select>
                  ) : field.type === 'combo' ? (
                    <ComboInput
                      value={values[field.name] ?? ''}
                      options={field.suggestions ?? []}
                      placeholder={field.placeholder}
                      autoFocus={field.name === focusFirst}
                      onChange={(next) => setValues((v) => ({ ...v, [field.name]: next }))}
                    />
                  ) : field.type === 'textarea' ? (
                    <textarea
                      className="value-input"
                      rows={4}
                      value={values[field.name] ?? ''}
                      autoFocus={field.name === focusFirst}
                      onChange={(e) =>
                        setValues((v) => ({ ...v, [field.name]: e.target.value }))
                      }
                      placeholder={field.placeholder}
                    />
                  ) : (
                    <span className="field-with-eye">
                      <input
                        type={field.type === 'password' && !shown[field.name] ? 'password' : 'text'}
                        value={values[field.name] ?? ''}
                        autoFocus={field.name === focusFirst}
                        autoComplete={field.type === 'password' ? 'new-password' : 'off'}
                        placeholder={field.placeholder}
                        onChange={(e) =>
                          setValues((v) => ({ ...v, [field.name]: e.target.value }))
                        }
                        onKeyDown={(e) => {
                          // Enter отправляет - так же, как в браузерном окне,
                          // к которому все привыкли.
                          if (e.key === 'Enter') void submit()
                        }}
                      />
                      {/* Пароль вслепую набирают с опечаткой чаще, чем угадывают:
                          строку подключения к базе - тем более. */}
                      {field.type === 'password' && (
                        <button
                          type="button"
                          className="ghost icon-btn field-eye"
                          aria-label={shown[field.name] ? t('Скрыть') : t('Показать')}
                          onClick={() =>
                            setShown((v) => ({ ...v, [field.name]: !v[field.name] }))
                          }
                        >
                          {shown[field.name] ? <EyeOffIcon /> : <EyeIcon />}
                        </button>
                      )}
                    </span>
                  )}
                  {field.quick && (
                    <span className="quick-row">
                      {field.quick
                        .filter(
                          (word) => !(values[field.name] ?? '').split(/[\s,]+/).includes(word),
                        )
                        .map((word) => (
                          <button
                            key={word}
                            type="button"
                            className="ghost small-btn"
                            onClick={() =>
                              setValues((v) => {
                                const current = (v[field.name] ?? '').trim()
                                return { ...v, [field.name]: current ? `${current} ${word}` : word }
                              })
                            }
                          >
                            + {word}
                          </button>
                        ))}
                    </span>
                  )}
                  {problem(field) && (values[field.name] ?? '') !== '' ? (
                    <span className="small form-error field-hint">{problem(field)}</span>
                  ) : (
                    field.hint && <span className="muted small field-hint">{field.hint}</span>
                  )}
                </label>
              ))}

            {failure && <p className="form-error">{failure}</p>}

            <div className="row-actions dialog-actions">
              {state.kind !== 'notify' && (
                <button
                  className="ghost"
                  disabled={sending}
                  // Опасное подтверждение без полей: фокус на отмене, чтобы
                  // Enter по привычке не удалил и не запер.
                  autoFocus={state.kind === 'confirm' && Boolean(state.options.danger)}
                  onClick={() => finish(state.kind === 'ask' ? null : false)}
                >
                  {t('Отмена')}
                </button>
              )}
              <button
                className={state.options.danger ? 'danger-btn' : undefined}
                disabled={!canSubmit}
                autoFocus={state.kind === 'notify' || (state.kind === 'confirm' && !state.options.danger)}
                onClick={() => void submit()}
              >
                {(typeof state.options.submit === 'function'
                  ? state.options.submit(values)
                  : state.options.submit) ??
                  (state.kind === 'notify' ? t('Понятно') : t('Сохранить'))}
              </button>
            </div>
          </div>
        </div>
      )}
    </DialogContext.Provider>
  )
}

export function useDialogs(): Dialogs {
  return useContext(DialogContext)
}
