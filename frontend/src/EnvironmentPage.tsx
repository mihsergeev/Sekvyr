import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  // Под своим именем: иначе он перекрывает браузерный KeyboardEvent, который
  // нужен обработчику на window.
  type KeyboardEvent as ReactKeyboardEvent,
} from 'react'
import {
  approveSecret,
  deleteSecret,
  getE2eWrap,
  inheritSecret,
  listPending,
  listMachines,
  compareEnvs,
  copyFrom,
  envEvents,
  idleSecrets,
  lintEnv,
  listMutes,
  listSecrets,
  missingKeys,
  unmuteNote,
  muteNote,
  myPermissions,
  putSecret,
  readSecret,
  sameValue,
  setSecretMeta,
  whoSees,
  rejectSecret,
  renameSecret,
  type Machine,
  type PendingRow,
  type Permissions,
  type EnvDiff,
  type EnvEvent,
  type SameRow,
  type WhoRow,
  type IdleKeys,
  type MissingKey,
  type MutedNote,
  type SecretNote,
  type SecretRow,
} from './api'
import { useAuth } from './auth'
import {
  forgetKey,
  keyFor,
  openValue,
  rememberKey,
  sealValue,
  unlockProjectKey,
  type Bytes,
} from './e2e'
import { useDialogs } from './Dialogs'
import { ErrorNote } from './Notes'
import { plural, useI18n } from './i18n'
import { serverText, versionComment } from './serverText'
import { formatAgo, formatDate, formatDateTime, formatDay, staleClass } from './time'
import { usePoll } from './usePoll'
import { absoluteUrl, type View } from './router'
import {
  BulkEditModal,
  HistoryModal,
  ImportModal,
  SecretEditor,
  SpreadModal,
} from './SecretModals'
import { ACTIONS } from './auditActions'

/* Экран окружения: его ключи.
 *
 * Здесь их бывает сотня, поэтому таблица плотная, строка занимает одну строку, а
 * действия спрятаны в меню: шесть кнопок в каждой строке - это шестьсот кнопок
 * на экране, среди которых не найти нужную.
 *
 * Значения скрыты и запрашиваются по одному: каждое обращение попадает в
 * журнал, и "кто видел прод-пароль" остается отвечаемым вопросом.
 */

const HIDE_AFTER_MS = 45_000

// i18n
// Подписи событий: в ленте окружения нужны только те, что здесь и случаются.
// Свои подписи для частых событий окружения, остальное - подписями журнала.
const EVENTS: Record<string, string> = {
  secret_written: 'значение изменено',
  secret_pending: 'правка ждёт подтверждения',
  secret_read: 'значение прочитано',
  secret_deleted: 'ключ удалён',
  secret_renamed: 'ключ переименован',
  secret_rolled_back: 'значение возвращено',
  secret_approved: 'правка подтверждена',
  secret_rejected: 'правка отклонена',
  secret_meta: 'подпись и срок',
  env_imported: 'импорт файла',
  env_compared: 'сравнение окружений',
  env_copied: 'копия окружения',
  env_key_rotated: 'смена ключа шифрования',
  lint_muted: 'замечание принято',
  lint_unmuted: 'замечание возвращено',
}

// С какого возраста значение считается давним. Год - не срок годности, а повод
// спросить: пароль, которого не касались год, обычно знает больше людей, чем
// думает тот, кто его завел.
// Запасной порог: столько же, сколько у нового проекта. Настройка живет в
// проекте, но страница должна работать и без нее.
const OLD_AFTER_DAYS = 365

/** Насколько горит срок: прошел, близко (месяц) или еще далеко. */
function dueClass(iso: string): 'over' | 'soon' | 'far' {
  const at = Date.parse(iso)
  if (Number.isNaN(at)) return 'far'
  const left = at - Date.now()
  if (left < 0) return 'over'
  return left < 30 * 24 * 60 * 60 * 1000 ? 'soon' : 'far'
}

function oldValue(iso: string, days: number): boolean {
  if (!iso) return false
  const at = Date.parse(iso)
  if (Number.isNaN(at)) return false
  return Date.now() - at > days * 24 * 60 * 60 * 1000
}

/* Открытое значение: то, что вернул сервер, и то, что человек успел набрать.
 * Разница между ними - единственный признак несохраненной правки, и по нему же
 * решается, можно ли закрывать значение по таймеру. */
// wide - значение не поместилось в строку и открыто под именем во всю ширину.
type Opened = { value: string; draft: string; busy: boolean; note: string; wide?: boolean }

const NOTHING: Permissions = {
  list: false,
  read: false,
  write: false,
  delete: false,
  rotate: false,
  approve: false,
}

type Modal =
  | { kind: 'new' }
  | { kind: 'edit'; secret: SecretRow }
  | { kind: 'history'; secret: SecretRow }
  | { kind: 'import' }
  | { kind: 'bulk' }
  | { kind: 'spread'; secret: SecretRow }
  | null

// Отказ буфера обмена отличаем по этой строке: она не показывается человеку,
// а нужна, чтобы поймать именно этот случай и открыть значение вместо ошибки.
const CLIPBOARD_CLOSED = 'clipboard-closed'

export function EnvironmentPage({
  envId,
  parentName = '',
  initialQuery = '',
  shareView,
  projectId = 0,
  e2e = false,
  onOpenServer,
  siblings = [],
  required = [],
  staleAfterDays = OLD_AFTER_DAYS,
  onFilter,
}: {
  envId: number
  /** Имя родительского окружения; пусто - наследовать не от кого. */
  parentName?: string
  /** Поиск из адреса: ссылка вида ?q=DB_PASSWORD открывает окружение сразу на нужном ключе. */
  initialQuery?: string
  shareView?: View
  projectId?: number
  /** Провалиться в сервер, который забирает это окружение. */
  onOpenServer?: (machine: { id: number; name: string }) => void
  /** Соседние окружения проекта: с ними это можно сравнить. */
  siblings?: { id: number; name: string }[]
  /** Ключи, без которых приложение проекта не поднимется. */
  required?: string[]
  /** С какого возраста значение считается давним: задается в проекте. */
  staleAfterDays?: number
  /** Набранный поиск - наверх: соседнее окружение откроется с ним же. */
  onFilter?: (text: string) => void
  /** Проект с шифрованием в браузере: значения здесь запечатаны, и ключ от них
   * есть только у того, кто ввел пароль проекта в этой вкладке. */
  e2e?: boolean
}) {
  const { t, lang } = useI18n()
  const auth = useAuth()
  const { ask, confirm, notify, toast } = useDialogs()
  const [can, setCan] = useState<Permissions>(NOTHING)
  const [rows, setRows] = useState<SecretRow[]>([])
  // Пришел ли список хоть раз: до этого пустой список - не "ключей нет", и
  // предложение добавить первый ключ в prod было бы неправдой.
  const [loaded, setLoaded] = useState(false)
  const [pending, setPending] = useState<PendingRow[]>([])
  // Кто забирает это окружение: сервер с агентом или сборка.
  const [servers, setServers] = useState<Machine[]>([])
  const [opened, setOpened] = useState<Record<string, Opened>>({})
  const [openMenu, setOpenMenu] = useState<string | null>(null)
  const [bulkMenu, setBulkMenu] = useState(false)
  // Режим выбора: чекбоксы в строках появляются по требованию, а не висят
  // всегда - в обычном чтении списка они только шум.
  const [picking, setPicking] = useState(false)
  const [picked, setPicked] = useState<Record<string, boolean>>({})
  // Сколько строк рисуем: тысяча строк с меню и полем в каждой заметно
  // тормозит браузер, а читают все равно первые несколько десятков.
  const [limit, setLimit] = useState(300)
  // Результат сравнения с соседним окружением: показывается секцией, пока его
  // не закроют. Пусто - не сравнивали.
  const [diff, setDiff] = useState<EnvDiff | null>(null)
  // Ключи, которых давно никто не открывал: тоже секция и тоже по запросу -
  // считать их на каждый заход незачем.
  const [idle, setIdle] = useState<IdleKeys | null>(null)
  // Лента событий этого окружения: "кто это менял" спрашивают, глядя на ключи,
  // а не уходя в журнал.
  const [events, setEvents] = useState<EnvEvent[] | null>(null)
  // Где еще лежит такое же значение: вопрос компрометации, ответ - список мест.
  const [same, setSame] = useState<{ name: string; rows: SameRow[] } | null>(null)
  // Кому видно это окружение: та же выдержка из прав, но про одно место.
  const [who, setWho] = useState<WhoRow[] | null>(null)
  // Подсветка списка серверов после клика по клетке сводки. Счетчик, а не
  // флаг: второй клик подряд должен подсветить снова.
  const [flash, setFlash] = useState(0)
  const consumers = useRef<HTMLDivElement>(null)
  // Замечания к значениям: пробел на конце, заготовка вместо значения, отладка
  // на боевом стенде. Считает сервер - на экране значений нет.
  const [notes, setNotes] = useState<SecretNote[]>([])
  // Показать только давние значения: ответ на "что тут не меняли годами".
  const [onlyOld, setOnlyOld] = useState(false)
  // Показать только ключи с замечаниями: их четыре из сотни, и искать глазами
  // янтарные точки по всему списку - работа, которой здесь не место.
  const [onlyNotes, setOnlyNotes] = useState(false)
  // Чего здесь нет, а в соседних окружениях есть. Ключ добавили в stage, на
  // прод забыли - авария, которую иначе находят на выкате.
  const [missing, setMissing] = useState<MissingKey[]>([])
  // Принятые замечания: без списка "так и надо" было решением в один конец.
  const [muted, setMuted] = useState<MutedNote[]>([])

  // Принять замечание: панель перестает про него говорить. Списка "принятых"
  // на экране нет - он появится, когда о нем спросят; сейчас важнее, чтобы
  // ложное замечание убиралось в один клик, а не копилось.
  const accept = useCallback(
    async (note: SecretNote) => {
      try {
        await muteNote(envId, { name: note.name, path: note.path, code: note.code })
        setNotes((prev) =>
          prev.filter(
            (n) => !(n.name === note.name && n.path === note.path && n.code === note.code),
          ),
        )
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err))
      }
    },
    [envId],
  )
  // Какая строка только что скопирована: подпись живет полторы секунды.
  const [copied, setCopied] = useState<string | null>(null)
  const search = useRef<HTMLInputElement>(null)
  const [filter, setFilter] = useState(initialQuery)
  // Новый поиск в адресе (палитра нашла ключ, "назад" по истории) при уже
  // открытом окружении: состояние из первого захода его не видело, и в адресе
  // висел ?q=, а список оставался нефильтрованным.
  useEffect(() => {
    setFilter(initialQuery)
  }, [initialQuery])
  useEffect(() => {
    onFilter?.(filter)
  }, [filter, onFilter])
  const [modal, setModal] = useState<Modal>(null)
  const [error, setError] = useState('')
  // Ключ e2e-проекта живет в памяти вкладки: ни в хранилище браузера, ни в
  // адресе, ни тем более на сервере.
  const [projectKey, setProjectKey] = useState<Bytes | null>(
    projectId ? keyFor(projectId) : null,
  )

  const key = (s: { path: string; name: string }) => `${s.path}:${s.name}`

  const reload = useCallback(async () => {
    try {
      const [permissions, secrets, waiting] = await Promise.all([
        myPermissions(envId),
        listSecrets(envId),
        listPending(envId),
      ])
      setCan(permissions)
      setRows(secrets)
      setPending(waiting)
      setLoaded(true)
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [envId])

  useEffect(() => {
    setOpened({})
    setOpenMenu(null)
    void reload()
  }, [reload])

  useEffect(() => {
    setMissing([])
    missingKeys(envId)
      .then(setMissing)
      .catch(() => setMissing([]))
    listMutes(envId)
      .then(setMuted)
      .catch(() => setMuted([]))
  }, [envId, rows])

  useEffect(() => {
    setNotes([])
    // В проекте с шифрованием в браузере сервер значений не видит: там его
    // "замечания" были бы замечаниями к шифротексту.
    if (e2e) return
    lintEnv(envId)
      // Без права читать значения проверка недоступна - это не ошибка
      // страницы, просто замечаний не будет.
      .then(setNotes)
      .catch(() => setNotes([]))
  }, [envId, e2e, rows])

  // Незакрытая правка значения не должна исчезать молча: браузер спросит, точно
  // ли уходим. Внутри страницы черновик живет сам - его не трогает даже
  // автозакрытие по времени.
  useEffect(() => {
    const dirty = Object.values(opened).some((row) => row.draft !== row.value)
    if (!dirty) return
    const warn = (event: BeforeUnloadEvent) => event.preventDefault()
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [opened])

  // Режим могли включить только что, в окне настроек: ключ уже лежит в памяти
  // вкладки, и спрашивать пароль заново было бы странно.
  useEffect(() => {
    setProjectKey(projectId ? keyFor(projectId) : null)
  }, [projectId, e2e])

  // Ключ окружения у сервера - "группа/проект/окружение"; группу знает адрес
  // страницы. По нему из отчета агента находится нужное приложение.
  const target =
    shareView && shareView.kind === 'env'
      ? `${shareView.group ? `${shareView.group}/` : ''}${shareView.slug}/${shareView.env}`
      : ''

  // Стрелки водят по списку, Enter открывает значение, Esc закрывает все
  // открытое. Список длинный, и тянуться к мыши ради каждой строки незачем.
  function onListKey(event: ReactKeyboardEvent<HTMLDivElement>) {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
    const rows = Array.from(
      event.currentTarget.querySelectorAll<HTMLElement>('.key-row[tabindex]'),
    )
    const at = rows.indexOf(document.activeElement as HTMLElement)
    const next = event.key === 'ArrowDown' ? at + 1 : at - 1
    const target = rows[next < 0 ? 0 : next]
    if (!target) return
    event.preventDefault()
    target.focus()
  }

  // "/" ставит курсор в поиск - привычка из почты, гита и всего, где ищут
  // часто. Внутри поля и в диалогах не перехватываем: там косая черта это
  // просто символ.
  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null
      const typing = target && ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)
      // Esc закрывает все открытое: значения не должны оставаться на экране
      // дольше, чем нужно, а тянуться к "Скрыть" в каждой строке - работа.
      if (event.key === 'Escape' && !typing) {
        setOpened({})
        return
      }
      if (event.key !== '/' || event.metaKey || event.ctrlKey || event.altKey) return
      if (typing) return
      event.preventDefault()
      search.current?.focus()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Строка приложения этого окружения у конкретного сервера - если он о ней
  // отчитался. Сборке CI отчитываться нечем, и это нормально.
  const appOf = (server: Machine) => server.apps?.find((row) => row.environment === target)

  // Кто забирает это окружение. Список серверов виден только ответственным, и
  // отказ здесь не должен ломать страницу с ключами - молча показываем пусто.
  const watchServers = auth.isManager && !!shareView && shareView.kind === 'env'
  const loadServers = useCallback(() => {
    if (!watchServers) {
      setServers([])
      return
    }
    // Сбой опроса оставляет прежний список: разовый 502 иначе прятал блок
    // "Где используется" до следующего опроса.
    listMachines()
      .then((all) => setServers(all.filter((m) => m.environments.includes(target))))
      .catch(() => undefined)
  }, [watchServers, target])
  useEffect(() => loadServers(), [loadServers])
  // "Обновлено N минут назад" у серверов - то, по чему проверяют, доехала ли
  // правка: снятое один раз при открытии, оно застывало на часы.
  usePoll(loadServers, 30_000, watchServers)

  useEffect(() => {
    setLimit(300)
  }, [filter, envId])

  useEffect(() => {
    setOnlyNotes(false)
  }, [envId])

  const noted = useMemo(() => new Set(notes.map((n) => `${n.path}:${n.name}`)), [notes])

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    let found = needle
      ? rows.filter(
          (r) =>
            r.name.toLowerCase().includes(needle) || r.path.toLowerCase().includes(needle),
        )
      : rows
    if (onlyNotes) found = found.filter((r) => noted.has(`${r.path}:${r.name}`))
    if (onlyOld) found = found.filter((r) => oldValue(r.updated_at, staleAfterDays))
    return found
  }, [rows, filter, onlyNotes, onlyOld, noted, staleAfterDays])

  // Группируем по папкам: сотня ключей в одном списке читается хуже, чем те же
  // сто в пяти подписанных группах.
  const shown = useMemo(() => visible.slice(0, limit), [visible, limit])

  // По ключу: первое замечание показываем строкой, остальные - подсказкой.
  const noteFor = useMemo(() => {
    const map = new Map<string, SecretNote[]>()
    for (const note of notes) {
      const id = `${note.path}:${note.name}`
      map.set(id, [...(map.get(id) ?? []), note])
    }
    return map
  }, [notes])

  const folders = useMemo(() => {
    const map = new Map<string, SecretRow[]>()
    for (const row of shown) map.set(row.path, [...(map.get(row.path) ?? []), row])
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b))
  }, [shown])

  useEffect(() => {
    if (!flash) return
    const id = window.setTimeout(() => setFlash(0), 1200)
    return () => window.clearTimeout(id)
  }, [flash])

  /** Подпись ключа и срок замены значения. */
  async function editMeta(row: SecretRow) {
    const answer = await ask({
      title: `${t('Описание и срок действия')}: ${row.name}`,
      text: t('Описание показывается в списке ключей. Срок действия — дата плановой замены значения, уведомление приходит заранее.'),
      submit: t('Сохранить'),
      fields: [
        {
          name: 'note',
          label: t('Описание'),
          value: row.note,
          placeholder: t('например: токен бота для оповещений'),
          optional: true,
        },
        {
          name: 'expires',
          label: t('Срок действия до'),
          value: row.expires_at ? row.expires_at.slice(0, 10) : '',
          placeholder: '2027-03-01',
          optional: true,
        },
      ],
    })
    if (!answer) return
    try {
      await setSecretMeta(envId, row.name, row.path, answer.note.trim(), answer.expires.trim())
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  /** Где еще в панели лежит ровно это же значение. */
  async function findSame(row: SecretRow) {
    try {
      setSame({ name: row.name, rows: await sameValue(envId, row.name, row.path) })
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  /** Кому видно это окружение. */
  async function showWho() {
    try {
      setWho(await whoSees(envId))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  /** Показать, что здесь происходило в последнее время. */
  async function showEvents() {
    try {
      setEvents(await envEvents(envId, 20))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  /** Показать ключи, которых давно никто не открывал. */
  async function showIdle() {
    try {
      setIdle(await idleSecrets(envId))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  /** Сравнить с соседним окружением: выбрать, с каким, и показать разницу. */
  async function compare() {
    const answer = await ask({
      title: t('Сравнить с другим окружением'),
      text: t('Значения сравниваются на сервере и в ответе не передаются.'),
      submit: t('Сравнить'),
      fields: [
        {
          name: 'env',
          label: t('Окружение для сравнения'),
          type: 'select',
          options: siblings.map((s) => ({ value: String(s.id), label: s.name })),
          value: String(siblings[0].id),
        },
      ],
    })
    if (!answer) return
    try {
      setDiff(await compareEnvs(envId, Number(answer.env)))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  /** Куда ведет клетка "серверы". */
  function showServers() {
    const open = onOpenServer && auth.isManager ? onOpenServer : null
    if (open && servers.length === 1) {
      open(servers[0])
      return
    }
    // Серверов несколько (или ходить в них некому): показываем список, где они
    // все перечислены. Плавную прокрутку выключаем тем, кто просил меньше
    // движения на экране.
    const calm = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    consumers.current?.scrollIntoView?.({
      behavior: calm ? 'auto' : 'smooth',
      block: 'center',
    })
    setFlash((n) => n + 1)
  }

  // Клик по точкам открывает значение и сразу отдает его в правку: в ключ
  // заглядывают чаще всего затем, чтобы его поменять, и отдельное окно ради
  // одной строки было лишним шагом.
  async function reveal(secret: SecretRow) {
    const id = key(secret)
    if (opened[id]) return
    try {
      const res = await readSecret(envId, secret.name, secret.path)
      // В e2e-проекте сервер отдал шифротекст: открыть его может только эта
      // вкладка, и только пока в ней есть ключ проекта.
      const value = await incoming(res.value)
      setOpened((prev) => ({
        ...prev,
        [id]: { value, draft: value, busy: false, note: '' },
      }))
      setError('')
      // Значение не висит на экране вечно. Начатую правку таймер не трогает:
      // потерять набранное хуже, чем оставить строку открытой.
      window.setTimeout(() => {
        setOpened((prev) => {
          const cur = prev[id]
          if (!cur || cur.draft !== cur.value) return prev
          const next = { ...prev }
          delete next[id]
          return next
        })
      }, HIDE_AFTER_MS)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  // Открыть все разом: глазами сравнивают соседние ключи, и щелкать по каждому
  // ради этого - работа, которую панель может сделать сама. Значения по-прежнему
  // едут по одному, поэтому каждое видно в журнале отдельной строкой.
  // Буфер обмена: сначала обычный путь, потом запасной. Современный API
  // работает не везде - в старом браузере, в http-стенде без TLS и при
  // отозванном разрешении он просто отказывает, а значение нужно все равно.
  async function copyText(text: string) {
    try {
      await navigator.clipboard.writeText(text)
      return
    } catch {
      const field = document.createElement('textarea')
      field.value = text
      field.style.cssText = 'position:fixed;opacity:0'
      document.body.appendChild(field)
      field.select()
      const ok = document.execCommand('copy')
      field.remove()
      if (!ok) throw new Error(CLIPBOARD_CLOSED)
    }
  }

  // Скопировать значение, не показывая его. Самое частое действие на этой
  // странице: значение нужно вставить в терминал или в конфиг, а не прочитать
  // глазами. Показывать его ради этого - лишний риск и лишний клик.
  async function copyValue(secret: SecretRow) {
    const id = key(secret)
    try {
      const res = await readSecret(envId, secret.name, secret.path)
      await copyText(await incoming(res.value))
      setCopied(id)
      window.setTimeout(() => setCopied((cur) => (cur === id ? null : cur)), 1500)
      toast(`${secret.name} ${t('скопирован')}`)
      setError('')
    } catch (e) {
      // Буфер бывает закрыт: без TLS, в чужой обертке, при отозванном
      // разрешении. Тогда не ругаемся, а открываем значение - скопировать его
      // руками человек все равно сможет.
      if (e instanceof Error && e.message === CLIPBOARD_CLOSED) {
        await reveal(secret)
        return
      }
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  function hide(id: string) {
    setOpened((prev) => {
      const next = { ...prev }
      delete next[id]
      return next
    })
  }

  function draft(id: string, text: string) {
    setOpened((prev) => (prev[id] ? { ...prev, [id]: { ...prev[id], draft: text, note: '' } } : prev))
  }

  async function saveInline(secret: SecretRow) {
    const id = key(secret)
    const opened0 = opened[id]
    if (!opened0) return
    // Однострочное значение, к которому Enter дописал перевод строки только в
    // конец, - это нажатый по привычке Enter, а не новая строка: хвостовой
    // перевод строки в адресе базы или токене ломает приложение. Значение,
    // которое и было многострочным, и строки внутри не трогаем.
    const accidental = !opened0.value.includes('\n') && /^[^\n]*\n+$/.test(opened0.draft)
    const cur = accidental ? { ...opened0, draft: opened0.draft.replace(/\n+$/, '') } : opened0
    if (cur.draft === cur.value) {
      hide(id)
      return
    }
    setOpened((prev) => ({ ...prev, [id]: { ...prev[id], busy: true } }))
    try {
      const row = await putSecret(envId, {
        name: secret.name,
        path: secret.path,
        value: await outgoing(cur.draft),
      })
      // Строка остается открытой с новым значением: так видно, что сохранилось
      // именно то, что набрали, и не нужно открывать ключ заново ради проверки.
      setOpened((prev) => ({
        ...prev,
        [id]: {
          value: cur.draft,
          draft: cur.draft,
          busy: false,
          note: row.pending ? t('ждёт подтверждения') : `${t('сохранено')} · v${row.version}`,
          // Раскладку не меняем: строка, в которой только что правили, не
          // должна прыгать от нажатия "Сохранить".
          wide: prev[id]?.wide,
        },
      }))
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setOpened((prev) => (prev[id] ? { ...prev, [id]: { ...prev[id], busy: false } } : prev))
    }
  }

  /** Значение на сервер: в e2e-проекте его запечатывает браузер. */
  async function outgoing(value: string): Promise<string> {
    if (!e2e) return value
    if (!projectKey) throw new Error(t('Сначала введите пароль проекта'))
    return sealValue(projectKey, value)
  }

  /** Значение с сервера: в e2e-проекте это блоб, и раскрыть его можно только здесь. */
  async function incoming(value: string): Promise<string> {
    if (!e2e) return value
    // Без ключа показывать нечего. Блоб на месте значения выглядит значением:
    // его скопировали бы в конфиг под надписью "скопирован".
    if (!projectKey) throw new Error(t('Сначала введите пароль проекта'))
    return openValue(projectKey, value)
  }

  async function unlock() {
    try {
      const wrap = await getE2eWrap(projectId)
      const answer = await ask({
        title: t('Пароль проекта'),
        text: t(
          'Значения проекта шифруются в браузере. Сервер пароль не хранит и восстановить не может.',
        ),
        submit: t('Открыть'),
        fields: [{ name: 'password', label: t('Пароль проекта'), type: 'password' }],
      })
      if (!answer) return
      const key = await unlockProjectKey(wrap, answer.password)
      if (!key) {
        setError(t('Пароль не подошёл'))
        return
      }
      rememberKey(projectId, key)
      setProjectKey(key)
      setError('')
      setOpened({})
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  function lock() {
    forgetKey(projectId)
    setProjectKey(null)
    setOpened({})
  }

  const chosen = () => visible.filter((row) => picked[key(row)])

  function unpick() {
    setPicking(false)
    setPicked({})
  }

  // Переносим по одному: у панели нет пакетной ручки, и заводить её ради
  // десятка ключей не стоит - зато каждая правка попадает в журнал отдельной
  // записью, как любая другая.
  async function moveChosen() {
    const rows = chosen()
    if (rows.length === 0) return
    const answer = await ask({
      title: t('Перенести в папку'),
      text: t('Меняется только путь ключей, значения и история сохраняются.'),
      submit: t('Перенести'),
      fields: [{ name: 'path', label: t('Папка'), value: rows[0].path, placeholder: '/infra' }],
    })
    if (!answer) return
    const target = answer.path.trim() || '/'
    await act(async () => {
      for (const row of rows) {
        if (row.inherited_from) continue
        await renameSecret(envId, {
          name: row.name,
          path: row.path,
          new_name: row.name,
          new_path: target,
        })
      }
      unpick()
    })
  }

  async function deleteChosen() {
    const rows = chosen().filter((row) => !row.inherited_from)
    if (rows.length === 0) return
    const yes = await confirm({
      title: t('Удалить выбранные ключи?'),
      text: `${rows.length} ${plural(rows.length, [t('ключ'), t('ключа'), t('ключей')])} — ${t('значения останутся в истории, но выдаваться перестанут')}`,
      submit: t('Удалить'),
      danger: true,
    })
    if (!yes) return
    await act(async () => {
      for (const row of rows) await deleteSecret(envId, row.name, row.path)
      unpick()
    })
  }

  async function bringBack(note: MutedNote) {
    try {
      await unmuteNote(envId, { name: note.name, path: note.path, code: note.code })
      setMuted((prev) => prev.filter((m) => !(m.name === note.name && m.path === note.path && m.code === note.code)))
      lintEnv(envId)
        .then(setNotes)
        .catch(() => undefined)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  // Перенос значения между окружениями - не мелочь: спрашиваем прямо, и в
  // вопросе говорим, что именно случится и с чем ничего не случится.
  async function take(row: MissingKey, source: string) {
    const yes = await confirm({
      title: t('Взять значение из {env}?', { env: source }),
      text: t('Значение {name} будет скопировано из {env} новой версией. Исходное окружение не изменится.', {
        name: row.name,
        env: source,
      }),
      submit: t('Взять'),
    })
    if (!yes) return
    await act(async () => {
      await copyFrom(envId, { source, name: row.name, path: row.path })
    })
  }

  async function act(action: () => Promise<unknown>) {
    setOpenMenu(null)
    try {
      await action()
    } catch (e) {
      // Пакетный перенос или удаление могли успеть часть ключей: список
      // перечитывается и после отказа, иначе он показывал уже удаленное.
      void reload()
      // Окном, а не строкой наверху: действия вызывают из меню строки, и на
      // сотом ключе шапка страницы далеко за пределами экрана - отказ там
      // просто никто не увидит.
      await notify(t('Не получилось'), e instanceof Error ? e.message : String(e))
      return
    }
    await reload()
  }

  async function review(row: PendingRow, approve: boolean) {
    if (approve) {
      await act(() => approveSecret(envId, row.name, row.path, row.version))
      return
    }
    const answer = await ask({
      title: t('Отклонить правку'),
      text: `${row.name} · ${row.author}`,
      submit: t('Отклонить'),
      danger: true,
      fields: [
        {
          name: 'note',
          label: t('Причина'),
          type: 'textarea',
          placeholder: t('её увидит автор, и она останется в истории'),
        },
      ],
    })
    if (!answer) return
    await act(() => rejectSecret(envId, row.name, row.path, row.version, answer.note))
  }

  // Сводка страницы. Четыре числа вместо разбега глазами по списку: сколько
  // всего, сколько пришло из родителя (по этому вопросу чаще всего и спорят с
  // панелью), сколько правок ждет и сколько серверов это забирает.
  const inherited = rows.filter((row) => row.inherited_from).length
  // Обязательные ключи проекта, которых здесь нет. Считаем по именам без
  // папки: приложение читает переменную окружения, а не путь в панели.
  const lacking = useMemo(() => {
    if (required.length === 0) return []
    const here = new Set(rows.map((row) => row.name))
    return required.filter((name) => !here.has(name))
  }, [required, rows])

  // Сколько значений не трогали больше года: не авария, но и не пустяк.
  const stale = rows.filter((row) => oldValue(row.updated_at, staleAfterDays)).length

  return (
    <div className="stack">
      <ErrorNote text={error} onClose={() => setError('')} />

      <div className="summary">
        <div className="summary-cell">
          <span className="summary-number">{rows.length}</span>
          <span className="muted small">
            {plural(rows.length, [t('ключ'), t('ключа'), t('ключей')])}
          </span>
        </div>
        {inherited > 0 && (
          <div className="summary-cell">
            <span className="summary-number">{inherited}</span>
            <span className="muted small">{t('из родителя')}</span>
          </div>
        )}
        {/* Ноль ожидающих не показываем: клетка со "стало нечего ждать"
            занимает место наравне с числом ключей, а говорит ровно ничего. */}
        {pending.length > 0 && (
          <div className="summary-cell">
            <span className="summary-number summary-warn">{pending.length}</span>
            <span className="muted small">{t('ждут подтверждения')}</span>
          </div>
        )}
        {stale > 0 && (
          <button
            className={`summary-cell summary-link${onlyOld ? ' summary-cell-on' : ''}`}
            onClick={() => setOnlyOld((v) => !v)}
            title={
              onlyOld
                ? t('показать все ключи')
                : t('оставить только давние значения')
            }
          >
            <span className="summary-number">{stale}</span>
            <span className="muted small">{t('давние')}</span>
          </button>
        )}
        {noteFor.size > 0 && (
          // Кликается: счетчик и есть самый короткий путь к тем ключам, ради
          // которых он показан.
          <button
            className={`summary-cell summary-link${onlyNotes ? ' summary-cell-on' : ''}`}
            onClick={() => setOnlyNotes((v) => !v)}
            title={onlyNotes ? t('показать все ключи') : t('оставить только ключи с замечаниями')}
          >
            <span className="summary-number summary-warn">{noteFor.size}</span>
            <span className="muted small">{t('с замечаниями')}</span>
          </button>
        )}
        {servers.length > 0 && (
          // Клетка кликается: число серверов и есть самый короткий путь к тому,
          // что за ними стоит.
          <button
            className="summary-cell summary-link"
            title={
              servers.length === 1 && auth.isManager && onOpenServer
                ? t('открыть сервер')
                : t('показать, кто забирает это окружение')
            }
            onClick={showServers}
          >
            <span
              className={`summary-number${
                servers.some((s) => s.last_seen_at && !staleClass(s.last_seen_at))
                  ? ' summary-ok'
                  : ''
              }`}
            >
              {servers.length}
            </span>
            <span className="muted small">
              {plural(servers.length, [t('сервер'), t('сервера'), t('серверов')])}
            </span>
          </button>
        )}
      </div>

      {servers.length > 0 && (
        // Имени сервера мало: на одном сервере живет несколько приложений, и
        // вопрос "к чему относятся эти переменные" без файла не закрывается.
        // Путь берется из отчета агента - он же говорит, когда значения
        // доехали. Машина без строки приложения (сборка CI, чужой хостинг)
        // показывает только имя: файла у нее нет, и идет она следом.
        <div ref={consumers} className={`consumers${flash ? ' consumers-flash' : ''}`}>
          <span className="consumers-title muted small">{t('Где используется')}</span>
          {[...servers]
            .sort((a, b) => Number(appOf(b) !== undefined) - Number(appOf(a) !== undefined))
            .map((server) => {
              const app = appOf(server)
              const seen = app?.last_seen_at || server.last_seen_at
              // Имя сервера здесь - не подпись, а дорога: следующий вопрос
              // после "кто это забирает" почти всегда "а что там еще".
              const open = onOpenServer && auth.isManager ? onOpenServer : null
              const inside = (
                <>
                  <span
                    className={`sdot ${seen && !staleClass(seen) ? 'sdot-up' : 'sdot-stale'}`}
                    title={seen ? formatDateTime(seen) : t('ещё не забирал')}
                  />
                  <span className="consumer-name">{server.name}</span>
                  {app?.path && (
                    <span className="mono small muted consumer-path" title={app.path}>
                      {app.path}
                    </span>
                  )}
                  <span className="spacer" />
                  <span className={`small ${seen ? staleClass(seen) || 'muted' : 'stale-warn'}`}>
                    {seen ? formatAgo(seen, lang) : t('ещё не забирал')}
                  </span>
                  {open && <span className="chev">›</span>}
                </>
              )
              return open ? (
                <button
                  key={server.id}
                  className="consumer-row consumer-open"
                  title={t('Открыть сервер')}
                  onClick={() => open(server)}
                >
                  {inside}
                </button>
              ) : (
                <div key={server.id} className="consumer-row">
                  {inside}
                </div>
              )
            })}
        </div>
      )}

      {pending.length > 0 && (
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">{t('Ждут подтверждения')}</span>
            <span className="key-folder-count">{pending.length}</span>
          </div>
          {pending.map((p) => (
            <div key={`${p.path}:${p.name}:${p.version}`} className="pending-row">
              <span className="key-dot audit-dot-sensitive" />
              <span className="mono pending-name">
                {p.path !== '/' && <span className="muted">{p.path}/</span>}
                {p.name}
              </span>
              <span className="muted small pending-who" title={p.comment ? versionComment(p.comment) : undefined}>
                {p.author}
                {p.comment && ` · ${versionComment(p.comment)}`}
              </span>
              <span className="spacer" />
              {can.approve ? (
                <>
                  <button className="ghost small-btn" onClick={() => void review(p, true)}>
                    {t('Подтвердить')}
                  </button>
                  <button
                    className="ghost small-btn danger-text"
                    onClick={() => void review(p, false)}
                  >
                    {t('Отклонить')}
                  </button>
                </>
              ) : (
                <span className="muted small">{t('ждёт того, кто выше')}</span>
              )}
            </div>
          ))}
        </section>
      )}

      {e2e && (
        <div className="banner">
          {projectKey
            ? t('Значения этого проекта шифруются в браузере. Ключ открыт в этой вкладке.')
            : t('Значения этого проекта шифруются в браузере: без пароля проекта их не прочитать.')}{' '}
          <button className="ghost small-btn" onClick={projectKey ? lock : () => void unlock()}>
            {projectKey ? t('Запереть') : t('Ввести пароль проекта')}
          </button>
        </div>
      )}

      <div className="card stack">
        <div className="row-actions">
          <input
            ref={search}
            style={{ flex: 1, minWidth: 180 }}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder={t('поиск по ключам — /')}
          />
          {filter && (
            <span className="muted small search-count">
              {visible.length} {t('из')} {rows.length}
            </span>
          )}
          {can.write && (
            <button onClick={() => setModal({ kind: 'new' })}>{t('Добавить ключ')}</button>
          )}
          {can.write && visible.length > 1 && (
            <button className="ghost" onClick={() => (picking ? unpick() : setPicking(true))}>
              {picking ? t('Отмена') : t('Выбрать')}
            </button>
          )}
          {/* Здесь стояло "показать все": сотня открытых значений в строках
              по восемь символов - то же полотно, только светящееся. Правка
              всего разом показывает их там же, где их и правят. */}
          {!e2e && can.read && rows.length > 0 && (
            <button className="ghost" onClick={() => setModal({ kind: 'bulk' })}>
              {can.write ? t('Редактировать все') : t('Все значения')}
            </button>
          )}
          {/* Работа с файлом целиком: выгрузить, поправить в своем редакторе,
              залить обратно. Нужное, но редкое - под меню. */}
          {!e2e && can.write && (
            <div className="menu-wrap">
              <button
                className="ghost icon-btn"
                aria-label={t('Меню')}
                onClick={() => setBulkMenu((v) => !v)}
              >
                ⋯
              </button>
              {bulkMenu && (
                <>
                  <div className="menu-catcher" onClick={() => setBulkMenu(false)} />
                  <div className="menu-pop menu-pop-right">
                    <button
                      className="menu-item"
                      onClick={() => {
                        setBulkMenu(false)
                        setModal({ kind: 'import' })
                      }}
                    >
                      {t('Импорт из .env')}
                    </button>
                    {siblings.length > 0 && (
                      <button
                        className="menu-item"
                        onClick={() => {
                          setBulkMenu(false)
                          void compare()
                        }}
                      >
                        {t('Сравнить с другим окружением')}
                      </button>
                    )}
                    <button
                      className="menu-item"
                      onClick={() => {
                        setBulkMenu(false)
                        void showIdle()
                      }}
                    >
                      {t('Неиспользуемые ключи')}
                    </button>
                    <button
                      className="menu-item"
                      onClick={() => {
                        setBulkMenu(false)
                        void showEvents()
                      }}
                    >
                      {t('Журнал окружения')}
                    </button>
                    {auth.isManager && (
                      <button
                        className="menu-item"
                        onClick={() => {
                          setBulkMenu(false)
                          void showWho()
                        }}
                      >
                        {t('Права доступа')}
                      </button>
                    )}
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        {!loaded && <p className="muted">{t('Загружаем…')}</p>}
        {loaded && visible.length === 0 && (
          <div className="empty">
            {rows.length ? (
              <>
                <p className="empty-title">{t('Ничего не нашлось')}</p>
                <p className="muted small">{t('Поиск идёт по имени ключа и по папке.')}</p>
                <button className="ghost" onClick={() => setFilter('')}>
                  {t('Сбросить поиск')}
                </button>
              </>
            ) : (
              <>
                <p className="empty-title">{t('Ключей пока нет')}</p>
                <p className="muted small">
                  {e2e
                    ? t('Добавьте первый ключ: значение запечатает браузер.')
                    : t('Добавьте первый или залейте готовый .env через импорт.')}
                </p>
                {can.write && (
                  <div className="row-actions">
                    <button onClick={() => setModal({ kind: 'new' })}>{t('Добавить ключ')}</button>
                    {/* В e2e-проекте импорта нет и здесь: файл ушел бы на сервер
                        открытым текстом, ради сокрытия которого режим включали. */}
                    {!e2e && (
                      <button className="ghost" onClick={() => setModal({ kind: 'import' })}>
                        {t('Импорт из .env')}
                      </button>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>

      {same && (
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">
              {t('Совпадения значения')}: {same.name}
            </span>
            <span className="key-folder-count">{same.rows.length}</span>
            <span className="spacer" />
            <button className="ghost small-btn" onClick={() => setSame(null)}>
              {t('Закрыть')}
            </button>
          </div>
          {same.rows.length === 0 && (
            <div className="miss-row muted small">{t('Совпадений нет')}</div>
          )}
          {same.rows.map((row) => (
            <div
              key={`${row.project}/${row.environment}${row.path}${row.name}`}
              className="miss-row"
            >
              <span className="key-dot key-dot-note" />
              <span className="mono miss-name">
                {row.project}/{row.environment}
              </span>
              <span className="mono muted small">
                {row.path !== '/' && `${row.path}/`}
                {row.name}
              </span>
            </div>
          ))}
        </section>
      )}

      {who && (
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">{t('Права доступа')}</span>
            <span className="key-folder-count">{who.length}</span>
            <span className="spacer" />
            <button className="ghost small-btn" onClick={() => setWho(null)}>
              {t('Закрыть')}
            </button>
          </div>
          {who.length === 0 && (
            <div className="miss-row muted small">{t('Только владелец панели')}</div>
          )}
          {who.map((row, index) => (
            <div key={`${row.kind}:${row.subject}:${index}`} className="miss-row">
              <span className={`key-dot${row.effect === 'deny' ? ' key-dot-note' : ''}`} />
              <span className="mono miss-name">{row.subject}</span>
              <span className="tag tag-muted">
                {row.kind === 'user'
                  ? t('человек')
                  : row.kind === 'machine'
                    ? t('машина')
                    : t('группа')}
              </span>
              {row.effect === 'deny' && <span className="tag tag-deny">{t('запрет')}</span>}
              {row.whole_project && (
                <span className="muted small">{t('на весь проект')}</span>
              )}
              <span className="spacer" />
              <span className="muted small">{row.actions.join(', ')}</span>
              {row.until && (
                <span className="muted small">
                  {t('до')} {formatDate(row.until)}
                </span>
              )}
            </div>
          ))}
        </section>
      )}

      {events && (
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">{t('Журнал окружения')}</span>
            <span className="key-folder-count">{events.length}</span>
            <span className="spacer" />
            <button className="ghost small-btn" onClick={() => setEvents(null)}>
              {t('Закрыть')}
            </button>
          </div>
          {events.length === 0 && (
            <div className="miss-row muted small">{t('Событий нет')}</div>
          )}
          {events.map((event, index) => (
            <div key={`${event.at}:${index}`} className="miss-row">
              <span className="key-dot" />
              <span className="mono miss-name">{event.key || '—'}</span>
              <span className="muted small">{t(EVENTS[event.action] ?? ACTIONS[event.action] ?? event.action)}</span>
              <span className="spacer" />
              <span className="muted small">{serverText(event.actor)}</span>
              <span className="muted small" title={formatDateTime(event.at)}>
                {formatAgo(event.at, lang)}
              </span>
            </div>
          ))}
        </section>
      )}

      {lacking.length > 0 && (
        // Не "нет здесь, а рядом есть": это требование проекта, и оно работает
        // даже в новом окружении, где пусто везде и сравнивать не с чем.
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">{t('Отсутствуют обязательные ключи')}</span>
            <span className="key-folder-count">{lacking.length}</span>
          </div>
          {lacking.map((name) => (
            <div key={name} className="miss-row">
              <span className="key-dot key-dot-note" />
              <span className="mono miss-name">{name}</span>
              <span className="spacer" />
              {can.write && (
                <button
                  className="ghost small-btn"
                  onClick={() => setModal({ kind: 'new' })}
                >
                  {t('Добавить')}
                </button>
              )}
            </div>
          ))}
        </section>
      )}

      {idle && (
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">{t('Без чтений за год')}</span>
            <span className="key-folder-count">{idle.rows.length}</span>
            {/* Дата начала журнала - не пояснение, а условие: без нее
                "никто не читал" можно прочитать неверно. */}
            {idle.log_since && (
              <span className="muted small role-hint">
                {t('журнал с')} {formatDate(idle.log_since)}
              </span>
            )}
            <span className="spacer" />
            <button className="ghost small-btn" onClick={() => setIdle(null)}>
              {t('Закрыть')}
            </button>
          </div>
          {idle.rows.length === 0 && (
            <div className="miss-row muted small">{t('Все ключи читались за последний год')}</div>
          )}
          {idle.rows.map((row) => (
            <div key={`${row.path}:${row.name}`} className="miss-row">
              <span className="key-dot" />
              <span className="mono miss-name">
                {row.path !== '/' && <span className="muted">{row.path}/</span>}
                {row.name}
              </span>
              <span className="spacer" />
              {row.updated_at && (
                <span className="muted small" title={formatDateTime(row.updated_at)}>
                  {t('изменён')} {formatAgo(row.updated_at, lang)}
                </span>
              )}
            </div>
          ))}
        </section>
      )}

      {diff && (
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">
              {t('Расхождения с')} {diff.other}
            </span>
            <span className="key-folder-count">{diff.rows.length}</span>
            <span className="muted small role-hint">
              {t('совпадений')}: {diff.same}
            </span>
            <span className="spacer" />
            <button className="ghost small-btn" onClick={() => setDiff(null)}>
              {t('Закрыть')}
            </button>
          </div>
          {diff.rows.length === 0 && (
            <div className="miss-row muted small">{t('Расхождений нет')}</div>
          )}
          {diff.rows.map((row) => (
            <div key={`${row.path}:${row.name}:${row.state}`} className="miss-row">
              <span className={`key-dot${row.state === 'differs' ? ' key-dot-note' : ''}`} />
              <span className="mono miss-name">
                {row.path !== '/' && <span className="muted">{row.path}/</span>}
                {row.name}
              </span>
              <span className="spacer" />
              <span className={`small ${row.state === 'differs' ? 'stale-warn' : 'muted'}`}>
                {row.state === 'differs'
                  ? t('значения различаются')
                  : row.state === 'here'
                    ? `${t('нет в')} ${diff.other}`
                    : row.state === 'there'
                      ? t('нет в текущем')
                      : t('нет права на чтение')}
              </span>
            </div>
          ))}
        </section>
      )}

      {missing.length > 0 && (
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">{t('Отсутствуют в этом окружении')}</span>
            <span className="key-folder-count">{missing.length}</span>
          </div>
          {missing.map((row) => (
            <div key={`${row.path}:${row.name}`} className="miss-row">
              <span className="key-dot" />
              <span className="mono miss-name">
                {row.path !== '/' && <span className="muted">{row.path}/</span>}
                {row.name}
              </span>
              <span className="spacer" />
              <span className="muted small">{t('найден в')}</span>
              {row.present_in.map((where) => (
                <button
                  key={where}
                  className="ghost small-btn"
                  disabled={!can.write}
                  title={
                    can.write
                      ? t('Скопировать значение из этого окружения')
                      : t('Нет права на запись')
                  }
                  onClick={() => void take(row, where)}
                >
                  {where}
                </button>
              ))}
            </div>
          ))}
        </section>
      )}

      {visible.length > shown.length && (
        <div className="row-actions">
          <button className="ghost" onClick={() => setLimit((n) => n + 300)}>
            {t('Показать ещё')}
          </button>
          <span className="muted small">
            {shown.length} {t('из')} {visible.length}
          </span>
        </div>
      )}

      {muted.length > 0 && (
        <section className="key-folder">
          <div className="key-folder-head">
            <span className="key-folder-name">{t('Принятые замечания')}</span>
            <span className="key-folder-count">{muted.length}</span>
          </div>
          {muted.map((note) => (
            <div key={`${note.path}:${note.name}:${note.code}`} className="miss-row">
              <span className="key-dot" />
              <span className="mono miss-name">
                {note.path !== '/' && <span className="muted">{note.path}/</span>}
                {note.name}
              </span>
              <span className="muted small">{t(note.text)}</span>
              <span className="spacer" />
              <span className="muted small">{note.muted_by}</span>
              {can.write && (
                <button className="ghost small-btn" onClick={() => void bringBack(note)}>
                  {t('Вернуть')}
                </button>
              )}
            </div>
          ))}
        </section>
      )}

      {picking && (
        // Полоса действий липнет к низу: список длинный, а выбирают обычно
        // сверху вниз, и возвращаться за кнопкой наверх незачем.
        <div className="pick-bar">
          <span className="small">
            {t('выбрано')} {chosen().length}
          </span>
          <span className="spacer" />
          <button className="ghost small-btn" onClick={() => setPicked({})}>
            {t('Снять выбор')}
          </button>
          <button
            className="ghost small-btn"
            disabled={chosen().length === 0}
            onClick={() => void moveChosen()}
          >
            {t('Перенести в папку')}
          </button>
          <button
            className="ghost small-btn danger-text"
            disabled={chosen().length === 0}
            onClick={() => void deleteChosen()}
          >
            {t('Удалить')}
          </button>
        </div>
      )}

      {/* Папка - полоса-заголовок, ключи под ней - отдельные строки-карточки.
          Сплошная таблица сливалась в полотно: одинаковый тон, одинаковый вес,
          не за что зацепиться взглядом. */}
      {visible.length > 0 && (
        <div className="keys" onKeyDown={onListKey}>
          {folders.map(([path, items]) => (
            <section key={path} className="key-folder">
            {folders.length > 1 && (
              <div className="key-folder-head">
                <span className="key-folder-name mono">{path}</span>
                <span className="key-folder-count">{items.length}</span>
              </div>
            )}
            {items.map((s) => {
                    const id = key(s)
                    const open = opened[id]
                    return (
                      <div
                        key={id}
                        // Открывает вся строка, а не только звездочки: целиться
                        // в восемь символов мышью - работа, которой здесь не
                        // место. Кнопки и уже открытое поле обрабатывают клик
                        // сами, поэтому их пропускаем.
                        className={[
                          'key-row',
                          open ? 'key-row-open' : 'clickable',
                          open?.wide ? 'key-row-wide' : '',
                          s.pending ? 'key-row-wait' : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                        tabIndex={picking ? 0 : open || !can.read ? undefined : 0}
                        onClick={(e) => {
                          if ((e.target as HTMLElement).closest('button, textarea, a')) return
                          // В режиме выбора строка выбирает: целиться в
                          // пятнадцать точек чекбокса - работа, а промах мимо
                          // него открыл бы значение, которого не просили.
                          if (picking) {
                            if (s.inherited_from) return
                            if ((e.target as HTMLElement).closest('input')) return
                            setPicked((prev) => ({ ...prev, [id]: !prev[id] }))
                            return
                          }
                          if (open || !can.read) return
                          void reveal(s)
                        }}
                        onKeyDown={(e) => {
                          if (e.target !== e.currentTarget) return
                          if (e.key !== 'Enter' && e.key !== ' ') return
                          if (picking) {
                            if (s.inherited_from) return
                            e.preventDefault()
                            setPicked((prev) => ({ ...prev, [id]: !prev[id] }))
                            return
                          }
                          if (open || !can.read) return
                          e.preventDefault()
                          void reveal(s)
                        }}
                      >
                        {/* Чекбокс и точка - одна колонка сетки: пятый
                            ребенок в сетке из четырех колонок сваливал меню на
                            второй ряд, а имя занимало место значения. */}
                        <span className="key-mark">
                          {picking && (
                            <input
                              type="checkbox"
                              className="key-pick"
                              checked={Boolean(picked[id])}
                              disabled={Boolean(s.inherited_from)}
                              title={
                                s.inherited_from
                                  ? t('значение из другого окружения')
                                  : undefined
                              }
                              onChange={(e) =>
                                setPicked((prev) => ({ ...prev, [id]: e.target.checked }))
                              }
                            />
                          )}
                          {/* Точка состояния - та же роль, что у нее в списке
                              мониторов: не украшение, а колонка, по которой
                              список читается сверху вниз. Открытое значение
                              светится зеленым, потому что оно на экране и это
                              ненадолго. */}
                          <span
                            className={[
                              'key-dot',
                              open ? 'key-dot-open' : '',
                              s.pending ? 'key-dot-wait' : '',
                              s.inherited_from ? 'key-dot-inherited' : '',
                              noteFor.get(`${s.path}:${s.name}`) ? 'key-dot-note' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                          />
                        </span>
                        <div className="key-name">
                          <span className="mono">{s.name}</span>
                          {s.inherited_from && (
                            <span className="tag tag-muted" title={t('значение из другого окружения')}>
                              {s.inherited_from}
                            </span>
                          )}
                          {s.pending && <span className="tag tag-wait">{t('правка ждёт')}</span>}
                          {/* Конфиг и пароль в списке выглядели одинаково, а
                              открывают их по-разному. */}
                          {s.multiline && (
                            <span className="tag tag-lines" title={t('многострочное значение')}>
                              ≡
                            </span>
                          )}
                          {/* Срок важнее возраста: он про будущее. Просроченный
                              красным, близкий - янтарным. */}
                          {s.expires_at && (
                            <span
                              className={`small ${
                                dueClass(s.expires_at) === 'over'
                                  ? 'stale-old'
                                  : dueClass(s.expires_at) === 'soon'
                                    ? 'stale-warn'
                                    : 'muted'
                              }`}
                              title={t('заменить до')}
                            >
                              {t('до')} {formatDay(s.expires_at)}
                            </span>
                          )}
                          {/* Возраст показываем только у давних: у остальных
                              это столбец одинаковых чисел, который читают один
                              раз и больше не замечают. */}
                          {oldValue(s.updated_at, staleAfterDays) && (
                            <span
                              className="muted small key-age"
                              title={`${t('последняя правка')}: ${formatDateTime(s.updated_at)}`}
                            >
                              {formatAgo(s.updated_at, lang)}
                            </span>
                          )}
                        </div>
                        <div className="key-value">
                          <ValueCell
                            open={open}
                            canRead={can.read}
                            canWrite={can.write}
                            onReveal={() => void reveal(s)}
                            onWide={() =>
                              setOpened((prev) =>
                                prev[id] ? { ...prev, [id]: { ...prev[id], wide: true } } : prev,
                              )
                            }
                            onDraft={(text) => draft(id, text)}
                            onSave={() => void saveInline(s)}
                            onHide={() => hide(id)}
                          />
                        </div>
                        <div className="key-actions">
                          {can.read && (
                            <button
                              className="ghost small-btn key-copy"
                              title={t('Скопировать значение')}
                              aria-label={t('Скопировать значение')}
                              onClick={(e) => {
                                e.stopPropagation()
                                void copyValue(s)
                              }}
                            >
                              {copied === id ? '✓' : '⧉'}
                            </button>
                          )}
                          <div className="menu-wrap">
                            <button
                              className="ghost small-btn"
                              onClick={() => setOpenMenu(openMenu === id ? null : id)}
                              aria-label={t('Меню')}
                            >
                              ⋯
                            </button>
                            {openMenu === id && (
                              <>
                                <div className="menu-catcher" onClick={() => setOpenMenu(null)} />
                                <div className="menu-pop menu-pop-right">
                                  {/* Версия и автор - здесь, а не в строке: в
                                      списке на сотню ключей это шум, а нужны
                                      они ровно в тот момент, когда открывают
                                      меню. */}
                                  <div className="menu-head">
                                    {t('версия')} {s.version}
                                    {s.updated_by && ` · ${s.updated_by}`}
                                    {s.updated_at && (
                                      <>
                                        {' · '}
                                        <span title={formatDateTime(s.updated_at)}>
                                          {formatAgo(s.updated_at, lang)}
                                        </span>
                                      </>
                                    )}
                                  </div>
                                  {can.write && (
                                    <button
                                      className="menu-item"
                                      onClick={() => {
                                        setOpenMenu(null)
                                        setModal({ kind: 'edit', secret: s })
                                      }}
                                    >
                                      {s.inherited_from ? t('Переопределить') : t('Изменить')}
                                    </button>
                                  )}
                                  <button
                                    className="menu-item"
                                    onClick={() => {
                                      setOpenMenu(null)
                                      setModal({ kind: 'history', secret: s })
                                    }}
                                  >
                                    {t('История')}
                                  </button>
                                  {can.write && (
                                    <button
                                      className="menu-item"
                                      onClick={() => {
                                        setOpenMenu(null)
                                        void editMeta(s)
                                      }}
                                    >
                                      {t('Описание и срок действия')}
                                    </button>
                                  )}
                                  {/* Один и тот же токен в двадцати стендах
                                      вносят руками двадцать раз. */}
                                  {can.read && !e2e && siblings.length > 0 && (
                                    <button
                                      className="menu-item"
                                      onClick={() => {
                                        setOpenMenu(null)
                                        setModal({ kind: 'spread', secret: s })
                                      }}
                                    >
                                      {t('Скопировать в другие окружения')}
                                    </button>
                                  )}
                                  {/* Пароль засветился - первый вопрос "где он
                                      еще". Раньше на это отвечали перебором. */}
                                  {can.read && !e2e && (
                                    <button
                                      className="menu-item"
                                      onClick={() => {
                                        setOpenMenu(null)
                                        void findSame(s)
                                      }}
                                    >
                                      {t('Найти совпадения значения')}
                                    </button>
                                  )}
                                  {/* Дальше - про сам ключ, а не про то, что
                                      в нем лежит. */}
                                  <div className="menu-divider" />
                                  {shareView && shareView.kind === 'env' && (
                                    <button
                                      className="menu-item"
                                      onClick={async () => {
                                        setOpenMenu(null)
                                        // Ссылка ведет на окружение с поиском по
                                        // этому ключу. Значение по ней не
                                        // открывается: права спросят так же.
                                        const url = absoluteUrl({ ...shareView, query: s.name })
                                        await copyText(url)
                                        toast(t('Ссылка скопирована'))
                                      }}
                                    >
                                      {t('Скопировать ссылку')}
                                    </button>
                                  )}
                                  {can.write && !s.inherited_from && (
                                    <button
                                      className="menu-item"
                                      onClick={async () => {
                                        setOpenMenu(null)
                                        const answer = await ask({
                                          title: t('Переименовать ключ'),
                                          submit: t('Переименовать'),
                                          fields: [
                                            { name: 'name', label: t('Новое имя'), value: s.name },
                                            {
                                              name: 'path',
                                              label: t('Папка'),
                                              value: s.path,
                                              hint: t('создаётся новая версия с перешифрованием'),
                                            },
                                            // Имя ключа - общий словарь проекта:
                                            // приложение читает одну и ту же
                                            // переменную на всех стендах.
                                            ...(siblings.length > 0
                                              ? [
                                                  {
                                                    name: 'everywhere',
                                                    label: t('во всех окружениях проекта'),
                                                    type: 'check' as const,
                                                    optional: true,
                                                  },
                                                ]
                                              : []),
                                          ],
                                        })
                                        if (!answer || (answer.name === s.name && answer.path === s.path))
                                          return
                                        void act(async () => {
                                          const done = await renameSecret(envId, {
                                            name: s.name,
                                            path: s.path,
                                            new_name: answer.name.trim(),
                                            new_path: answer.path.trim() || '/',
                                            everywhere: Boolean(answer.everywhere),
                                          })
                                          if (done.also_renamed?.length) {
                                            toast(
                                              `${t('переименовано также в')}: ${done.also_renamed.join(', ')}`,
                                            )
                                          }
                                          return done
                                        })
                                      }}
                                    >
                                      {t('Переименовать')}
                                    </button>
                                  )}
                                  {/* Только если есть родитель: без него пункт
                                      всегда заканчивался отказом. */}
                                  {can.write && !s.inherited_from && parentName && (
                                    <button
                                      className="menu-item"
                                      onClick={() =>
                                        void act(() => inheritSecret(envId, s.name, s.path))
                                      }
                                    >
                                      {t('Восстановить наследование')}
                                    </button>
                                  )}
                                  {/* Опасное - отдельно и последним: до него
                                      не дотягиваются случайно, целясь в
                                      "переименовать". */}
                                  {can.delete && <div className="menu-divider" />}
                                  {can.delete && (
                                    <button
                                      className="menu-item menu-item-danger"
                                      onClick={async () => {
                                        setOpenMenu(null)
                                        const yes = await confirm({
                                          title: t('Удалить ключ?'),
                                          text: `${s.name} — ${t('историю это не стирает, удаление обратимо')}`,
                                          submit: t('Удалить'),
                                          danger: true,
                                        })
                                        if (yes) void act(() => deleteSecret(envId, s.name, s.path))
                                      }}
                                    >
                                      {t('Удалить')}
                                    </button>
                                  )}
                                </div>
                              </>
                            )}
                          </div>
                        </div>
                        {/* Подпись ключа - тоже своя строка: в ряду с именем
                            и значением ей достается десяток символов, а её
                            читают целиком или не читают вовсе. */}
                        {s.note && (
                          <div className="key-note-text muted small" title={s.note}>
                            {s.note}
                          </div>
                        )}
                        {/* Замечания к значению: своя строка во всю ширину.
                            В строке ключа им доставалось два десятка символов,
                            и подпись обрывалась на середине мысли. */}
                        {noteFor.get(`${s.path}:${s.name}`) && (
                          <div className="key-notes">
                            {noteFor.get(`${s.path}:${s.name}`)?.map((note) => (
                              <span key={note.code} className="key-note-line">
                                <span
                                  className={`key-note${
                                    note.level === 'bad' ? ' key-note-bad' : ''
                                  }`}
                                >
                                  {t(note.text)}
                                </span>
                                {can.write && (
                                  <button
                                    className="ghost small-btn key-note-ok"
                                    title={t('панель перестанет показывать это замечание')}
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      void accept(note)
                                    }}
                                  >
                                    {t('так и надо')}
                                  </button>
                                )}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })}
            </section>
          ))}
        </div>
      )}

      {modal?.kind === 'new' && (
        <SecretEditor
          secret={null}
          onClose={() => setModal(null)}
          onSaved={() => {
            setModal(null)
            void reload()
          }}
          save={async (body) => {
            await putSecret(envId, { ...body, value: await outgoing(body.value) })
          }}
        />
      )}

      {modal?.kind === 'edit' && (
        <SecretEditor
          secret={modal.secret}
          load={
            can.read
              ? () =>
                  readSecret(envId, modal.secret.name, modal.secret.path).then((r) =>
                    incoming(r.value),
                  )
              : undefined
          }
          onClose={() => setModal(null)}
          onSaved={() => {
            setModal(null)
            void reload()
          }}
          save={async (body) => {
            await putSecret(envId, {
              ...body,
              name: modal.secret.name,
              path: modal.secret.path,
              value: await outgoing(body.value),
            })
          }}
        />
      )}

      {modal?.kind === 'history' && (
        <HistoryModal
          envId={envId}
          secret={modal.secret}
          reveal={incoming}
          onClose={() => setModal(null)}
          onChanged={() => void reload()}
        />
      )}

      {modal?.kind === 'import' && (
        <ImportModal envId={envId} onClose={() => setModal(null)} onDone={() => void reload()} />
      )}

      {modal?.kind === 'spread' && (
        <SpreadModal
          envId={envId}
          secret={modal.secret}
          targets={siblings}
          onClose={() => setModal(null)}
          onDone={() => void reload()}
        />
      )}

      {modal?.kind === 'bulk' && (
        <BulkEditModal
          envId={envId}
          subject={
            shareView && shareView.kind === 'env'
              ? `${shareView.slug} · ${shareView.env}`
              : ''
          }
          canWrite={can.write}
          filename={
            shareView && shareView.kind === 'env'
              ? `${shareView.slug}-${shareView.env}.env`
              : 'sekvyr.env'
          }
          onClose={() => setModal(null)}
          onChanged={() => void reload()}
        />
      )}
    </div>
  )
}


/* Значение в строке: скрыто -> показано -> правится, без ухода со страницы.
 *
 * Поле растет под содержимое: в секретах живут не только пароли, но и конфиги
 * на двадцать строк, и показывать от них первую строку с многоточием значит не
 * показывать ничего.
 *
 * Короткое значение открывается на месте звездочек, и строка не меняется. Под
 * имя, во всю ширину, уходит только то, что в колонку не влезает: многострочное
 * или длиннее её. Решение в одну сторону - ушедшее вниз поле не прыгает обратно,
 * пока строку не закроют.
 */
function ValueCell({
  open,
  canRead,
  canWrite,
  onReveal,
  onWide,
  onDraft,
  onSave,
  onHide,
}: {
  open: Opened | undefined
  canRead: boolean
  canWrite: boolean
  onReveal: () => void
  onWide: () => void
  onDraft: (text: string) => void
  onSave: () => void
  onHide: () => void
}) {
  const { t } = useI18n()
  const field = useRef<HTMLElement | null>(null)
  const wide = Boolean(open?.wide)
  const text = open?.draft

  // До отрисовки: поле, которое не влезло, уходит вниз раньше, чем его увидят.
  useLayoutEffect(() => {
    if (text === undefined || wide) return
    const el = field.current
    if (text.includes('\n') || (el && el.scrollWidth > el.clientWidth + 1)) onWide()
  }, [text, wide, onWide])

  if (!open) {
    if (!canRead) return <span className="muted mono">********</span>
    return (
      <button
        className="value-mask mono"
        onClick={onReveal}
        title={canWrite ? t('показать и править') : t('показать значение')}
      >
        ********
      </button>
    )
  }

  const dirty = open.draft !== open.value
  const lines = open.draft.split('\n').length

  return (
    <div className="value-edit">
      {canWrite ? (
        <textarea
          ref={(el) => {
            field.current = el
          }}
          className="value-input value-inline"
          // Высота строго по содержимому: конфиг на полсотни строк должен быть
          // виден целиком. Прокрутка внутри поля прячет ровно ту строку, ради
          // которой ключ и открывали, а страница листается и так.
          rows={Math.max(lines, 1)}
          value={open.draft}
          autoFocus
          spellCheck={false}
          autoComplete="off"
          wrap="off"
          disabled={open.busy}
          onChange={(e) => onDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              onHide()
              return
            }
            // Enter всегда переводит строку: однострочное значение сплошь и
            // рядом становится многострочным, и терять на этом набранное
            // нельзя. Сохраняет Ctrl+Enter или кнопка.
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
              e.preventDefault()
              onSave()
            }
          }}
        />
      ) : (
        <pre
          ref={(el) => {
            field.current = el
          }}
          className="value-box value-read"
        >
          {open.value}
        </pre>
      )}
      <div className="value-edit-side">
        {canWrite && dirty ? (
          <>
            <button className="small-btn" disabled={open.busy} onClick={onSave}>
              {t('Сохранить')}
            </button>
            <button className="ghost small-btn" onClick={onHide}>
              {t('Отмена')}
            </button>
            {/* Подсказка - только у широкого поля: в строке она отнимала бы
                место у самого значения. */}
            {wide && <span className="muted small nowrap">Ctrl+Enter</span>}
          </>
        ) : (
          <button className="ghost small-btn" onClick={onHide}>
            {t('Скрыть')}
          </button>
        )}
        {open.note && <span className="muted small nowrap">{open.note}</span>}
      </div>
    </div>
  )
}
