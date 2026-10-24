import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ApiError,
  SESSION_GONE,
  getHealth,
  getToken,
  me,
  setToken,
  watchToken,
  type Me,
} from './api'
import { AboutModal } from './AboutModal'
import { AccessPage } from './AccessPage'
import { AuditPage } from './AuditPage'
import { MigratePage } from './MigratePage'
import { AuthProvider, toAuth } from './auth'
import { Hotkeys } from './Hotkeys'
import { LoginPage } from './LoginPage'
import { OpsPage } from './OpsPage'
import { BrandLogo, useBranding } from './BrandLogo'
import { PasswordModal } from './PasswordModal'
import { ProjectPage } from './ProjectPage'
import { Palette } from './Palette'
import { ProjectsPage } from './ProjectsPage'
import { TwoFactorModal } from './TwoFactorModal'
import { ServerPage } from './ServerPage'
import { ServersPage } from './ServersPage'
import { UsersPage } from './UsersPage'
import { VaultPage } from './VaultPage'
import { useDialogs } from './Dialogs'
import { useI18n } from './i18n'
import { useEscape } from './useEscape'
import { setTimeZone } from './time'
import { forgetAllKeys } from './e2e'
import { leaveGuard, setLeaveGuard } from './leave'
import { parseLocation, viewToPath, type View } from './router'

/* Навигация: проекты -> проект -> окружение, все служебное под шестеренкой.
 *
 * Боковое меню ушло намеренно. Оно годится, пока разделов пять и проектов
 * столько же; при сотне проектов работа начинается с поиска нужного, а журнал,
 * учетки и права открывают раз в неделю - им не место в постоянно видимом
 * списке.
 */

const THEME_KEY = 'sekvyr_theme'

// Вторая клавиша перехода после "g". Буквы русские и латинские сразу: панель
// открывают с любой раскладкой, и переключать её ради перехода - издевательство.
// Через сколько минут бездействия закрывать сессию: ключ в хранилище браузера.
const IDLE_KEY = 'sekvyr_idle_minutes'
// Когда человек последний раз что-то делал в любой из вкладок панели. Без
// общей отметки вкладка, забытая в фоне, выходила по бездействию и уносила
// сессию у той, в которой работали: токен у них один.
const ACTIVE_KEY = 'sekvyr_active_at'

const HOTKEYS: Record<string, View['kind']> = {
  p: 'projects',
  з: 'projects',
  v: 'vault',
  м: 'vault',
  a: 'access',
  ф: 'access',
  u: 'users',
  г: 'users',
  s: 'servers',
  ы: 'servers',
  l: 'audit',
  д: 'audit',
  o: 'ops',
  щ: 'ops',
  m: 'migrate',
  ь: 'migrate',
}

// Названия разделов для заголовка вкладки. Ключи русские, как везде в панели, а
// в заголовок попадают переведенными: иначе английский интерфейс открывался бы
// во вкладке с русским именем.
const TITLES: Partial<Record<View['kind'], string>> = {
  projects: 'Проекты',
  vault: 'Сейф',
  access: 'Доступ',
  users: 'Учётные записи',
  servers: 'Серверы',
  audit: 'Журнал',
  ops: 'Обслуживание',
  migrate: 'Перенос',
}

export default function App() {
  const { t, lang, setLang } = useI18n()
  const [user, setUser] = useState<Me | null>(null)
  // Открытый вопрос (защита ухода, подтверждение) при выходе по бездействию и
  // конце сессии закрывается как отмена: иначе он висел над экраном входа, а
  // "Уйти" потом уводило адрес на страницу, куда шли до выхода.
  const { dismiss } = useDialogs()
  const lastUser = useRef<string | null>(null)
  const [loading, setLoading] = useState(true)
  // Панель не ответила при загрузке. Это не конец сессии: токен цел, и экран
  // входа здесь соврал бы. null - отвечает.
  const [unreachable, setUnreachable] = useState<string | null>(null)
  // Состояние страницы живет в адресе: ссылкой на проект или окружение можно
  // поделиться, работают "назад" и "вперед", а обновление страницы не бросает
  // человека на главную.
  const [view, setViewState] = useState<View>(() =>
    parseLocation(window.location.pathname, window.location.search),
  )
  const currentView = useRef(view)
  currentView.current = view
  const setView = useCallback((next: View, replace = false) => {
    const go = () => {
      setViewState(next)
      const path = viewToPath(next)
      if (path === window.location.pathname + window.location.search) return
      // replace - когда панель сама уточнила адрес (выбрала окружение по
      // умолчанию). Такой шаг не должен попадать в историю: кнопка "назад"
      // иначе возвращала бы человека туда же, откуда его только что перенесли.
      if (replace) window.history.replaceState(null, '', path)
      else window.history.pushState(null, '', path)
    }
    const guard = leaveGuard()
    if (!guard) return go()
    // Защиту снимает только сама страница, когда уходит: переход в тот же
    // раздел страницу не пересоздает, и снятая здесь защита больше не
    // вставала, хотя доли оставались на экране.
    void guard().then((ok) => {
      if (ok) go()
    })
  }, [])


  // Переход по разделам с клавиатуры: "g" и буква раздела. Двухклавишный
  // прием вместо Ctrl с буквой - потому что все удобные сочетания с Ctrl уже
  // заняты браузером, а перехватывать их у него нечестно.
  useEffect(() => {
    if (!user) return
    let waiting = 0
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      const typing =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        target?.isContentEditable
      // Палитра - единственное сочетание, которое работает и во время набора:
      // за ней тянутся как раз из середины работы, не отрываясь от клавиатуры.
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setPalette(true)
        return
      }
      if (typing || event.ctrlKey || event.metaKey || event.altKey) return

      // "?" - единственное сочетание, о котором надо догадаться самому,
      // поэтому оно и открывает список всех остальных.
      if (event.key === '?') {
        event.preventDefault()
        setHotkeys(true)
        return
      }
      if (event.key === 'g') {
        waiting = Date.now()
        return
      }
      // Полторы секунды на вторую клавишу: дольше - это уже не сочетание, а
      // случайное совпадение с набором.
      if (!waiting || Date.now() - waiting > 1500) return
      waiting = 0
      const kind = HOTKEYS[event.key.toLowerCase()]
      if (kind) {
        event.preventDefault()
        setView({ kind } as View)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [user, setView])

  // Заголовок вкладки - это адрес для глаз: панель держат открытой в нескольких
  // вкладках сразу, и "Sekvyr" в каждой не помогает найти нужную. Имя панели
  // все же идет первым: по нему вкладку узнают среди чужих.
  useEffect(() => {
    const where =
      view.kind === 'env'
        ? `${view.slug}/${view.env}`
        : view.kind === 'project'
          ? view.slug
          : view.kind === 'server'
            ? view.name
            : t(TITLES[view.kind] ?? '')
    document.title = where ? `Sekvyr · ${where}` : 'Sekvyr'
  }, [view, t])

  useEffect(() => {
    // После согласия уйти "назад" повторяется уже без вопроса.
    let agreed = false
    const onPop = () => {
      const target = parseLocation(window.location.pathname, window.location.search)
      const guard = leaveGuard()
      if (!guard || agreed) {
        agreed = false
        return setViewState(target)
      }
      // "Назад" адрес уже сменил: возвращаем его, пока человек не ответил.
      window.history.pushState(null, '', viewToPath(currentView.current))
      void guard().then((ok) => {
        if (!ok) return
        // Шаг назад, а не новая запись: иначе в истории оставалась лишняя
        // страница сейфа, и следующее "назад" вело на нее снова.
        agreed = true
        window.history.back()
      })
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])
  const [changingPassword, setChangingPassword] = useState(false)
  const [about, setAbout] = useState(false)
  const [hotkeys, setHotkeys] = useState(false)
  const [idleMinutes, setIdleMinutes] = useState(() => {
    const saved = Number(localStorage.getItem(IDLE_KEY) ?? '0')
    return Number.isFinite(saved) && saved > 0 ? saved : 0
  })
  // Палитра перехода: одно поле, в котором ищется вся панель.
  const [palette, setPalette] = useState(false)
  const [twoFactor, setTwoFactor] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  // Escape закрывает меню шапки - так же, как окна.
  useEscape(() => setMenuOpen(false), menuOpen)
  const [light, setLight] = useState(
    () => document.documentElement.getAttribute('data-theme') === 'light',
  )
  // Пока своего выбора нет, тема едет за системной.
  const [followSystem, setFollowSystem] = useState(() => !localStorage.getItem(THEME_KEY))
  const [sealed, setSealed] = useState(false)
  // Свой логотип: нужен и экрану входа, поэтому грузится до входа.
  const [branding, setBranding] = useBranding()

  const load = useCallback(async () => {
    if (!getToken()) {
      setUser(null)
      setLoading(false)
      return
    }
    try {
      const next = await me()
      // Вход другим пользователем в той же вкладке (токен сменили в соседней)
      // не наследует ключи e2e прежнего.
      if (lastUser.current !== next.username) forgetAllKeys()
      lastUser.current = next.username
      setUnreachable(null)
      setUser(next)
    } catch (err) {
      // Токен мог протухнуть, пережить смену пароля или отключение учетки - во
      // всех случаях это "показать вход", а не пустая страница. Отказ любого
      // другого рода - панель лежит или сеть пропала: вход тут не поможет, а
      // токен еще пригодится, когда панель вернется.
      forgetAllKeys()
      setUser(null)
      if (err instanceof ApiError && err.status === 401) {
        setToken(null)
        setUnreachable(null)
      } else {
        setUnreachable(err instanceof Error ? err.message : String(err))
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  // Токен отвергнут посреди работы - снова экран входа. Адрес остается: после
  // входа человек вернется туда, где был.
  useEffect(() => {
    const gone = () => {
      setLeaveGuard(null)
      dismiss()
      forgetAllKeys()
      setUser(null)
    }
    window.addEventListener(SESSION_GONE, gone)
    return () => window.removeEventListener(SESSION_GONE, gone)
  }, [dismiss])

  // Токен общий на все вкладки. Вышли в соседней - здесь тоже вход, и открытые
  // значения с ключами e2e уходят вместе со страницей. Вошли там другим
  // человеком - эта вкладка уже ходит с его токеном, а на экране права и
  // значения прежнего: перезагрузка начинает с чистого листа.
  const signedIn = useRef(false)
  signedIn.current = Boolean(user)
  useEffect(
    () =>
      watchToken((token) => {
        if (!token) {
          setLeaveGuard(null)
          dismiss()
          forgetAllKeys()
          setUser(null)
          return
        }
        if (!signedIn.current) {
          void load()
          return
        }
        const restart = () => {
          forgetAllKeys()
          window.location.reload()
        }
        // Тот же человек вошел заново (сессия кончилась и в соседней вкладке
        // он вошел снова): набранное здесь не выбрасываем.
        me()
          .then((next) => {
            if (next.username !== lastUser.current) restart()
          })
          .catch(restart)
      }),
    [dismiss, load],
  )

  useEffect(() => {
    if (!user) return
    getHealth()
      .then((h) => {
        setSealed(Boolean(h.sealed))
        // Зону задает панель, а не браузер: журнал должен читаться одинаково у
        // всех, кто в него смотрит.
        setTimeZone(h.timezone ?? 'UTC')
      })
      .catch(() => setSealed(false))
  }, [user, view])

  // Панель следит за системной темой, пока человек не выбрал свою: у него в
  // системе вечером включается темная, и панель должна ехать вместе с ней.
  // После своего выбора слушатель снимается - иначе система перебивала бы его.
  useEffect(() => {
    if (!followSystem) return
    const media = window.matchMedia('(prefers-color-scheme: light)')
    const apply = () => {
      setLight(media.matches)
      if (media.matches) document.documentElement.setAttribute('data-theme', 'light')
      else document.documentElement.removeAttribute('data-theme')
    }
    media.addEventListener('change', apply)
    return () => media.removeEventListener('change', apply)
  }, [followSystem])

  function toggleTheme() {
    const next = !light
    setLight(next)
    setFollowSystem(false)
    if (next) {
      document.documentElement.setAttribute('data-theme', 'light')
      localStorage.setItem(THEME_KEY, 'light')
    } else {
      document.documentElement.removeAttribute('data-theme')
      localStorage.setItem(THEME_KEY, 'dark')
    }
  }

  // Через сколько минут бездействия закрывать сессию. 0 - не закрывать; это
  // состояние по умолчанию, потому что на своем компьютере такой выход только
  // мешает.
  // Бездействие считается по всем вкладкам сразу: отметка о последнем
  // действии общая (ACTIVE_KEY), и фоновая вкладка не выходит, пока в соседней
  // работают.
  const logoutRef = useRef(() => {})
  logoutRef.current = logout
  useEffect(() => {
    if (!user || !idleMinutes) return
    let last = Date.now()
    let shared = 0
    const share = () => {
      // Не на каждое движение: запись в хранилище будит все вкладки.
      if (last - shared < 5_000) return
      shared = last
      try {
        localStorage.setItem(ACTIVE_KEY, String(last))
      } catch {
        // Хранилище закрыто: считаем по своей вкладке, как раньше.
      }
    }
    const touch = () => {
      last = Date.now()
      share()
    }
    share()
    const events = ['mousedown', 'keydown', 'wheel', 'touchstart', 'visibilitychange']
    for (const name of events) window.addEventListener(name, touch, { passive: true })
    const timer = window.setInterval(() => {
      let other = 0
      try {
        other = Number(localStorage.getItem(ACTIVE_KEY) ?? 0) || 0
      } catch {
        other = 0
      }
      if (Date.now() - Math.max(last, other) >= idleMinutes * 60_000) logoutRef.current()
    }, 30_000)
    return () => {
      for (const name of events) window.removeEventListener(name, touch)
      window.clearInterval(timer)
    }
  }, [user, idleMinutes])

  // "Выйти" из меню: с несохраненными долями на экране сначала спросить.
  async function askLogout() {
    const guard = leaveGuard()
    if (guard && !(await guard())) return
    logout()
  }

  function logout() {
    // Выход по бездействию и после смены пароля спросить не может: защита
    // ухода снимается, иначе ее вопрос всплывал над экраном входа.
    setLeaveGuard(null)
    dismiss()
    setToken(null)
    // Ключи e2e-проектов живут в памяти вкладки: следующий вошедший в той же
    // вкладке видел бы открытые значения без пароля проекта.
    forgetAllKeys()
    setUser(null)
    setView({ kind: 'projects' })
    setMenuOpen(false)
  }

  // Имя окружения в адресе - человеческое, а работает панель с номером. Ищем
  // номер, когда проект уже загружен: до этого показывать "не найдено" рано.

  if (loading) return null
  if (!user && unreachable !== null) {
    return (
      <div className="login-wrap">
        <div className="card login-card stack">
          <div className="login-brand">
            <BrandLogo where="login" branding={branding} />
          </div>
          <h2>{t('Нет связи с панелью')}</h2>
          <p className="muted small">{unreachable}</p>
          <p className="muted small">
            {t('Сессия при этом не закончилась: когда панель ответит, работа продолжится с того же места.')}
          </p>
          <button
            onClick={() => {
              setLoading(true)
              void load()
            }}
          >
            {t('Повторить')}
          </button>
        </div>
      </div>
    )
  }
  if (!user) return <LoginPage onLogin={load} branding={branding} />

  const auth = toAuth(user)

  const SUB: Partial<Record<View['kind'], View['kind']>> = {
    project: 'projects',
    env: 'projects',
    server: 'servers',
  }

  const menuItem = (kind: View['kind'], title: string, shown: boolean) =>
    shown ? (
      <button
        key={kind}
        className="menu-item"
        onClick={() => {
          setView({ kind } as View)
          setMenuOpen(false)
        }}
      >
        {title}
      </button>
    ) : null

  const tab = (kind: View['kind'], title: string, shown: boolean) => {
    const letter = Object.entries(HOTKEYS).find(([key, target]) => target === kind && key < 'а')
    return shown ? (
      <button
        key={kind}
        className={`tab${(SUB[view.kind] ?? view.kind) === kind ? ' tab-active' : ''}`}
        title={letter ? `g ${letter[0]}` : undefined}
        onClick={() => setView({ kind } as View)}
      >
        {title}
      </button>
    ) : null
  }

  return (
    <AuthProvider value={auth}>
      <div className="shell">
        <header className="header">
          <button
            className="brand-link"
            onClick={() => setView({ kind: 'projects' })}
            title={t('На главную')}
          >
            <BrandLogo where="header" branding={branding} />
          </button>

          {/* Разделы здесь же, рядом со знаком: отдельная строка под шапкой
              стоила высоты, а разделов три. На узком экране строка
              прокручивается вбок, а не переносится. */}
          <nav className="tabs" aria-label={t('Разделы')}>
            {tab('projects', t('Проекты'), true)}
            {tab('access', t('Доступ'), auth.isOwner)}
            {tab('servers', t('Серверы'), auth.isManager)}
          </nav>

          <span className="spacer" />
          {/* На узком экране обе кнопки переезжают в меню: втроем с шестеренкой
              они занимали отдельную строку. */}
          <button className="ghost wide-only" onClick={toggleTheme}>
            {t('Тема')}
          </button>
          <button
            className="ghost wide-only"
            onClick={() => setLang(lang === 'ru' ? 'en' : 'ru')}
          >
            {lang === 'ru' ? 'EN' : 'RU'}
          </button>
          <div className="menu-wrap">
            <button
              className="ghost icon-btn"
              onClick={() => setMenuOpen((v) => !v)}
              aria-label={t('Меню')}
            >
              <span className="menu-gear">⚙</span>
            </button>
            {menuOpen && (
              <>
                <div className="menu-catcher" onClick={() => setMenuOpen(false)} />
                <div className="menu-pop menu-pop-right">
                  <div className="menu-role-badge">
                    {auth.username} · {t(auth.role_title)}
                  </div>
                  <div className="menu-divider narrow-only" />
                  <button
                    className="menu-item narrow-only"
                    onClick={() => {
                      toggleTheme()
                      setMenuOpen(false)
                    }}
                  >
                    {t('Тема')}
                  </button>
                  <button
                    className="menu-item narrow-only"
                    onClick={() => {
                      setLang(lang === 'ru' ? 'en' : 'ru')
                      setMenuOpen(false)
                    }}
                  >
                    {lang === 'ru' ? 'English' : 'Русский'}
                  </button>
                  <div className="menu-divider" />
                  {/* Разделы, куда ходят по поводу: сейф открывают, когда
                      панель заперли, журнал - когда разбираются, перенос -
                      однажды. В строке наверху они были оглавлением, а не
                      дорогой. */}
                  {menuItem('vault', t('Сейф'), auth.isManager)}
                  {menuItem('users', t('Учётные записи'), auth.isManager)}
                  {menuItem('audit', t('Журнал'), auth.isManager)}
                  {menuItem('ops', t('Обслуживание'), auth.isOwner)}
                  {menuItem('migrate', t('Перенос'), auth.isManager)}
                  <div className="menu-divider" />
                  <button
                    className="menu-item"
                    onClick={() => {
                      setChangingPassword(true)
                      setMenuOpen(false)
                    }}
                  >
                    {t('Сменить пароль')}
                  </button>
                  <button
                    className="menu-item"
                    onClick={() => {
                      setTwoFactor(true)
                      setMenuOpen(false)
                    }}
                  >
                    {t('Двухфакторная аутентификация')}
                    {user.totp_enabled && <span className="tag">{t('вкл')}</span>}
                  </button>
                  <button
                    className="menu-item"
                    onClick={() => {
                      setHotkeys(true)
                      setMenuOpen(false)
                    }}
                  >
                    {t('Сочетания клавиш')}
                  </button>
                  {/* Выход по бездействию: настройка браузера, а не панели -
                      она не знает, кто еще ходит мимо этого экрана. */}
                  <button
                    className="menu-item"
                    onClick={() => {
                      const next = idleMinutes === 0 ? 15 : idleMinutes === 15 ? 60 : 0
                      setIdleMinutes(next)
                      localStorage.setItem(IDLE_KEY, String(next))
                    }}
                  >
                    {t('Выход при бездействии')}:{' '}
                    {idleMinutes === 0 ? t('выключен') : `${idleMinutes} ${t('мин')}`}
                  </button>
                  <div className="menu-divider" />
                  {/* "О панели" - внизу, рядом с выходом: туда заходят раз, а не
                      каждый день, и в середине меню она стояла между настройками. */}
                  <button
                    className="menu-item"
                    onClick={() => {
                      setAbout(true)
                      setMenuOpen(false)
                    }}
                  >
                    {t('О панели Sekvyr')}
                  </button>
                  <button className="menu-item menu-item-danger" onClick={() => void askLogout()}>
                    {t('Выйти')}
                  </button>
                </div>
              </>
            )}
          </div>
        </header>

        {/* Строки адреса над страницей нет: заголовок проекта и так называет
            группу, проект и открытое окружение, а плашка с тем же путем над ним
            повторяла его. */}

        {sealed && (
          <div className="banner">
            {t('Панель заперта: чтобы читать значения, введите корневой ключ.')}{' '}
            {auth.isManager && (
              <button className="ghost small-btn" onClick={() => setView({ kind: 'vault' })}>
                {t('Отпереть')}
              </button>
            )}
          </div>
        )}

        <main className="content content-wide">
          {view.kind === 'projects' && (
            <ProjectsPage
              onOpen={(group, slug, env, query) =>
                setView(
                  env
                    ? { kind: 'env', group, slug, env, query }
                    : { kind: 'project', group, slug },
                )
              }
              onOpenServers={() => setView({ kind: 'servers' })}
            />
          )}
          {(view.kind === 'project' || view.kind === 'env') && (
            // Свой экземпляр на каждый проект: пока новый проект грузится,
            // старый список окружений не должен решать, какое открыть. Иначе
            // переход из shop/stage в billing/dev?q=... приводил на billing/prod
            // без поиска.
            <ProjectPage
              key={`${view.group}/${view.slug}`}
              group={view.group}
              slug={view.slug}
              envName={view.kind === 'env' ? view.env : undefined}
              initialQuery={view.kind === 'env' ? view.query : undefined}
              shareView={view.kind === 'env' ? view : undefined}
              onEnvChosen={(name, replace) =>
                setView(
                  { kind: 'env', group: view.group, slug: view.slug, env: name },
                  replace,
                )
              }
              onMoved={(group, slug) =>
                setView(
                  view.kind === 'env'
                    ? { ...view, group, slug }
                    : { kind: 'project', group, slug },
                  true,
                )
              }
              onDeleted={() => setView({ kind: 'projects' })}
              onOpenServer={(m) => setView({ kind: 'server', name: m.name, id: m.id })}
            />
          )}
          {view.kind === 'vault' && auth.isManager && (
            <VaultPage onStatus={(s) => setSealed(s.sealed)} />
          )}
          {view.kind === 'access' && auth.isOwner && (
            <AccessPage
              onOpenServer={(m) => setView({ kind: 'server', name: m.name, id: m.id })}
            />
          )}
          {view.kind === 'users' && auth.isManager && <UsersPage />}
          {view.kind === 'servers' && auth.isManager && (
            <ServersPage onOpen={(m) => setView({ kind: 'server', name: m.name, id: m.id })} />
          )}
          {view.kind === 'server' && auth.isManager && (
            <ServerPage
              key={view.id ?? view.name}
              name={view.name}
              id={view.id}
              onBack={() => setView({ kind: 'servers' })}
              onGo={(next) => setView(next)}
            />
          )}
          {view.kind === 'audit' && auth.isManager && <AuditPage />}
          {view.kind === 'ops' && auth.isOwner && <OpsPage />}
          {view.kind === 'migrate' && auth.isManager && <MigratePage />}
        </main>
      </div>

      {about && (
        <AboutModal
          onClose={() => setAbout(false)}
          branding={branding}
          onBranding={setBranding}
        />
      )}
      {hotkeys && <Hotkeys onClose={() => setHotkeys(false)} />}

      {palette && (
        <Palette onClose={() => setPalette(false)} onGo={(next) => setView(next)} />
      )}

      {twoFactor && (
        <TwoFactorModal
          enabled={user.totp_enabled}
          onClose={() => setTwoFactor(false)}
          onChanged={() => {
            setTwoFactor(false)
            void load()
          }}
        />
      )}

      {changingPassword && (
        <PasswordModal
          onClose={() => setChangingPassword(false)}
          onChanged={() => {
            // пароль сменился - прежний токен уже недействителен, входим заново
            setChangingPassword(false)
            logout()
          }}
        />
      )}
    </AuthProvider>
  )
}
