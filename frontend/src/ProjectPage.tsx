import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import {
  createEnvironment,
  listEnvironments,
  listProjects,
  type Environment,
  type Project,
} from './api'
import { useAuth } from './auth'
import { useDialogs } from './Dialogs'
import { EnvironmentPage } from './EnvironmentPage'
import { ProjectSettingsModal } from './ProjectSettingsModal'
import { ErrorNote } from './Notes'
import { plural, useI18n } from './i18n'
import { pinned, togglePin } from './pins'
import type { View } from './router'

/* Экран проекта - это сразу ключи выбранного окружения.
 *
 * Отдельная страница со списком окружений выглядела логично, но добавляла
 * лишний шаг: в проект заходят, чтобы посмотреть или поправить значение, а не
 * чтобы полюбоваться списком стендов. Поэтому окружение переключается сверху, а
 * содержимое открыто сразу.
 *
 * Порядок в переключателе не алфавитный: prod, stage и qa нужны чаще, чем
 * tech7, и должны быть под рукой.
 */

const ORDER = ['prod', 'production', 'stage', 'staging', 'uat', 'qa', 'dev']

function rank(name: string): number {
  const index = ORDER.indexOf(name.toLowerCase())
  return index < 0 ? ORDER.length : index
}

/** Переключатель окружений, который умеет не помещаться.
 *
 * Кнопки рисуются все, потом измеряются: те, что вышли за правый край, прячутся
 * под "еще N". Измерение вместо "больше пяти - выпадашка" потому, что `prod` и
 * `tech-base` занимают разную ширину, а окно бывает любым.
 */
// Со скольких спрятанных окружений в списке нужен поиск.
const SEARCH_FROM = 8

function EnvSwitch({
  environments,
  current,
  onChoose,
}: {
  environments: Environment[]
  current: string
  onChoose: (name: string) => void
}) {
  const { t } = useI18n()
  const box = useRef<HTMLDivElement>(null)
  const shadow = useRef<HTMLDivElement>(null)
  const [fits, setFits] = useState(environments.length)
  const [open, setOpen] = useState(false)
  // Поиск внутри "еще N": у проекта бывает десяток стендов, и tech7 ищут по
  // имени, а не глазами по столбцу.
  const [find, setFind] = useState('')

  useLayoutEffect(() => {
    const node = box.current
    if (!node) return

    function measure() {
      const holder = box.current
      const ruler = shadow.current
      if (!holder || !ruler) return
      const items = Array.from(ruler.querySelectorAll<HTMLElement>('.env-switch-item'))
      if (items.length === 0) return

      // Ширину берем у внешней рамки: она занимает свободное место в строке и
      // от числа кнопок не зависит. Сами кнопки меряем в невидимой копии, где
      // они есть все и всегда, - иначе измерение начнет зависеть от своего же
      // результата.
      const room = holder.clientWidth - 8
      let used = 0
      let count = 0
      for (const item of items) {
        const tail = count === environments.length - 1 ? 0 : 76
        if (used + item.offsetWidth + tail > room) break
        used += item.offsetWidth + 4
        count += 1
      }
      setFits(Math.max(count, 1))
    }

    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(node)
    return () => observer.disconnect()
  }, [environments])

  const shown = environments.slice(0, fits)
  const hidden = environments.slice(fits)
  // Выбранное окружение видно всегда: если оно уехало под "еще", меняем его
  // местами с последней видимой кнопкой.
  if (hidden.some((e) => e.name === current) && shown.length > 0) {
    const at = hidden.findIndex((e) => e.name === current)
    const last = shown.length - 1
    const moved = hidden[at]
    hidden[at] = shown[last]
    shown[last] = moved
  }

  const needle = find.trim().toLowerCase()
  const matched = needle
    ? hidden.filter((e) => e.name.toLowerCase().includes(needle))
    : hidden

  return (
    <div className="env-switch-fit" ref={box}>
      {/* Невидимая копия со всеми кнопками: по ней меряем их настоящую ширину.
          Читалкам она не нужна. Обертка режет её по размеру полосы: линейка
          шире экрана, и без обрезки она растягивала бы документ вбок. */}
      <div className="env-switch-ruler-box" aria-hidden>
        <div className="env-switch env-switch-ruler" ref={shadow}>
          {environments.map((e) => (
            <span key={e.id} className="env-switch-item">
              {e.name}
            </span>
          ))}
        </div>
      </div>
      <div className="env-switch">
      {shown.map((e) => (
        <button
          key={e.id}
          type="button"
          className={`env-switch-item${e.name === current ? ' env-switch-active' : ''}${
            e.name === 'prod' ? ' env-switch-prod' : ''
          }`}
          title={e.parent_name ? `${e.name} ← ${e.parent_name}` : e.name}
          onClick={() => onChoose(e.name)}
        >
          {e.name}
        </button>
      ))}
      {hidden.length > 0 && (
        <div className="menu-wrap">
          <button
            type="button"
            className="env-switch-item env-switch-more"
            onClick={() => {
              setFind('')
              setOpen((v) => !v)
            }}
          >
            {t('ещё')} {hidden.length}
          </button>
          {open && (
            <>
              <div className="menu-catcher" onClick={() => setOpen(false)} />
              <div className="menu-pop menu-pop-right env-switch-pop">
                {hidden.length > SEARCH_FROM && (
                  <input
                    className="env-switch-find"
                    autoFocus
                    value={find}
                    placeholder={t('поиск')}
                    onChange={(e) => setFind(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Escape') {
                        e.stopPropagation()
                        setOpen(false)
                        return
                      }
                      if (e.key === 'Enter' && matched[0]) {
                        setOpen(false)
                        onChoose(matched[0].name)
                      }
                    }}
                  />
                )}
                {matched.map((e) => (
                  <button
                    key={e.id}
                    className="menu-item"
                    onClick={() => {
                      setOpen(false)
                      onChoose(e.name)
                    }}
                  >
                    {e.name}
                    {e.parent_name && <span className="muted small"> ← {e.parent_name}</span>}
                  </button>
                ))}
                {matched.length === 0 && (
                  <div className="pick-empty muted small">{t('ничего не нашлось')}</div>
                )}
              </div>
            </>
          )}
        </div>
      )}
      </div>
    </div>
  )
}

export function ProjectPage({
  group,
  slug,
  envName,
  initialQuery,
  onEnvChosen,
  onMoved,
  onDeleted,
  shareView,
  onOpenServer,
}: {
  /** Группа из адреса; пусто - проект без группы. */
  group: string
  slug: string
  /** Окружение из адреса; пусто - выберем сами и поправим адрес. */
  envName?: string
  initialQuery?: string
  onEnvChosen: (name: string, replace: boolean) => void
  /** Проект переехал в другую группу - адрес нужно поправить. */
  onMoved: (group: string, slug: string) => void
  onDeleted: () => void
  shareView?: View
  /** Провалиться в сервер, который забирает окружение. */
  onOpenServer?: (machine: { id: number; name: string }) => void
}) {
  const { t } = useI18n()
  const auth = useAuth()
  const { ask, toast } = useDialogs()
  // Закреплено ли текущее окружение: звезда в шапке и строка на главной.
  const [keep, setKeep] = useState(false)
  const [project, setProject] = useState<Project | null>(null)
  const [envs, setEnvs] = useState<Environment[]>([])
  // Для какого адреса загружены окружения. Пока грузится другой проект,
  // старый список не должен решать, какое окружение открыть.
  const [envsOf, setEnvsOf] = useState('')
  const [settings, setSettings] = useState(false)
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)
  // Поиск переживает смену окружения: у каждого окружения свой экземпляр
  // страницы, и набранное "DB_" пропадало при переходе из stage в prod, где
  // его искали как раз для сравнения.
  const [carried, setCarried] = useState(initialQuery ?? '')
  useEffect(() => {
    // Только новый поиск из адреса: при смене окружения адрес уходит без ?q=,
    // и пустое значение стирало бы набранное.
    if (initialQuery) setCarried(initialQuery)
  }, [initialQuery])
  const moved = useRef<Project | null>(null)

  const reload = useCallback(async () => {
    try {
      const projects = await listProjects()
      let found = projects.find((p) => p.group_slug === group && p.slug === slug) ?? null
      if (!found) {
        // Проект мог переехать в другую группу - тогда старая ссылка ведет в
        // пустоту, хотя проект жив. Находим по имени и правим адрес.
        const sameName = projects.filter((p) => p.slug === slug)
        if (sameName.length === 1) {
          found = sameName[0]
          moved.current = found
        }
      }
      const list = found ? await listEnvironments(found.id) : []
      setProject(found)
      setEnvs(list)
      setEnvsOf(`${group}/${slug}`)
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setEnvsOf(`${group}/${slug}`)
    } finally {
      setLoaded(true)
    }
  }, [group, slug])

  useEffect(() => {
    void reload()
  }, [reload])

  useEffect(() => {
    const target = moved.current
    if (!target) return
    moved.current = null
    onMoved(target.group_slug, target.slug)
  }, [project, onMoved])

  const sorted = useMemo(
    () => [...envs].sort((a, b) => rank(a.name) - rank(b.name) || a.name.localeCompare(b.name)),
    [envs],
  )

  const fresh = envsOf === `${group}/${slug}`
  const current = useMemo(
    () => (fresh ? (sorted.find((e) => e.name === envName) ?? sorted[0] ?? null) : null),
    [fresh, sorted, envName],
  )

  // Адрес всегда указывает на конкретное окружение: ссылку можно скинуть, и она
  // откроет то же, что видит отправитель, а не "что-нибудь первое".
  useEffect(() => {
    if (current && current.name !== envName) onEnvChosen(current.name, true)
  }, [current, envName, onEnvChosen])

  useEffect(() => {
    if (project && current) setKeep(pinned(project.group_slug, project.slug, current.name))
  }, [project, current])

  async function addEnv() {
    if (!project) return
    const answer = await ask({
      title: t('Новое окружение'),
      submit: t('Создать'),
      fields: [
        {
          name: 'name',
          label: t('Имя'),
          placeholder: 'prod',
          hint: t('строчные латинские буквы, цифры и дефис'),
        },
        {
          name: 'parent',
          label: t('Наследовать от'),
          type: 'select',
          optional: true,
          options: [
            { value: '', label: t('ни от какого') },
            ...sorted.map((e) => ({ value: String(e.id), label: e.name })),
          ],
          hint: t('своё значение перекрывает родительское, остальное берётся оттуда'),
        },
        // Копия - не наследование: значения переезжают сюда один раз и дальше
        // живут своей жизнью. Нужно, когда стенд "как прод", но менять его
        // будут отдельно.
        ...(sorted.length > 0 && !project.e2e
          ? [
              {
                name: 'copy',
                label: t('Скопировать значения из'),
                type: 'select' as const,
                optional: true,
                options: [
                  { value: '', label: t('ниоткуда: окружение будет пустым') },
                  ...sorted.map((e) => ({ value: String(e.id), label: e.name })),
                ],
                hint: t('Значения копируются однократно, без связи с исходным окружением'),
              },
            ]
          : []),
      ],
    })
    if (!answer) return
    const parent = envs.find((e) => String(e.id) === answer.parent)
    const source = envs.find((e) => String(e.id) === answer.copy)
    try {
      const created = await createEnvironment(
        project.id,
        answer.name.trim(),
        parent?.id ?? null,
        source?.id ?? null,
      )
      await reload()
      onEnvChosen(created.name, false)
      if (created.copied) {
        toast(`${t('скопировано значений')}: ${created.copied}`)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  if (!loaded || !fresh) return null
  if (!project && error) {
    return (
      <div className="stack">
        <ErrorNote text={error} onClose={() => void reload()} />
      </div>
    )
  }
  if (!project) {
    return (
      <div className="card empty">
        <p className="empty-title">{t('Проекта нет')}</p>
        <p className="muted small">
          {t('Либо его удалили, либо доступ к нему вам не выдавали: панель не показывает даже имена чужих проектов.')}
        </p>
      </div>
    )
  }

  return (
    <div className="stack">
      <ErrorNote text={error} onClose={() => setError('')} />

      <div className="project-head">
        <div className="project-head-title">
          {/* Звезда закрепляет стенд на главной: недавние вытесняются разовым
              заходом, а рабочих стендов у человека три-четыре, и они те же
              изо дня в день. */}
          {current && (
            <button
              className={`ghost icon-btn pin-btn${keep ? ' pin-on' : ''}`}
              title={keep ? t('убрать из закреплённых') : t('закрепить на главной')}
              aria-label={keep ? t('убрать из закреплённых') : t('закрепить на главной')}
              onClick={() => setKeep(togglePin(project.group_slug, project.slug, current.name))}
            >
              {keep ? '★' : '☆'}
            </button>
          )}
          <h2>{project.title || project.slug}</h2>
          {project.group_name && <span className="chip">{project.group_name}</span>}
          <span className="muted small">
            {envs.length} {plural(envs.length, [t('окружение'), t('окружения'), t('окружений')])}
          </span>
          {current?.parent_name && (
            <span className="muted small" title={t('своё значение перекрывает родительское, остальное берётся оттуда')}>
              {current.name} ← {current.parent_name}
            </span>
          )}
        </div>

        <div className="row-actions">
          {/* Окружения кнопками: их обычно два-три, переключаются постоянно, и
              выпадашка требовала двух кликов вместо одного. Когда их больше,
              чем влезает в строку, лишние уходят под "еще" - считаем по
              настоящей ширине, а не по количеству: имена бывают длинные. */}
          {sorted.length > 0 && (
            <EnvSwitch
              environments={sorted}
              current={current?.name ?? ''}
              onChoose={(name) => onEnvChosen(name, false)}
            />
          )}
          {project.manage && (
            <button className="ghost" onClick={addEnv}>
              {t('Новое окружение')}
            </button>
          )}
          {auth.isManager && (
            <button
              className="ghost icon-btn"
              onClick={() => setSettings(true)}
              title={t('Настройки проекта')}
              aria-label={t('Настройки проекта')}
            >
              <span className="menu-gear">⚙</span>
            </button>
          )}
        </div>
      </div>

      {current ? (
        // Свой экземпляр на окружение: сравнение, лента событий, "кому видно"
        // и отмеченные строки прошлого окружения иначе оставались на экране, а
        // "Удалить" по отметкам било по одноименным ключам уже здесь.
        <EnvironmentPage
          key={current.id}
          envId={current.id}
          parentName={current.parent_name}
          initialQuery={carried}
          onFilter={setCarried}
          shareView={shareView}
          projectId={project.id}
          e2e={project.e2e}
          onOpenServer={onOpenServer}
          siblings={envs
            .filter((e) => e.id !== current.id)
            .map((e) => ({ id: e.id, name: e.name }))}
          required={project.required_keys.split(/\s+/).filter(Boolean)}
          staleAfterDays={project.stale_after_days}
        />
      ) : (
        <div className="card empty">
          <p className="empty-title">{t('Окружений пока нет')}</p>
          <p className="muted small">
            {t('Ключи живут в окружениях: заведите prod, а рядом dev или stage — они умеют наследовать значения друг от друга.')}
          </p>
          {project.manage && <button onClick={addEnv}>{t('Новое окружение')}</button>}
        </div>
      )}

      {settings && (
        <ProjectSettingsModal
          project={project}
          onClose={() => setSettings(false)}
          onSaved={() => {
            setSettings(false)
            void reload()
          }}
          onDeleted={onDeleted}
        />
      )}
    </div>
  )
}
