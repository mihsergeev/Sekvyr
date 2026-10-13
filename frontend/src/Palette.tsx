/* Палитра перехода: одно поле на всю панель.
 *
 * Разделы открываются сочетанием "g" с буквой, но до конкретного стенда все
 * равно два-три движения: раздел, проект, окружение. При двух сотнях проектов
 * это и есть основная трата времени - не поиск ответа, а дорога до места.
 *
 * Поэтому здесь ищется все сразу: проекты, окружения, серверы и ключи. Ключи
 * приходят с сервера (он знает, что человеку видно), остальное фильтруется на
 * месте - списки уже загружены ради самой панели.
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import { listMachines, listProjects, searchSecrets, type SecretHit } from './api'
import { useAuth } from './auth'
import { useI18n } from './i18n'
import { useEscape } from './useEscape'
import type { View } from './router'

type Item = {
  key: string
  /** Что это: окружение, проект, сервер, ключ. */
  kind: 'env' | 'project' | 'server' | 'secret'
  title: string
  hint: string
  view: View
}

// Сколько строк показываем. Больше - это уже список, который читают, а не
// палитра, в которой уточняют запрос еще одной буквой.
const SHOWN = 12

export function Palette({
  onClose,
  onGo,
}: {
  onClose: () => void
  onGo: (view: View) => void
}) {
  const { t } = useI18n()
  const auth = useAuth()
  useEscape(onClose)
  const [query, setQuery] = useState('')
  const [local, setLocal] = useState<Item[]>([])
  const [hits, setHits] = useState<SecretHit[]>([])
  const [active, setActive] = useState(0)
  const list = useRef<HTMLDivElement>(null)

  // Проекты, окружения и серверы - один раз при открытии: палитру держат
  // открытой секунды, и перечитывать это на каждую букву незачем.
  useEffect(() => {
    let alive = true
    void (async () => {
      const out: Item[] = []
      try {
        for (const project of await listProjects()) {
          const where = project.group_slug ? `${project.group_slug}/${project.slug}` : project.slug
          out.push({
            key: `p:${project.id}`,
            kind: 'project',
            title: where,
            hint: t('проект'),
            view: { kind: 'project', group: project.group_slug, slug: project.slug },
          })
          for (const env of project.environments) {
            out.push({
              key: `e:${project.id}:${env}`,
              kind: 'env',
              title: `${where}/${env}`,
              hint: t('окружение'),
              view: { kind: 'env', group: project.group_slug, slug: project.slug, env },
            })
          }
        }
      } catch {
        // Палитра - вспомогательная вещь: если список не пришел, она просто
        // ищет по тому, что есть.
      }
      if (auth.isManager) {
        try {
          for (const machine of await listMachines()) {
            out.push({
              key: `m:${machine.id}`,
              kind: 'server',
              title: machine.name,
              hint: machine.os || t('сервер'),
              view: { kind: 'server', name: machine.name, id: machine.id },
            })
          }
        } catch {
          // см. выше
        }
      }
      if (alive) setLocal(out)
    })()
    return () => {
      alive = false
    }
  }, [auth.isManager, t])

  // Ключи ищет сервер: у него и права, и полный список. Полсекунды тишины,
  // чтобы не слать запрос на каждую букву.
  useEffect(() => {
    const needle = query.trim()
    if (needle.length < 2) {
      setHits([])
      return
    }
    // Ответ на прежний запрос может прийти позже нового или после очистки
    // поля: такой ответ выбрасывается, иначе под пустым полем висели хиты.
    let alive = true
    const id = window.setTimeout(() => {
      void searchSecrets(needle, 10)
        .then((found) => alive && setHits(found))
        .catch(() => alive && setHits([]))
    }, 300)
    return () => {
      alive = false
      window.clearTimeout(id)
    }
  }, [query])

  const items = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const parts = needle ? needle.split(/\s+/) : []
    const found = local.filter((item) =>
      parts.every((part) => item.title.toLowerCase().includes(part)),
    )
    // Окружение - самый частый ответ на вопрос "куда мне", поэтому оно выше
    // проекта, а проект выше сервера.
    const rank = { env: 0, project: 1, server: 2, secret: 3 }
    found.sort((a, b) => rank[a.kind] - rank[b.kind] || a.title.localeCompare(b.title))
    const keys: Item[] = hits.map((hit) => ({
      key: `s:${hit.group_slug}/${hit.project_slug}/${hit.environment}${hit.path}${hit.name}`,
      kind: 'secret',
      title: hit.name,
      hint: `${hit.project_slug}/${hit.environment}${hit.path === '/' ? '' : ` · ${hit.path}`}`,
      view: {
        kind: 'env',
        group: hit.group_slug,
        slug: hit.project_slug,
        env: hit.environment,
        query: hit.name,
      },
    }))
    return [...found.slice(0, SHOWN), ...keys]
  }, [local, hits, query])

  useEffect(() => {
    setActive(0)
  }, [query])

  useEffect(() => {
    const node = list.current?.querySelector<HTMLElement>('[data-active="1"]')
    node?.scrollIntoView?.({ block: 'nearest' })
  }, [active])

  function choose(item: Item | undefined) {
    if (!item) return
    onGo(item.view)
    onClose()
  }

  return (
    <div className="modal-backdrop palette-backdrop" onMouseDown={onClose}>
      <div className="card modal palette" onMouseDown={(e) => e.stopPropagation()}>
        <input
          autoFocus
          className="palette-input"
          value={query}
          placeholder={t('проект, окружение, сервер или ключ')}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') {
              e.preventDefault()
              setActive((n) => Math.min(n + 1, items.length - 1))
            } else if (e.key === 'ArrowUp') {
              e.preventDefault()
              setActive((n) => Math.max(n - 1, 0))
            } else if (e.key === 'Enter') {
              e.preventDefault()
              choose(items[active])
            }
          }}
        />
        <div className="palette-list" ref={list}>
          {items.length === 0 && (
            <div className="pick-empty muted small">
              {query.trim() ? t('ничего не нашлось') : t('начните вводить имя')}
            </div>
          )}
          {items.map((item, index) => (
            <button
              key={item.key}
              type="button"
              data-active={index === active ? '1' : undefined}
              className={`palette-row${index === active ? ' palette-row-on' : ''}`}
              onMouseEnter={() => setActive(index)}
              onMouseDown={(e) => {
                e.preventDefault()
                choose(item)
              }}
            >
              <span className="palette-title mono">{item.title}</span>
              <span className="spacer" />
              <span className="muted small">{item.hint}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
