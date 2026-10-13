/* Адреса страниц.
 *
 * Своя разборка вместо библиотеки роутинга: маршрутов пять, все плоские, а
 * лишняя зависимость в панели, которая хранит чужие секреты, стоит дороже
 * пятидесяти строк здесь.
 *
 * В адресе имена, а не номера: номер ничего не говорит человеку, которому
 * прислали ссылку, и разъезжается между стендами.
 *
 * Проект адресуется парой "группа/имя": `frontend` бывает и у globex, и у
 * initech. У проекта без группы на её месте стоит прочерк - так число кусков
 * адреса всегда одно и то же, и `/p/globex/frontend` нельзя прочитать как
 * "проект globex, окружение frontend".
 */

export const NO_GROUP = '-'

export type View =
  | { kind: 'projects' }
  | { kind: 'project'; group: string; slug: string }
  | { kind: 'env'; group: string; slug: string; env: string; query?: string }
  | { kind: 'vault' }
  | { kind: 'access' }
  | { kind: 'users' }
  | { kind: 'servers' }
  | { kind: 'server'; name: string; id?: number }
  | { kind: 'audit' }
  | { kind: 'ops' }
  | { kind: 'migrate' }

const SERVICE = [
  'vault',
  'access',
  'users',
  'servers',
  'audit',
  'ops',
  'migrate',
] as const

// Битый "%" в адресе (обрезанная ссылка из чата) ронял все приложение:
// decodeURIComponent бросает исключение. Такой кусок берется как есть.
function decode(part: string): string {
  try {
    return decodeURIComponent(part)
  } catch {
    return part
  }
}

export function parseLocation(pathname: string, search = ''): View {
  const parts = pathname.split('/').filter(Boolean).map(decode)
  if (parts.length === 0) return { kind: 'projects' }

  const first = parts[0]
  // Отдельный сервер: /servers/<имя>?id=<номер>. Имя личности в кластере само
  // содержит косую черту (namespace/account), но в адресе она закодирована и
  // потому не разбивает путь на лишние куски. Номер нужен потому, что имя не
  // уникально: переподключенный сервер с тем же hostname дает вторую строку, и
  // по одному имени открывалась бы первая из них.
  if (first === 'servers' && parts[1]) {
    const id = Number(new URLSearchParams(search).get('id'))
    return Number.isInteger(id) && id > 0
      ? { kind: 'server', name: parts[1], id }
      : { kind: 'server', name: parts[1] }
  }
  if ((SERVICE as readonly string[]).includes(first)) {
    return {
      kind: first as
        | 'vault'
        | 'access'
        | 'users'
        | 'servers'
        | 'audit'
        | 'ops'
        | 'migrate',
    }
  }
  if (first === 'p' && parts[1] && parts[2]) {
    const group = parts[1] === NO_GROUP ? '' : parts[1]
    if (parts[3]) {
      const query = new URLSearchParams(search).get('q') ?? undefined
      return { kind: 'env', group, slug: parts[2], env: parts[3], query }
    }
    return { kind: 'project', group, slug: parts[2] }
  }
  // Неизвестный адрес - на главную: битая ссылка не должна показывать пустоту.
  return { kind: 'projects' }
}

function projectPath(group: string, slug: string): string {
  return `/p/${encodeURIComponent(group || NO_GROUP)}/${encodeURIComponent(slug)}`
}

export function viewToPath(view: View): string {
  switch (view.kind) {
    case 'projects':
      return '/'
    case 'project':
      return projectPath(view.group, view.slug)
    case 'server': {
      const base = `/servers/${encodeURIComponent(view.name)}`
      return view.id ? `${base}?id=${view.id}` : base
    }
    case 'env': {
      const base = `${projectPath(view.group, view.slug)}/${encodeURIComponent(view.env)}`
      return view.query ? `${base}?q=${encodeURIComponent(view.query)}` : base
    }
    default:
      return `/${view.kind}`
  }
}

/** Адрес целиком - им делятся с коллегой. */
export function absoluteUrl(view: View): string {
  return `${window.location.origin}${viewToPath(view)}`
}
