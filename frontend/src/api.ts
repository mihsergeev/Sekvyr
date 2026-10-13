import { tr } from './i18n'
import { serverText } from './serverText'

// Должна совпадать с MIN_PASSWORD_LEN в backend/app/security.py: форма не дает
// ввести короче, бэкенд не принимает короче. Расхождение ловит ops/selfcheck.py -
// иначе интерфейс молча отправлял бы то, что API отвергнет.
export const MIN_PASSWORD_LEN = 12

/** Что не так с новым паролем; пусто - подходит. Длина в байтах - потому что
 *  bcrypt на сервере учитывает первые 72 байта и длиннее не принимает. */
export function passwordProblem(
  value: string,
  t: (text: string, vars?: Record<string, string | number>) => string,
): string {
  if (value.length < MIN_PASSWORD_LEN) return t('Пароль не короче {n} символов', { n: MIN_PASSWORD_LEN })
  if (new TextEncoder().encode(value).length > 72) {
    return t('не длиннее 72 байт: это 72 латинские буквы или 36 русских')
  }
  return ''
}

const TOKEN_KEY = 'sekvyr_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token)
  } else {
    localStorage.removeItem(TOKEN_KEY)
  }
}

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

// Ошибку показываем словами. FastAPI отдает `detail` строкой там, где ошибку
// сформулировали мы, и СПИСКОМ служебных объектов там, где не прошла проверка
// схемы. Второй случай раньше превращался в "Ошибка HTTP 422" - человек видел
// номер вместо ответа на вопрос, что он ввел не так.
function errorText(body: unknown, status: number): string {
  const detail = (body as { detail?: unknown } | null)?.detail
  // Сервер отвечает по-русски, английский интерфейс переводит у себя.
  if (typeof detail === 'string') return serverText(detail)
  if (Array.isArray(detail) && detail.length) {
    const first = detail[0] as { msg?: string; loc?: unknown[] }
    const field = Array.isArray(first.loc) ? first.loc[first.loc.length - 1] : ''
    if (first.msg) return field ? `${field}: ${first.msg}` : first.msg
  }
  return tr('Ошибка HTTP {code}', { code: status })
}

/* Сессия кончилась посреди работы: токен истек, пароль сменили или включили
 * второй фактор в другой вкладке, учетку отключили. Раньше каждая страница
 * показывала свою ошибку ("Недействительный или отсутствующий токен", а
 * страница проекта и вовсе "Проекта нет"), и выйти можно было только руками.
 * Теперь приложение слышит событие и показывает вход, не теряя адреса. */
export const SESSION_GONE = 'sekvyr:session-gone'

function sessionGone(status: number, sent: string | null) {
  // Только для запроса, ушедшего с токеном, и только если токен с тех пор не
  // сменился: ответ на старый запрос не должен выкидывать после нового входа.
  if (status !== 401 || !sent || getToken() !== sent) return
  setToken(null)
  window.dispatchEvent(new Event(SESSION_GONE))
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  }
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(path, { ...options, headers })
  if (res.status === 204) return undefined as T

  const body = await res.json().catch(() => null)
  if (!res.ok) {
    sessionGone(res.status, token)
    throw new ApiError(errorText(body, res.status), res.status)
  }
  return body as T
}

// --- система ---

export type Health = {
  status: string
  version: string
  db?: string
  sealed?: boolean
  /** Зона, в которой панель показывает время. */
  timezone?: string
}

// Версию спрашиваем у бэкенда, а не пишем в верстке: при частичном обновлении
// (фронт обновили, бэкенд забыли) видно именно то, что интересно.
export const getHealth = () => api<Health>('/api/health')

// --- свой логотип ---

export type Branding = {
  logo: boolean
  /** Подпись на экране входа. */
  title: string
  /** Оформление: подстроить цвета под тему, всегда на плашке или как есть. */
  plate: 'auto' | 'always' | 'never'
  /** Загружена своя версия логотипа для темного фона. */
  dark_logo: boolean
  version: number
}

export const getBranding = () => api<Branding>('/api/branding')

/** Адрес картинки. Версия в адресе меняется с каждой правкой - кэш не мешает. */
export const brandingUrl = (version: number, dark = false) =>
  `/api/branding/${dark ? 'logo-dark' : 'logo'}?v=${version}`

export const saveBranding = (body: {
  data: string
  dark: string
  dark_remove: boolean
  plate: Branding['plate']
  title: string
}) => api<Branding>('/api/branding/save', { method: 'POST', body: JSON.stringify(body) })

export const resetBranding = () => api<Branding>('/api/branding/reset', { method: 'POST' })

/** Версия агента, которую панель раздает нодам. Пусто - версия не подписана. */
export const agentLatest = () =>
  api<{ version: string }>('/api/v1/machine/agent/manifest')
    .then((m) => m.version)
    .catch(() => '')

// --- вход и своя учетка ---

export type Role = 'owner' | 'maintainer' | 'developer' | 'viewer'

export type Me = {
  username: string
  role: Role
  level: number
  role_title: string
  totp_enabled: boolean
}

export const me = () => api<Me>('/api/auth/me')

export const login = (username: string, password: string, otp = '') =>
  api<{ access_token: string }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password, otp }),
  })

export const changeOwnPassword = (current_password: string, new_password: string) =>
  api<void>('/api/auth/password', {
    method: 'POST',
    body: JSON.stringify({ current_password, new_password }),
  })

// --- учетные записи ---

export type PanelUser = {
  id: number
  username: string
  role: Role
  role_title: string
  disabled: boolean
  totp_enabled: boolean
  /** Откуда пускать: адреса и подсети через пробел. Пусто - откуда угодно. */
  allow_ips: string
  created_at: string
}

export const listUsers = () => api<PanelUser[]>('/api/users')

export const createUser = (username: string, password: string, role: Role) =>
  api<PanelUser>('/api/users', {
    method: 'POST',
    body: JSON.stringify({ username, password, role }),
  })

export const updateUser = (
  id: number,
  body: { role?: Role; disabled?: boolean; allow_ips?: string },
) =>
  api<PanelUser>(`/api/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) })

export const resetUserPassword = (id: number, new_password: string) =>
  api<void>(`/api/users/${id}/password`, {
    method: 'POST',
    body: JSON.stringify({ new_password }),
  })

// --- журнал ---

export type AuditEntry = {
  id: number
  ts: string
  actor: string
  action: string
  target: string
  detail: string
  ip: string
}

/** Где лежит ключ с таким именем. Значений поиск не отдает - только места. */
export type SecretHit = {
  group_slug: string
  project_slug: string
  project_title: string
  environment: string
  path: string
  name: string
}

export const searchSecrets = (q: string, limit = 30) =>
  api<SecretHit[]>(`/api/search?q=${encodeURIComponent(q)}&limit=${limit}`)

/** Замечание к значению: панель отдает только его, само значение остается внутри. */
export type SecretNote = {
  path: string
  name: string
  /** Машинное имя проверки: по нему замечание принимают. */
  code: string
  level: 'bad' | 'warn'
  text: string
}

export const lintEnv = (envId: number) =>
  api<SecretNote[]>(`/api/environments/${envId}/lint`)

/** Ключ, которого в этом окружении нет, а в соседних есть. */
export type MissingKey = {
  path: string
  name: string
  present_in: string[]
}

export const missingKeys = (envId: number) =>
  api<MissingKey[]>(`/api/environments/${envId}/missing`)

/** Чем окружение отличается от соседнего. Значения не отдаются: панель
 *  сравнивает их у себя и сообщает только состояние. */
export type DiffRow = {
  path: string
  name: string
  /** here - только здесь, there - только там, differs - значения разные,
   *  unknown - сравнить нечем (панель заперта, нет права читать, e2e). */
  state: 'here' | 'there' | 'differs' | 'unknown'
}

export type EnvDiff = { other: string; rows: DiffRow[]; same: number }

export const compareEnvs = (envId: number, other: number) =>
  api<EnvDiff>(`/api/environments/${envId}/diff?other=${other}`)

/** Итог раскладки ключа по стендам: по строке на окружение. */
export type SpreadResult = {
  environment: string
  /** written - записано, pending - ждет подтверждения, denied - нет права,
   *  same - там уже такое же значение. */
  state: 'written' | 'pending' | 'denied' | 'same'
}

/** Ключи, которых за столько-то дней никто не открывал. */
export type IdleRow = { path: string; name: string; updated_at: string }

export type IdleKeys = { rows: IdleRow[]; log_since: string; days: number }

/** Событие окружения: то же, что в журнале, но про это место. */
export type EnvEvent = {
  at: string
  actor: string
  action: string
  /** Имя ключа, если событие про ключ. Пусто - про окружение целиком. */
  key: string
  detail: string
}

/** Где еще лежит такое же значение. Самого значения ответ не содержит. */
export type SameRow = {
  project: string
  environment: string
  path: string
  name: string
}

export const sameValue = (envId: number, name: string, path: string) =>
  api<SameRow[]>(
    `/api/environments/${envId}/same?name=${encodeURIComponent(name)}&path=${encodeURIComponent(path)}`,
  )

/** Кому видно окружение: люди, группы и машины с их правами. */
export type WhoRow = {
  subject: string
  kind: string
  actions: string[]
  effect: string
  until: string
  /** Право выдано на весь проект, а не на этот стенд. */
  whole_project: boolean
}

export const whoSees = (envId: number) => api<WhoRow[]>(`/api/environments/${envId}/who`)

export const envEvents = (envId: number, limit = 20) =>
  api<EnvEvent[]>(`/api/environments/${envId}/events?limit=${limit}`)

export const idleSecrets = (envId: number, days = 365) =>
  api<IdleKeys>(`/api/environments/${envId}/idle?days=${days}`)

export const spreadSecret = (
  envId: number,
  name: string,
  path: string,
  targets: number[],
) =>
  api<{ rows: SpreadResult[] }>(`/api/environments/${envId}/spread`, {
    method: 'POST',
    body: JSON.stringify({ name, path, targets }),
  }).then((r) => r.rows)

/** Принятое замечание: панель про него молчит, пока его не вернут. */
export type MutedNote = {
  path: string
  name: string
  code: string
  text: string
  muted_by: string
}

export const listMutes = (envId: number) =>
  api<MutedNote[]>(`/api/environments/${envId}/lint/mutes`)

export const unmuteNote = (envId: number, body: { name: string; path: string; code: string }) =>
  api<void>(
    `/api/environments/${envId}/lint/mute?${q({
      name: body.name,
      path: body.path,
      code: body.code,
    })}`,
    { method: 'DELETE' },
  )

/** Взять ключ из соседнего окружения: значение копируется сюда новой версией. */
export const copyFrom = (
  envId: number,
  body: { source: string; name: string; path: string },
) =>
  api<SecretRow>(`/api/environments/${envId}/copy-from`, {
    method: 'POST',
    body: JSON.stringify(body),
  })

/** "Здесь так и надо": панель перестает показывать это замечание. */
export const muteNote = (envId: number, body: { name: string; path: string; code: string }) =>
  api<void>(`/api/environments/${envId}/lint/mute`, {
    method: 'POST',
    body: JSON.stringify(body),
  })

export const listAudit = (
  options: {
    limit?: number
    offset?: number
    /** Что ищем: строка и коды действий, чьи названия под нее подходят. */
    q?: string
    queryActions?: string[]
    /** Чем сужаем: тип события и период. Складывается с поиском через И. */
    onlyActions?: string[]
    days?: number
  } = {},
) => {
  // Поиск считает сервер: страница видит сто последних записей, а спрашивают у
  // журнала про то, что случилось месяц назад.
  const query = new URLSearchParams({
    limit: String(options.limit ?? 100),
    offset: String(options.offset ?? 0),
  })
  if (options.q) query.set('q', options.q)
  if (options.days) query.set('days', String(options.days))
  for (const action of options.queryActions ?? []) query.append('q_action', action)
  for (const action of options.onlyActions ?? []) query.append('action', action)
  return api<{ total: number; entries: AuditEntry[] }>(`/api/audit?${query.toString()}`)
}

export const verifyAudit = () =>
  api<{ ok: boolean; broken_id: number | null; breaks: number }>('/api/audit/verify')

// --- корневой ключ (сейф) ---

export type VaultStatus = {
  initialized: boolean
  sealed: boolean
  mode: string
  shares: number
  threshold: number
  pending_shares: number
  root_generation: number
  auto_unseal_intent: boolean
  root_key_configured: boolean
  key_file_path: string
  key_file_present: boolean
}

export const vaultStatus = () => api<VaultStatus>('/api/vault/status')

export type VaultInit = {
  mode: string
  shares: string[]
  root_key: string
  warning: string
}

export const vaultInit = (
  mode: string,
  shares: number,
  threshold: number,
  autoUnseal = false,
) =>
  api<VaultInit>('/api/vault/init', {
    method: 'POST',
    body: JSON.stringify({ mode, shares, threshold, auto_unseal: autoUnseal }),
  })

export type UnsealResult = {
  sealed: boolean
  pending_shares: number
  threshold: number
  detail: string
}

// Доля и корневой ключ уходят в ТЕЛЕ запроса, не в адресе: адреса попадают в
// логи прокси и в историю браузера, а это ровно тот материал, ради которого все
// остальное и затевалось.
export const vaultUnseal = (body: { share?: string; root_key?: string }) =>
  api<UnsealResult>('/api/vault/unseal', { method: 'POST', body: JSON.stringify(body) })

export const vaultRememberKey = () =>
  api<{ path: string; present: boolean; detail: string }>('/api/vault/remember-key', {
    method: 'POST',
  })

export const vaultForgetKey = () =>
  api<{ path: string; present: boolean; detail: string }>('/api/vault/forget-key', {
    method: 'POST',
  })

export const vaultSeal = () => api<VaultStatus>('/api/vault/seal', { method: 'POST' })

export type RootRotation = {
  root_generation: number
  rewrapped_keys: number
  shares: string[]
  root_key: string
}

export const vaultRotateRoot = () =>
  api<RootRotation>('/api/vault/rotate-root', { method: 'POST' })

// --- проекты и окружения ---

export type Project = {
  id: number
  slug: string
  title: string
  e2e: boolean
  environments: string[]
  approval_min_level: number
  /** Ключи, без которых приложение не поднимется: имена через пробел. */
  required_keys: string
  /** С какого возраста значение считается давним. */
  stale_after_days: number
  group_name: string
  // Группа куском адреса: имя проекта уникально внутри нее
  group_slug: string
  /** Проект закрыт: в списке он лежит в "Архиве", а не среди живых. */
  archived: boolean
  /** Когда последний раз правили ключ. Пусто - правок не было вовсе. */
  last_change_at: string
  // счетчики для списка: без них сотня проектов - сотня одинаковых строк
  env_count: number
  secret_count: number
  pending_count: number
  /** Можно ли заводить окружения: владелец или право на проект целиком. */
  manage: boolean
}

export const listProjects = () => api<Project[]>('/api/projects')

export const createProject = (
  slug: string,
  title: string,
  group_name = '',
  environments: string[] = [],
) =>
  api<Project>('/api/projects', {
    method: 'POST',
    body: JSON.stringify({ slug, title, group_name, environments }),
  })

export type Environment = {
  id: number
  project_id: number
  name: string
  title: string
  key_generation: number
  parent_id: number | null
  parent_name: string
  // сколько ключей окружение отдает всего и сколько задано в нем самом
  secret_count: number
  own_count: number
}

export const listEnvironments = (projectId: number) =>
  api<Environment[]>(`/api/projects/${projectId}/environments`)

// Создание окружения умеет копировать значения: `copy_from` - id стенда, с
// которого снимают копию. Не то же, что родитель: копия живет своей жизнью.
export const createEnvironment = (
  projectId: number,
  name: string,
  parent_id: number | null = null,
  copy_from: number | null = null,
) =>
  api<Environment & { copied?: number }>(`/api/projects/${projectId}/environments`, {
    method: 'POST',
    body: JSON.stringify({ name, parent_id, copy_from }),
  })

export const updateEnvironment = (
  envId: number,
  body: { title?: string; parent_id?: number | null },
) => api<Environment>(`/api/environments/${envId}`, { method: 'PATCH', body: JSON.stringify(body) })

// --- ключи ---

export type SecretRow = {
  name: string
  path: string
  version: number
  updated_by: string
  /** Когда значение меняли последний раз. Пусто у ключа без версий. */
  updated_at: string
  /** Многострочное значение: конфиг или ключ, а не пароль в одну строку. */
  multiline: boolean
  /** Зачем ключ нужен: постоянная подпись, её видно в списке. */
  note: string
  /** К какой дате значение надо заменить. Пусто - срока нет. */
  expires_at: string
  // по ключу есть правка, ожидающая подтверждения
  pending?: boolean
  // имя окружения, откуда пришло значение; пусто - задано здесь
  inherited_from?: string
  /** Окружения, где ключ переименовали заодно. Приходит только в ответе на
   *  переименование. */
  also_renamed?: string[]
}

export type SecretValue = SecretRow & { value: string }

export const listSecrets = (envId: number) =>
  api<SecretRow[]>(`/api/environments/${envId}/secrets`)

const q = (params: Record<string, string | number>) =>
  new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)])).toString()

export const readSecret = (envId: number, name: string, path: string) =>
  api<SecretValue>(`/api/environments/${envId}/secret?${q({ name, path })}`)

export const putSecret = (
  envId: number,
  body: { name: string; path: string; value: string; comment?: string },
) =>
  api<SecretRow>(`/api/environments/${envId}/secrets`, {
    method: 'PUT',
    body: JSON.stringify(body),
  })

export const deleteSecret = (envId: number, name: string, path: string) =>
  api<void>(`/api/environments/${envId}/secret?${q({ name, path })}`, { method: 'DELETE' })

export const setSecretMeta = (
  envId: number,
  name: string,
  path: string,
  note: string,
  expires_at: string,
) =>
  api<SecretRow>(`/api/environments/${envId}/secret/meta`, {
    method: 'POST',
    body: JSON.stringify({ name, path, note, expires_at }),
  })

export const renameSecret = (
  envId: number,
  body: {
    name: string
    path: string
    new_name: string
    new_path: string
    /** Переименовать и в остальных окружениях проекта. */
    everywhere?: boolean
  },
) =>
  api<SecretRow>(`/api/environments/${envId}/secret/rename`, {
    method: 'POST',
    body: JSON.stringify(body),
  })

// --- версии ---

export type SecretVersion = {
  version: number
  name: string
  path: string
  deleted: boolean
  author: string
  comment: string
  created_at: string
  current: boolean
  status?: string
  inherits?: boolean
  /** Значение лежало в папке, где читать нельзя: не раскрыть и не вернуть. */
  closed?: boolean
}

export const secretHistory = (envId: number, name: string, path: string) =>
  api<SecretVersion[]>(`/api/environments/${envId}/secret/history?${q({ name, path })}`)

export const readSecretVersion = (envId: number, name: string, path: string, version: number) =>
  api<SecretValue>(`/api/environments/${envId}/secret/version?${q({ name, path, version })}`)

export const rollbackSecret = (envId: number, name: string, path: string, version: number) =>
  api<SecretRow>(`/api/environments/${envId}/secret/rollback`, {
    method: 'POST',
    body: JSON.stringify({ name, path, version }),
  })

// --- обмен .env ---

export const exportEnv = (envId: number) =>
  api<{ text: string }>(`/api/environments/${envId}/export`)

export type SecretValueRow = {
  name: string
  path: string
  version: number
  value: string
  inherited_from?: string
}

/** Все значения окружения разом - для окна, где их правят списком. */
export const readAllValues = (envId: number) =>
  api<SecretValueRow[]>(`/api/environments/${envId}/values`)

export const importEnv = (envId: number, text: string, path: string, overwrite: boolean) =>
  api<{ created: number; updated: number; skipped: string[] }>(
    `/api/environments/${envId}/import`,
    { method: 'POST', body: JSON.stringify({ text, path, overwrite }) },
  )

// --- ключ окружения ---

export const rotateEnvKey = (envId: number) =>
  api<{ key_generation: number; reencrypted_versions: number }>(
    `/api/environments/${envId}/rotate-key`,
    { method: 'POST' },
  )

// --- второй фактор ---

export const totpStart = () =>
  api<{ secret: string; otpauth_url: string }>('/api/auth/2fa/start', { method: 'POST' })

// Оба ответа несут новый токен: прежние сессии после включения и выключения
// фактора закрываются, а эта продолжается с ним.
export const totpEnable = (code: string, password: string) =>
  api<{ access_token: string }>('/api/auth/2fa/enable', {
    method: 'POST',
    body: JSON.stringify({ code, password }),
  })

export const totpDisable = (password: string, code: string) =>
  api<{ access_token: string }>('/api/auth/2fa/disable', {
    method: 'POST',
    body: JSON.stringify({ password, code }),
  })

// --- права ---

export type Permissions = {
  list: boolean
  read: boolean
  write: boolean
  delete: boolean
  rotate: boolean
  approve: boolean
}

export const myPermissions = (envId: number, path = '/') =>
  api<Permissions>(
    `/api/environments/${envId}/permissions${path === '/' ? '' : `?path=${encodeURIComponent(path)}`}`,
  )

export type PolicyRow = {
  id: number
  subject_type: string
  subject_id: number
  subject_name: string
  project_id: number | null
  project_slug: string
  environment_id: number | null
  environment_name: string
  path_prefix: string
  actions: string[]
  effect: string
  expires_at: string
  require_2fa: boolean
  created_by: string
  expired: boolean
}

export const listPolicies = () => api<PolicyRow[]>('/api/policies')

export const createPolicy = (body: {
  subject_type: string
  subject_id: number
  project_id?: number | null
  environment_id?: number | null
  path_prefix: string
  actions: string[]
  effect: string
  expires_at?: string
  require_2fa?: boolean
}) => api<PolicyRow>('/api/policies', { method: 'POST', body: JSON.stringify(body) })

export const deletePolicy = (id: number) =>
  api<void>(`/api/policies/${id}`, { method: 'DELETE' })

export type GroupRow = { id: number; name: string; members: string[] }

export const listGroups = () => api<GroupRow[]>('/api/groups')
export const createGroup = (name: string) =>
  api<GroupRow>('/api/groups', { method: 'POST', body: JSON.stringify({ name }) })
export const deleteGroup = (id: number) => api<void>(`/api/groups/${id}`, { method: 'DELETE' })
export const addGroupMember = (groupId: number, userId: number) =>
  api<void>(`/api/groups/${groupId}/members`, {
    method: 'POST',
    body: JSON.stringify({ user_id: userId }),
  })
export const removeGroupMember = (groupId: number, userId: number) =>
  api<void>(`/api/groups/${groupId}/members/${userId}`, { method: 'DELETE' })

// --- согласование ---

export type PendingRow = {
  name: string
  path: string
  version: number
  author: string
  comment: string
  created_at: string
  deleted: boolean
}

export const listPending = (envId: number) =>
  api<PendingRow[]>(`/api/environments/${envId}/pending`)

export const approveSecret = (envId: number, name: string, path: string, version: number, note = '') =>
  api<SecretRow>(`/api/environments/${envId}/secret/approve`, {
    method: 'POST',
    body: JSON.stringify({ name, path, version, note }),
  })

export const rejectSecret = (envId: number, name: string, path: string, version: number, note: string) =>
  api<void>(`/api/environments/${envId}/secret/reject`, {
    method: 'POST',
    body: JSON.stringify({ name, path, version, note }),
  })

export const updateProject = (
  id: number,
  body: {
    title?: string
    approval_min_level?: number
    group_name?: string
    required_keys?: string
    stale_after_days?: number
    archived?: boolean
  },
) => api<Project>(`/api/projects/${id}`, { method: 'PATCH', body: JSON.stringify(body) })

/** Все окружения проекта одним файлом. Пропущенные названы отдельно. */
export const exportProject = (id: number) =>
  api<{ text: string; skipped: string[] }>(`/api/projects/${id}/export`)

export const deleteProject = (id: number, confirm: string) =>
  api<void>(`/api/projects/${id}?confirm=${encodeURIComponent(confirm)}`, {
    method: 'DELETE',
  })

export const inheritSecret = (envId: number, name: string, path: string) =>
  api<SecretRow>(`/api/environments/${envId}/secret/inherit`, {
    method: 'POST',
    body: JSON.stringify({ name, path }),
  })

// --- машины ---

/** Приложение на сервере: что агент забирает и в какой файл кладет. */
export type MachineApp = {
  environment: string
  path: string
  applied: string
  last_seen_at: string
}

export type Machine = {
  id: number
  name: string
  client_id: string
  /** Заполнено у личности за подом: секрета у нее нет вовсе. */
  cluster: string
  k8s_namespace: string
  k8s_service_account: string
  description: string
  allow_ips: string
  expires_at: string
  disabled: boolean
  agent_version: string
  applied: string
  last_seen_at: string
  /** Адрес, с которого пришел агент: панель видит его сама. */
  last_ip: string
  /** Страна по внешнему адресу - считает бэкенд по офлайн-таблице. */
  country: string
  /** Что рассказал о себе сам сервер: система и адрес во внутренней сети. */
  os: string
  local_ip: string
  created_by: string
  environments: string[]
  /** Что сервер забирает на самом деле: об этом отчитывается сам агент.
   *  `environments` - выданные права, это разные вещи. */
  apps: MachineApp[]
}

/** Секрет приходит только здесь: в базе от него остается один хеш. */
export type MachineWithSecret = Machine & { client_secret: string }

export const listMachines = () => api<Machine[]>('/api/machines')

export const createMachine = (body: {
  name: string
  description?: string
  allow_ips?: string
  expires_at?: string
  cluster_id?: number | null
  k8s_namespace?: string
  k8s_service_account?: string
}) =>
  api<MachineWithSecret>('/api/machines', { method: 'POST', body: JSON.stringify(body) })

export const updateMachine = (
  id: number,
  body: Partial<{
    name: string
    description: string
    allow_ips: string
    expires_at: string
    disabled: boolean
  }>,
) => api<Machine>(`/api/machines/${id}`, { method: 'PATCH', body: JSON.stringify(body) })

export const rotateMachineSecret = (id: number) =>
  api<MachineWithSecret>(`/api/machines/${id}/secret`, { method: 'POST' })

export const deleteMachine = (id: number, confirm: string) =>
  api<void>(`/api/machines/${id}?confirm=${encodeURIComponent(confirm)}`, { method: 'DELETE' })

export type EnrollTicket = {
  token: string
  expires_at: string
  environment: string
  /** Готовая команда для ноды - её копируют целиком. */
  command: string
  /** Команда для сервера, который уже подключен: ставит агента этому
   *  приложению и перезапускает его после изменения значений. */
  app_command: string
}

/** Выдать машине окружение и получить готовую команду для этого приложения. */
export const attachEnvironment = (machineId: number, environmentId: number) =>
  api<{ environment: string; command: string; granted: boolean; expires_at: string }>(
    `/api/machines/${machineId}/attach`,
    { method: 'POST', body: JSON.stringify({ environment_id: environmentId }) },
  )

export const createEnrollToken = (body: {
  environment_id: number | null
  allow_ips?: string
  minutes?: number
  /** язык установщика и агента - язык этого интерфейса */
  lang?: string
}) =>
  api<EnrollTicket>('/api/machines/enroll-token', {
    method: 'POST',
    body: JSON.stringify(body),
  })

// --- кластеры ---

export type Cluster = {
  id: number
  name: string
  issuer: string
  audience: string
  disabled: boolean
  identities: number
}

export const listClusters = () => api<Cluster[]>('/api/machines/clusters')

export const createCluster = (body: {
  name: string
  issuer: string
  audience: string
  jwks: string
}) =>
  api<Cluster>('/api/machines/clusters', { method: 'POST', body: JSON.stringify(body) })

export const updateCluster = (
  id: number,
  body: { issuer: string; audience: string; jwks: string },
) =>
  api<Cluster>(`/api/machines/clusters/${id}`, { method: 'PATCH', body: JSON.stringify(body) })

export const deleteCluster = (id: number, confirm: string) =>
  api<void>(`/api/machines/clusters/${id}?confirm=${encodeURIComponent(confirm)}`, {
    method: 'DELETE',
  })

// --- обслуживание: оповещения, бэкап, аварийный архив ---

export type AlertsConfig = {
  telegram_token: string
  telegram_chat: string
  telegram_api: string
  webhook: string
  audit_webhook: string
  enabled: boolean
  /** Поля, заданные в .env: панель их показывает, но стереть из интерфейса нельзя. */
  from_env: string[]
}

export const getAlerts = () => api<AlertsConfig>('/api/ops/alerts')

/** Пустое поле оставляет прежнее значение, "-" очищает канал. */
export const saveAlerts = (body: Partial<Record<keyof AlertsConfig, string>>) =>
  api<AlertsConfig>('/api/ops/alerts', { method: 'PUT', body: JSON.stringify(body) })

export const testAlerts = () =>
  api<{ sent: boolean; errors: string[] }>('/api/ops/alerts/test', { method: 'POST' })

export type BackupState = {
  configured: boolean
  at: string
  ok: boolean
  file: string
  size: number
  detail: string
  age_hours: number
  stale: boolean
}

export const getBackupState = () => api<BackupState>('/api/ops/backup')

/** Аварийный архив приходит файлом, а не JSON: забираем его отдельным запросом. */
export async function buildEmergencyArchive(body: {
  password: string
  login_password: string
  otp?: string
  note?: string
}): Promise<Blob> {
  const token = getToken()
  const res = await fetch('/api/ops/emergency', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const parsed = await res.json().catch(() => null)
    sessionGone(res.status, token)
    throw new ApiError(errorText(parsed, res.status), res.status)
  }
  return res.blob()
}

// --- все окружения одним списком ---

export type EnvBrief = {
  id: number
  name: string
  project_slug: string
  group_slug: string
  title: string
}

export const listAllEnvironments = () => api<EnvBrief[]>('/api/environments')

// --- перенос из другого хранилища ---

export type MigrateSource = {
  source: 'infisical' | 'vault'
  url: string
  client_id?: string
  client_secret?: string
  workspace_id?: string
  environment?: string
  secret_path?: string
  token?: string
  mount?: string
  path?: string
}

export type MigrateRow = { path: string; name: string; action: string; size: number }

export type MigratePreview = {
  total: number
  create: number
  update: number
  same: number
  note: string
  rows: MigrateRow[]
}

export const previewMigration = (body: MigrateSource & { environment_id: number; target_path?: string }) =>
  api<MigratePreview>('/api/migrate/preview', { method: 'POST', body: JSON.stringify(body) })

export const applyMigration = (
  body: MigrateSource & { environment_id: number; target_path?: string; overwrite: boolean },
) =>
  api<{ created: number; updated: number; skipped: string[] }>('/api/migrate/apply', {
    method: 'POST',
    body: JSON.stringify(body),
  })

export type InfisicalProject = { id: string; name: string; environments: string[] }

export const infisicalProjects = (body: {
  url: string
  client_id: string
  client_secret: string
  environment_id: number
}) =>
  api<InfisicalProject[]>('/api/migrate/infisical/projects', {
    method: 'POST',
    body: JSON.stringify(body),
  })

// --- проекты с шифрованием в браузере ---

export type E2eWrap = {
  enabled: boolean
  salt: string
  nonce: string
  wrapped_key: string
  verifier_nonce: string
  verifier: string
  iterations: number
}

export const getE2eWrap = (projectId: number) => api<E2eWrap>(`/api/projects/${projectId}/e2e`)

export const enableE2e = (
  projectId: number,
  body: {
    salt: string
    nonce: string
    wrapped_key: string
    verifier_nonce: string
    verifier: string
  },
) => api<E2eWrap>(`/api/projects/${projectId}/e2e`, { method: 'POST', body: JSON.stringify(body) })

export type E2eMachine = {
  machine_id: number
  name: string
  /** Прислал ли агент свой публичный ключ: без него запечатать нечего. */
  has_key: boolean
  has_wrap: boolean
}

export const listE2eMachines = (projectId: number) =>
  api<E2eMachine[]>(`/api/projects/${projectId}/e2e/machines`)

export const wrapE2eForMachine = (
  projectId: number,
  body: { machine_id: number; ephemeral_public: string; nonce: string; wrapped_key: string },
) =>
  api<E2eMachine>(`/api/projects/${projectId}/e2e/machines`, {
    method: 'POST',
    body: JSON.stringify(body),
  })

/** Публичный ключ машины: им браузер запечатывает ключ проекта. */
export const machinePublicKey = (id: number) =>
  api<{ public_key: string }>(`/api/machines/${id}/public-key`)
