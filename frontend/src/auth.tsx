import { createContext, useContext } from 'react'
import type { Me, Role } from './api'

/* Кто вошел - для того, чтобы не показывать заведомо запрещенное. Настоящую
 * проверку делает бэкенд (роль сверяется в зависимости FastAPI, а не в
 * роутерах), здесь только гейтинг интерфейса: спрятанная кнопка это удобство,
 * а не защита. */

// Уровни ролей - те же числа, что в backend/app/roles.py. Их расхождение ловит
// ops/selfcheck.py: иначе интерфейс однажды покажет раздел, который API закроет.
export const LEVELS: Record<Role, number> = {
  owner: 40,
  maintainer: 30,
  developer: 20,
  viewer: 10,
}

export type Auth = Me & {
  isOwner: boolean
  /** ответственный и выше: список учеток и журнал */
  isManager: boolean
  /** только чтение */
  isViewer: boolean
}

const empty: Auth = {
  username: '',
  role: 'viewer' as Role,
  level: 0,
  role_title: '',
  totp_enabled: false,
  isOwner: false,
  isManager: false,
  isViewer: true,
}

const AuthContext = createContext<Auth>(empty)

export function toAuth(me: Me): Auth {
  return {
    ...me,
    isOwner: me.role === 'owner',
    isManager: me.level >= LEVELS.maintainer,
    isViewer: me.role === 'viewer',
  }
}

export const AuthProvider = AuthContext.Provider

export function useAuth(): Auth {
  return useContext(AuthContext)
}
