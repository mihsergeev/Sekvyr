import { useCallback, useLayoutEffect, useRef } from 'react'
import { isCurrentSession, sessionStamp } from './api'

/** Запоздалый ответ не должен действовать за пределами окна или страницы. */
export function useOperationScope(scope: string | number) {
  const revision = useRef(0)
  useLayoutEffect(() => () => { revision.current += 1 }, [scope])

  return useCallback(() => {
    const session = sessionStamp()
    const started = revision.current
    return () => started === revision.current && isCurrentSession(session)
  }, [])
}
