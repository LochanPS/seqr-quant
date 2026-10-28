import { useState, useEffect } from 'react'

export function usePrefersReducedMotion(): boolean {
  const [prefers, setPrefers] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setPrefers(mq.matches)
    const handler = (e: MediaQueryListEvent) => setPrefers(e.matches)
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])
  return prefers
}

export function useHasFinePointer(): boolean {
  const [hasFine, setHasFine] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia('(pointer: fine)')
    setHasFine(mq.matches)
  }, [])
  return hasFine
}
