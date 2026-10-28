'use client'
import { useEffect, useRef } from 'react'
import { usePrefersReducedMotion, useHasFinePointer } from '@/lib/use-motion-preference'
import { marketing } from '@/lib/marketing-tokens'

interface Point { x: number; y: number; t: number }

export default function CursorTrail() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const pointsRef = useRef<Point[]>([])
  const reducedMotion = usePrefersReducedMotion()
  const hasFinePointer = useHasFinePointer()

  useEffect(() => {
    if (reducedMotion || !hasFinePointer) return
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resize = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    const handleMove = (e: MouseEvent) => {
      pointsRef.current.push({ x: e.clientX, y: e.clientY, t: performance.now() })
      if (pointsRef.current.length > 28) pointsRef.current.shift()
    }
    window.addEventListener('mousemove', handleMove)

    let raf: number
    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height)
      const pts = pointsRef.current
      const now = performance.now()
      while (pts.length && now - pts[0].t > 520) pts.shift()

      if (pts.length > 2) {
        ctx.beginPath()
        for (let i = 0; i < pts.length - 1; i++) {
          const p0 = pts[i]
          const p1 = pts[i + 1]
          const dx = p1.x - p0.x
          const dy = p1.y - p0.y
          const len = Math.hypot(dx, dy) || 1
          const px = -dy / len
          const py = dx / len
          const age = (now - p0.t) / 520
          const phase = i * 0.9
          const amplitude = 6 * (1 - age)
          const wave = Math.sin(phase + now * 0.006) * amplitude
          const wx = p0.x + px * wave
          const wy = p0.y + py * wave
          if (i === 0) ctx.moveTo(wx, wy)
          else ctx.lineTo(wx, wy)
        }
        ctx.strokeStyle = marketing.accent
        ctx.globalAlpha = 0.32
        ctx.lineWidth = 1.4
        ctx.lineCap = 'round'
        ctx.stroke()
      }
      raf = requestAnimationFrame(draw)
    }
    raf = requestAnimationFrame(draw)

    return () => {
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', handleMove)
      cancelAnimationFrame(raf)
    }
  }, [reducedMotion, hasFinePointer])

  if (reducedMotion || !hasFinePointer) return null

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed', inset: 0, pointerEvents: 'none',
        zIndex: 40, mixBlendMode: 'screen'
      }}
    />
  )
}
