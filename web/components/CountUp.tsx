"use client"

import { useEffect, useRef } from "react"
import { animate, type AnimationParams } from "animejs"
import { prefersReducedMotion, startIfAllowed } from "@/lib/animeControl"

export function CountUp({ value }: { value: number }) {
  const ref = useRef<HTMLSpanElement>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (prefersReducedMotion()) {
      el.textContent = String(value)
      return
    }
    const obj = { v: 0 }
    return startIfAllowed(false, () => animate(obj, {
      v: value,
      duration: 700,
      ease: "outCubic",
      onUpdate: () => { el.textContent = String(Math.round(obj.v)) },
    } as AnimationParams))
  }, [value])
  return <span ref={ref}>{value}</span>
}
