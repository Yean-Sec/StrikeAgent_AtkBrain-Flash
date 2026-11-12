"use client"

import { useEffect, type RefObject } from "react"
import { animate, type AnimationParams } from "animejs"
import { prefersReducedMotion, startIfAllowed } from "./animeControl"

export function useAnime(ref: RefObject<HTMLElement | null>, spec: AnimationParams) {
  useEffect(() => {
    const el = ref.current
    if (!el) return
    return startIfAllowed(prefersReducedMotion(), () => animate(el, spec))
    // 规格只在挂载时读取，卸载时由 startIfAllowed 取消。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ref])
}
