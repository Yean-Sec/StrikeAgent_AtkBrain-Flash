export type AnimeHandle = { cancel?: () => void; revert?: () => void }

const live = new Set<AnimeHandle>()

export function prefersReducedMotion(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches
}

export function startIfAllowed(reduced: boolean, factory: () => AnimeHandle): () => void {
  if (reduced) return () => {}
  const anim = factory()
  live.add(anim)
  return () => {
    anim.cancel?.()
    anim.revert?.()
    live.delete(anim)
  }
}

export function liveAnimations(): number {
  return live.size
}
