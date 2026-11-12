import { liveAnimations, startIfAllowed } from "./animeControl.ts"

function assert(cond: boolean, message: string) {
  if (!cond) throw new Error(message)
}

const stop = startIfAllowed(false, () => ({ cancel() {} }))
assert(liveAnimations() === 1, "挂载后应有一个动画")
stop()
assert(liveAnimations() === 0, "卸载后应取消")

const again = startIfAllowed(false, () => ({ cancel() {} }))
again()
const third = startIfAllowed(false, () => ({ cancel() {} }))
third()
assert(liveAnimations() === 0, "反复挂载卸载后不应残留")

startIfAllowed(true, () => {
  throw new Error("减少动态效果时不应创建动画")
})
assert(liveAnimations() === 0, "减少动态效果时计数仍为 0")

console.log("anime ok")
