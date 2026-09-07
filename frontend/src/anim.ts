// anime.js v4 动画助手，全站统一平滑动效。
import { animate, stagger } from "animejs";

export function fadeInUp(targets: any, delay = 0) {
  return animate(targets, {
    opacity: [0, 1],
    translateY: [14, 0],
    duration: 520,
    delay,
    ease: "outCubic",
  });
}

export function staggerReveal(targets: any, step = 55) {
  return animate(targets, {
    opacity: [0, 1],
    translateY: [16, 0],
    duration: 560,
    delay: stagger(step),
    ease: "outCubic",
  });
}

export function popIn(targets: any) {
  return animate(targets, {
    scale: [0.6, 1],
    opacity: [0, 1],
    duration: 480,
    ease: "outBack",
  });
}

export function pulse(targets: any) {
  return animate(targets, {
    scale: [1, 1.35, 1],
    opacity: [1, 0.6, 1],
    duration: 1400,
    loop: true,
    ease: "inOutSine",
  });
}

export function countUp(el: HTMLElement, to: number, dur = 900) {
  const obj = { v: 0 };
  animate(obj, {
    v: to,
    duration: dur,
    ease: "outCubic",
    onUpdate: () => {
      el.textContent = String(Math.round(obj.v));
    },
  });
}
