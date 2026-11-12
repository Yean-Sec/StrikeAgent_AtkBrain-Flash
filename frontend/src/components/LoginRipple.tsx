import { useEffect, useRef, useState } from "react";
import { animate, stagger, utils } from "animejs";

/** 只在奶油 / 陶土里轻轻变，避免高饱和闪色。 */
const PALETTE = ["#d6e4ff", "#7aa2ff", "#e4dcff", "#b7c9f2", "#9eb6ee", "#c5d4f5", "#eef4ff"];
const SVG_NS = "http://www.w3.org/2000/svg";

type Kind = "round" | "sq" | "tall";
type Mode = "drift" | "cluster" | "orbit" | "rings" | "tiles" | "embers";
type Mote = { id: number; x: number; y: number; size: number; kind: Kind; color: string };
type Anim = { cancel?: () => void; revert?: () => void };

const WEIGHTED: Mode[] = [
  "rings", "rings", "tiles", "tiles",
  "embers", "cluster", "orbit", "drift",
];
const KINDS: Kind[] = ["round", "sq", "tall"];

function pickMode(prev: Mode | null): Mode {
  const pool = prev ? WEIGHTED.filter((m) => m !== prev) : WEIGHTED;
  return pool[utils.random(0, pool.length - 1, 0)] as Mode;
}

function seedMotes(n: number): Mote[] {
  return Array.from({ length: n }, (_, id) => ({
    id,
    x: utils.random(3, 97, 2),
    y: utils.random(4, 96, 2),
    size: utils.random(6, 24),
    kind: utils.randomPick(KINDS) as Kind,
    color: utils.randomPick(PALETTE) as string,
  }));
}

export function LoginRipple() {
  const host = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [box, setBox] = useState({ w: 0, h: 0 });
  const [motes, setMotes] = useState<Mote[]>([]);

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const fit = () => {
      const w = el.clientWidth;
      const h = el.clientHeight;
      setBox((prev) => (prev.w === w && prev.h === h ? prev : { w, h }));
      const n = Math.max(48, Math.min(84, Math.round((w * h) / 14000)));
      setMotes((prev) => (Math.abs(prev.length - n) < 8 && prev.length ? prev : seedMotes(n)));
    };
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const root = host.current;
    const svg = svgRef.current;
    if (!root || !svg || !box.w || !motes.length) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const dots = [...root.querySelectorAll<HTMLElement>(".login-mote")];
    const tiles = [...root.querySelectorAll<HTMLElement>(".login-tile")];
    const ringG = svg.querySelector(".js-rings") as SVGGElement | null;
    if (!dots.length) return;

    let stopped = false;
    const running: Anim[] = [];
    let wait: ReturnType<typeof setTimeout> | null = null;
    let prev: Mode | null = null;

    const track = (a: Anim) => {
      running.push(a);
      return a;
    };

    const clearSvg = () => {
      ringG?.replaceChildren();
    };

    const resetTiles = () => {
      tiles.forEach((el) => {
        el.style.opacity = "0";
        el.style.transform = "scale(.7)";
      });
    };

    const hold = (ms: number) => {
      if (wait) clearTimeout(wait);
      wait = setTimeout(play, ms);
    };

    const play = () => {
      if (stopped) return;
      if (wait) { clearTimeout(wait); wait = null; }
      running.splice(0).forEach((a) => {
        try { a.cancel?.(); } catch { /* ignore */ }
      });
      clearSvg();
      resetTiles();

      const mode = pickMode(prev);
      prev = mode;
      root.dataset.scene = mode;
      if (utils.random(0, 1, 0) === 0) {
        dots.forEach((el) => {
          if (Math.random() < 0.3) el.style.color = utils.randomPick(PALETTE) as string;
        });
      }

      if (mode === "drift") {
        track(animate(dots, {
          x: () => utils.random(-48, 48),
          y: () => utils.random(-36, 36),
          opacity: () => utils.random(0.08, 0.28, 2),
          rotate: () => utils.random(-16, 16),
          delay: () => utils.random(0, 700),
          duration: () => utils.random(2600, 4200),
          ease: "inOutSine",
        }));
        hold(utils.random(4200, 5000));
        return;
      }

      if (mode === "cluster") {
        const foci = Array.from({ length: utils.random(2, 3, 0) }, () => ({
          x: utils.random(18, 82, 2),
          y: utils.random(18, 82, 2),
        }));
        track(animate(dots, {
          x: (_, i) => {
            const m = motes[i];
            const f = foci[i % foci.length];
            return ((f.x - m.x) / 100) * box.w * 0.55;
          },
          y: (_, i) => {
            const m = motes[i];
            const f = foci[i % foci.length];
            return ((f.y - m.y) / 100) * box.h * 0.55;
          },
          opacity: () => utils.random(0.1, 0.3, 2),
          scale: () => utils.random(0.7, 1.15, 2),
          duration: 2600,
          ease: "inOutQuad",
          onComplete: () => {
            if (stopped) return;
            track(animate(dots, {
              x: 0,
              y: 0,
              scale: 1,
              opacity: () => utils.random(0.08, 0.18, 2),
              duration: 1400,
              ease: "inOutSine",
            }));
          },
        }));
        hold(4800);
        return;
      }

      if (mode === "orbit") {
        const cx = utils.random(30, 70, 2);
        const cy = utils.random(28, 72, 2);
        track(animate(dots, {
          x: (_, i) => {
            const ang = (i / dots.length) * Math.PI * 2;
            const r = 28 + (i % 6) * 16;
            const m = motes[i];
            return ((cx - m.x) / 100) * box.w + Math.cos(ang) * r;
          },
          y: (_, i) => {
            const ang = (i / dots.length) * Math.PI * 2;
            const r = 22 + (i % 6) * 14;
            const m = motes[i];
            return ((cy - m.y) / 100) * box.h + Math.sin(ang) * r;
          },
          opacity: (_, i) => (i % 4 === 0 ? 0.06 : utils.random(0.12, 0.3, 2)),
          duration: 2800,
          ease: "inOutSine",
          onComplete: () => {
            if (stopped) return;
            track(animate(dots, {
              x: 0,
              y: 0,
              opacity: () => utils.random(0.08, 0.18, 2),
              duration: 1300,
              ease: "inOutSine",
            }));
          },
        }));
        hold(5000);
        return;
      }

      if (mode === "rings") {
        if (!ringG) { hold(40); return; }
        const cx = utils.random(box.w * 0.22, box.w * 0.78, 1);
        const cy = utils.random(box.h * 0.22, box.h * 0.78, 1);
        const maxR = Math.min(box.w, box.h) * 0.46;
        track(animate(dots, {
          opacity: (_, i) => {
            const m = motes[i];
            const d = Math.hypot((m.x / 100) * box.w - cx, (m.y / 100) * box.h - cy);
            return d < maxR * 0.75 ? utils.random(0.16, 0.3, 2) : 0.05;
          },
          duration: 1600,
          ease: "inOutSine",
        }));
        [0, 1, 2].forEach((i) => {
          const c = document.createElementNS(SVG_NS, "circle");
          c.setAttribute("cx", String(cx));
          c.setAttribute("cy", String(cy));
          c.setAttribute("r", "14");
          c.setAttribute("class", "login-scene-ring");
          c.style.opacity = "0";
          ringG.appendChild(c);
          const state = { r: 14, o: 0 };
          track(animate(state, {
            r: maxR,
            o: [{ to: 0.62, duration: 480 }, { to: 0.42, duration: 1100 }, { to: 0, duration: 1420 }],
            delay: i * 420,
            duration: 3000,
            ease: "outCubic",
            onRender: () => {
              c.setAttribute("r", String(state.r));
              c.style.opacity = String(state.o);
            },
          }));
        });
        hold(4200);
        return;
      }

      if (mode === "tiles") {
        const picks = tiles.slice(0, utils.random(4, 7, 0));
        picks.forEach((el) => {
          const w = utils.random(72, 180);
          const h = utils.random(56, 140);
          el.style.left = `${utils.random(4, 78, 2)}%`;
          el.style.top = `${utils.random(6, 72, 2)}%`;
          el.style.width = `${w}px`;
          el.style.height = `${h}px`;
          el.style.color = utils.randomPick(PALETTE) as string;
          el.style.borderRadius = `${utils.random(10, 28)}px`;
        });
        track(animate(dots, {
          opacity: 0.05,
          scale: 0.65,
          duration: 900,
          ease: "inOutSine",
        }));
        track(animate(picks, {
          opacity: [{ to: utils.random(0.14, 0.22, 2) }, { to: 0 }],
          scale: [{ to: 1 }, { to: 0.86 }],
          delay: stagger(160, { from: "random" }),
          duration: 3200,
          ease: "inOutSine",
        }));
        hold(4000);
        return;
      }

      const hot = new Set<number>();
      while (hot.size < Math.min(10, Math.floor(dots.length * 0.16))) {
        hot.add(utils.random(0, dots.length - 1, 0));
      }
      hot.forEach((i) => {
        dots[i].style.color = utils.randomPick(["#4c7dff", "#7aa2ff", "#a9c0f5"]) as string;
      });
      track(animate(dots, {
        opacity: (_, i) => (hot.has(i) ? utils.random(0.28, 0.42, 2) : 0.04),
        scale: (_, i) => (hot.has(i) ? utils.random(1.4, 2.1, 2) : 0.55),
        x: (_, i) => (hot.has(i) ? utils.random(-10, 10) : 0),
        y: (_, i) => (hot.has(i) ? utils.random(-14, -2) : 0),
        delay: stagger(40, { from: "random" }),
        duration: 2600,
        ease: "inOutSine",
        onComplete: () => {
          if (stopped) return;
          track(animate(dots, {
            opacity: () => utils.random(0.08, 0.18, 2),
            scale: 1,
            x: 0,
            y: 0,
            duration: 1200,
            ease: "inOutSine",
          }));
        },
      }));
      hold(5000);
    };

    play();
    return () => {
      stopped = true;
      if (wait) clearTimeout(wait);
      running.forEach((a) => {
        try { a.cancel?.(); } catch { /* ignore */ }
        try { a.revert?.(); } catch { /* ignore */ }
      });
      clearSvg();
    };
  }, [box, motes]);

  return (
    <div ref={host} className="login-wash" aria-hidden>
      <span className="login-wash-blob a" />
      <span className="login-wash-blob b" />
      <span className="login-wash-blob c" />
      <span className="login-wash-spot" />
      <svg
        ref={svgRef}
        className="login-scene-svg"
        viewBox={box.w && box.h ? `0 0 ${box.w} ${box.h}` : undefined}
        preserveAspectRatio="xMidYMid meet"
      >
        <g className="js-rings" />
      </svg>
      <div className="login-motes">
        {motes.map((m) => (
          <span
            key={m.id}
            className="login-mote-wrap"
            style={{ left: `${m.x}%`, top: `${m.y}%` }}
          >
            <span
              className={`login-mote is-${m.kind}`}
              style={{
                width: m.size,
                height: m.kind === "tall" ? Math.round(m.size * 1.7) : m.size,
                color: m.color,
              }}
            />
          </span>
        ))}
      </div>
      <div className="login-tiles">
        {Array.from({ length: 8 }, (_, i) => (
          <span key={i} className="login-tile" />
        ))}
      </div>
    </div>
  );
}
