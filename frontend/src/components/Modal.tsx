import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { animate } from "animejs";

export function Modal({
  children, onClose, title, wide = false,
}: { children: any; onClose: () => void; title: string; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) animate(ref.current, { opacity: [0, 1], translateY: [24, 0], scale: [0.96, 1], duration: 380, ease: "outCubic" });
  }, []);
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);
  return createPortal(
    <div className="modal-overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal${wide ? " modal-wide" : ""}`} ref={ref}>
        <div className="spread" style={{ marginBottom: 20 }}>
          <h2>{title}</h2>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>✕</button>
        </div>
        {children}
      </div>
    </div>,
    document.body,
  );
}
