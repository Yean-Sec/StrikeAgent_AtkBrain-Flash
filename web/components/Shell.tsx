"use client"

import Link from "next/link"
import { useRef, type ReactNode } from "react"
import { useAnime } from "@/lib/useAnime"

export function Shell({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLElement>(null)
  useAnime(ref, { opacity: [0, 1], translateY: [12, 0], duration: 480, ease: "outCubic" })
  return (
    <div className="shell">
      <nav className="nav">
        <Link href="/">项目</Link>
        <Link href="/vulns/">漏洞</Link>
        <Link href="/settings/account/">设置</Link>
        <Link href="/about/">关于</Link>
      </nav>
      <main className="main" ref={ref}>{children}</main>
    </div>
  )
}
