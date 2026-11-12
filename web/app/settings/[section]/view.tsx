"use client"

import Link from "next/link"
import { FormEvent, useEffect, useState } from "react"
import { Shell } from "@/components/Shell"
import { api } from "@/lib/api"
import type { PasswordResult, ReviewSettings, Settings } from "@/lib/types"

const sections = ["account", "hunt", "review", "proxy", "model"] as const

function sectionOf() {
  if (typeof window === "undefined") return "account"
  const parts = window.location.pathname.split("/").filter(Boolean)
  const at = parts.indexOf("settings")
  const name = at >= 0 ? parts[at + 1] : "account"
  return sections.includes(name as typeof sections[number]) ? name : "account"
}

export function SettingsView() {
  const [section, setSection] = useState("account")
  const [settings, setSettings] = useState<Settings | null>(null)
  const [oldPassword, setOldPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [message, setMessage] = useState("")
  useEffect(() => { setSection(sectionOf()) }, [])
  useEffect(() => {
    if (section === "account") return
    api<Settings>("/api/settings").then(setSettings).catch((e: Error) => setMessage(e.message))
  }, [section])
  async function savePassword(ev: FormEvent) {
    ev.preventDefault()
    const row = await api<PasswordResult>("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    })
    setMessage(row.must_change_password ? "仍需修改" : "已更新")
  }
  async function saveReview(ev: FormEvent) {
    ev.preventDefault()
    const form = new FormData(ev.currentTarget as HTMLFormElement)
    const review: ReviewSettings = {
      secondary_verify: form.get("secondary_verify") === "on",
      redteam_rating: form.get("redteam_rating") === "on",
    }
    await api("/api/settings/review", { method: "POST", body: JSON.stringify(review) })
    setMessage("已保存")
  }
  return (
    <Shell>
      <nav className="nav">
        {sections.map((item) => <Link key={item} href={`/settings/${item}/`}>{item}</Link>)}
      </nav>
      <h1>{section}</h1>
      <p className="ok">{message}</p>
      {section === "account" ? (
        <form className="form" onSubmit={savePassword}>
          <input type="password" value={oldPassword} onChange={(e) => setOldPassword(e.target.value)} placeholder="旧口令" />
          <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="新口令" />
          <button type="submit">修改口令</button>
        </form>
      ) : null}
      {section === "hunt" ? <p>并发 {settings?.concurrency ?? 0}</p> : null}
      {section === "review" ? (
        <form className="form" onSubmit={saveReview}>
          <label><input name="secondary_verify" type="checkbox" defaultChecked={settings?.review.secondary_verify} /> 二次验证</label>
          <label><input name="redteam_rating" type="checkbox" defaultChecked={settings?.review.redteam_rating} /> 红队评级</label>
          <button type="submit">保存</button>
        </form>
      ) : null}
      {section === "proxy" ? <p>代理设置由接口读写。</p> : null}
      {section === "model" ? <p>模型 {settings ? "已连接设置" : ""}</p> : null}
    </Shell>
  )
}
