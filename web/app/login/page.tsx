"use client"

import { FormEvent, useState } from "react"
import { useRouter } from "next/navigation"
import { api } from "@/lib/api"
import type { LoginResult, Pubkey } from "@/lib/types"

export default function LoginPage() {
  const router = useRouter()
  const [username, setUsername] = useState("operator")
  const [password, setPassword] = useState("")
  const [totp, setTotp] = useState("")
  const [pending, setPending] = useState("")
  const [message, setMessage] = useState("")
  async function onSubmit(ev: FormEvent) {
    ev.preventDefault()
    setMessage("")
    const key = await api<Pubkey>("/api/auth/pubkey")
    const result = await api<LoginResult>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password, ticket: key.ticket, totp, pending_id: pending || undefined }),
    })
    if (result.need_totp && result.pending_id) {
      setPending(result.pending_id)
      setMessage("需要验证码")
      return
    }
    router.push(result.must_change_password ? "/settings/account/" : "/")
  }
  return (
    <main className="main">
      <h1>登录</h1>
      <form className="form" onSubmit={onSubmit}>
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="用户名" />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="口令" />
        {pending ? <input value={totp} onChange={(e) => setTotp(e.target.value)} placeholder="验证码" /> : null}
        <button type="submit">进入</button>
        <p className="err">{message}</p>
      </form>
    </main>
  )
}
