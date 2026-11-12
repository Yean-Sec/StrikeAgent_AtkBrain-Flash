"use client"

import { FormEvent, useEffect, useState } from "react"
import { Shell } from "@/components/Shell"
import { api } from "@/lib/api"
import type { Graph, Project, RtEvent } from "@/lib/types"

function projectId() {
  if (typeof window === "undefined") return ""
  const parts = window.location.pathname.split("/").filter(Boolean)
  const at = parts.indexOf("project")
  const id = at >= 0 ? parts[at + 1] : ""
  return id && id !== "_" ? id : ""
}

export function ProjectView() {
  const [id, setId] = useState("")
  const [project, setProject] = useState<Project | null>(null)
  const [graph, setGraph] = useState<Graph | null>(null)
  const [events, setEvents] = useState<RtEvent[]>([])
  const [message, setMessage] = useState("")
  const [note, setNote] = useState("")
  useEffect(() => { setId(projectId()) }, [])
  useEffect(() => {
    if (!id) return
    api<Project>(`/api/projects/${id}`).then(setProject).catch((e: Error) => setMessage(e.message))
    api<Graph>(`/api/projects/${id}/graph`).then(setGraph).catch(() => {})
    api<RtEvent[]>(`/api/projects/${id}/events?after=0`).then(setEvents).catch(() => {})
  }, [id])
  async function start() {
    const row = await api<{ ok: boolean; status: string }>(`/api/projects/${id}/start?confirm_restart=false`, { method: "POST" })
    setMessage(row.status)
  }
  async function steer(ev: FormEvent) {
    ev.preventDefault()
    await api(`/api/projects/${id}/steer`, { method: "POST", body: JSON.stringify({ message: note }) })
    setNote("")
  }
  return (
    <Shell>
      <h1>{project?.name || id || "项目"}</h1>
      <p>{project?.status} · 发现 {graph?.stats.findings ?? 0} · 事件 {events.length}</p>
      <p className="err">{message}</p>
      <button type="button" onClick={start}>启动</button>
      <form className="form" onSubmit={steer}>
        <textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="协同消息" />
        <button type="submit">发送</button>
      </form>
    </Shell>
  )
}
