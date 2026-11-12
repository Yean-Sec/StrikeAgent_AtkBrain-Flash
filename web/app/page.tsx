"use client"

import { FormEvent, useEffect, useState } from "react"
import Link from "next/link"
import { Shell } from "@/components/Shell"
import { DataTable } from "@/components/DataTable"
import { CountUp } from "@/components/CountUp"
import { api } from "@/lib/api"
import type { Project } from "@/lib/types"

export default function HomePage() {
  const [rows, setRows] = useState<Project[]>([])
  const [name, setName] = useState("")
  const [message, setMessage] = useState("")
  useEffect(() => {
    api<Project[]>("/api/projects").then(setRows).catch((e: Error) => setMessage(e.message))
  }, [])
  async function onCreate(ev: FormEvent) {
    ev.preventDefault()
    const created = await api<Project>("/api/projects", {
      method: "POST",
      body: JSON.stringify({ name, objective: "agent", targets: ["example.com"] }),
    })
    setRows((cur) => [...cur, created])
    setName("")
  }
  return (
    <Shell>
      <h1>项目 <CountUp value={rows.length} /></h1>
      <p className={message ? "err" : "ok"}>{message}</p>
      <form className="form" onSubmit={onCreate}>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="名称" />
        <button type="submit">新建</button>
      </form>
      <DataTable
        columns={["名称", "状态", "目标"]}
        rows={rows.map((row) => [row.name, row.status, row.objective])}
      />
      <ul>
        {rows.map((row) => <li key={row.id}><Link href={`/project/${row.id}/`}>{row.name}</Link></li>)}
      </ul>
    </Shell>
  )
}
