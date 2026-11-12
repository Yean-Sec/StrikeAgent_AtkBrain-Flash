"use client"

import { useEffect, useState } from "react"
import { Shell } from "@/components/Shell"
import { DataTable } from "@/components/DataTable"
import { api } from "@/lib/api"
import type { Finding } from "@/lib/types"

export default function VulnsPage() {
  const [rows, setRows] = useState<Finding[]>([])
  const [message, setMessage] = useState("")
  useEffect(() => {
    api<Finding[]>("/api/findings").then(setRows).catch((e: Error) => setMessage(e.message))
  }, [])
  return (
    <Shell>
      <h1>漏洞</h1>
      <p className="err">{message}</p>
      <DataTable
        columns={["标题", "严重度", "状态"]}
        rows={rows.map((row) => [row.title, row.severity, row.verification_status])}
      />
    </Shell>
  )
}
