import type { ErrorBody } from "./types"

export const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL ?? ""

export class ApiError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json")
  const res = await fetch(`${apiBase}${path}`, { ...init, headers, credentials: "include" })
  if (res.status === 204) return undefined as T
  const text = await res.text()
  const data = text ? JSON.parse(text) : {}
  if (!res.ok) {
    const body = data as ErrorBody
    throw new ApiError(res.status, body.error?.code || "invalid", body.error?.message || res.statusText)
  }
  return data as T
}
