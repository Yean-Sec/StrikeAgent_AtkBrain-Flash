export type ErrorInfo = { code: string; message: string }
export type ErrorBody = { error: ErrorInfo }

export type Health = { ok: boolean }

export type Pubkey = { alg: string; pem: string; ticket: string; ttl: number }

export type AuthMe = {
  required: boolean
  authenticated: boolean
  username: string | null
  totp_enabled: boolean
  must_change_password: boolean
}

export type LoginRequest = {
  username: string
  password: string
  ticket: string
  totp?: string
  pending_id?: string
}

export type LoginResult = {
  ok: boolean
  username?: string
  totp_enabled?: boolean
  must_change_password?: boolean
  need_totp?: boolean
  pending_id?: string
}

export type OkBody = { ok: boolean }

export type PasswordRequest = { old_password: string; new_password: string }
export type PasswordResult = { ok: boolean; must_change_password: boolean }

export type TotpSetup = { otpauth_url: string; secret: string; setup_id: string }
export type TotpConfirmRequest = { setup_id: string; code: string }
export type TotpConfirmResult = { ok: boolean; totp_enabled: boolean }

export type ReviewSettings = { secondary_verify: boolean; redteam_rating: boolean }
export type HuntClocks = Record<string, number>
export type Settings = {
  review: ReviewSettings
  hunt_clocks: HuntClocks
  concurrency: number
}

export type ConcurrencyRequest = { value: number; track: string }
export type ConcurrencyResult = { ok: boolean; value: number; track: string }

export type Webhook = { url: string; severities: string[]; projects: string[]; assets: string[] }
export type WebhookResult = { webhook: Webhook }
export type WebhookRetry = { sent: number; failed: number }

export type ProxyStatus = { enabled: boolean; nodes: string[] }
export type ProxyEnabledRequest = { enabled: boolean }
export type ProxyEnabledResult = { enabled: boolean }
export type ProxyPoolRequest = { custom_text: string }
export type ProxyPoolResult = { ok: boolean; enabled: boolean; nodes: string[] }
export type ProxyVerify = { ok: boolean; alive: number }

export type TextBody = { text: string }
export type TextResult = { ok: boolean; text: string }

export type LlmProfile = {
  format: string
  model: string
  base_url: string
  api_key_set: boolean
  api_key_hint: string
  api_key?: string
  ok?: boolean
}

export type LlmTestResult = {
  ok: boolean
  latency_ms?: number
  model?: string
  reply?: string
  error?: string
}

export type VersionInfo = { version: string; update_available: boolean }
export type VersionApply = { ok: boolean }

export type Project = {
  id: string
  name: string
  status: string
  objective: string
  kind: string
}

export type CreateProject = { name: string; objective: string; targets: string[] }
export type PatchProject = { name?: string; status?: string }
export type OutputLangRequest = { output_lang: string }
export type OutputLangResult = { ok: boolean; output_lang: string }
export type IdsRequest = { ids: string[]; confirm_restart?: boolean }
export type IdsResult = { ok: boolean; ids: string[] }
export type StatusResult = { ok: boolean; status: string }
export type SteerRequest = { message: string }

export type RcePath = { path: string[]; likelihood: number }
export type GraphStats = { nodes: number; edges: number; findings: number; critical: number; has_shell: boolean; frontier_open: number }
export type Graph = {
  nodes: Record<string, unknown>[]
  edges: Record<string, unknown>[]
  findings: Record<string, unknown>[]
  intents: Record<string, unknown>[]
  frontier: Record<string, unknown>
  rce_path: RcePath
  stats: GraphStats
}

export type RtEvent = { id: string; type: string; payload: Record<string, unknown>; ts: number }

export type Memory = { episodes: Record<string, unknown>[]; playbook: Record<string, unknown>[] }
export type ReportBody = { format: string; body: string }
export type ExportJob = { job_id: string; status: string }

export type Finding = {
  id: string
  project_id: string
  title: string
  severity: string
  verification_status: string
  category: string
  evidence: string
  redteam_rating: string
  redteam_rating_rationale: string
  secondary_verified: boolean
}

export type ReviewRequest = {
  secondary_verified: boolean
  redteam_rating: string
  redteam_rating_rationale: string
}

export type ReviewJob = { job_id: string; status: string }
export type Poc = { curl: string; python: string }
export type RetestResult = { ok: boolean; job_id: string }

export type AssetGroup = { primary: string; zone: string; vhosts: string[]; ports: number[] }
export type AssetPreviewRequest = { text: string; objective: string }
export type AssetPreview = {
  group_count: number
  hosts: number
  lines_kept: number
  skipped_dup_count: number
  skipped_header: string[]
  groups: AssetGroup[]
}

export type FilesResult = { ok: boolean; files: string[] }
export type ArchiveResult = { ok: boolean; archived: string[] }
export type TemplateResult = { id: string; name: string }
export type Template = { id: string; name: string }
export type FromTemplate = { template_id: string; name: string }
export type CommandRequest = { allow: boolean }
export type ImportProgress = { status: string; done: number; total: number }
export type Scoreboard = { rows: Record<string, unknown>[] }
