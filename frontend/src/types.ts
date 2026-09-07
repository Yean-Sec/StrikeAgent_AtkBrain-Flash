export interface Stats {
  nodes: number;
  services?: number;
  edges: number;
  findings: number;
  high?: number;
  medium?: number;
  low?: number;
  critical: number;
  has_shell: boolean;
  frontier_open?: number;
  frontier_strategies?: number;
  lateral_active?: boolean;
  pivot_edges?: number;
  hosts_footed?: number;
  mass_data_leak?: boolean;
}

export interface GraphIntent {
  id: string;
  from: string[];
  description: string;
  rationale?: string;
  est_success: number;
  status: string;
  strategy_key?: string;
  priority?: number;
  attempt_count?: number;
  failure_fingerprint?: string;
  result_summary?: string;
}

export interface GraphNode {
  id: string;
  key: string;
  type: string;
  title: string;
  detail?: any;
  severity: string;
  is_rce: boolean;
  risk_score: number;
  tags: string[];
  status: string;
  created_at?: number;
  updated_at?: number;
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  relation: string;
  weight: number;
  rationale?: string;
  on_rce_path: boolean;
}

export interface Finding {
  id: string;
  node_key?: string;
  severity: string;
  category: string;
  title: string;
  description?: string;
  evidence?: string;
  poc_curl?: string;
  poc_python?: string;
  cvss?: number;
  critical: boolean;
  created_at: number;
  verification_status?: "pending" | "verified" | "flaky" | "rejected" | string;
  verified_at?: number;
  proof_type?: string;
  proof_canary?: string;
  proof_url?: string;
  proof_detail?: string;
  secondary_verified?: boolean;
  redteam_rating?: string;
  redteam_rating_rationale?: string;
}

/** 弹层用的全量详情（含手动步骤与 PoC） */
export interface FindingDetail extends Finding {
  related_node?: {
    key: string;
    type: string;
    title: string;
    detail?: string;
    severity?: string;
    risk_score?: number;
    tags?: string[];
  } | null;
  poc?: { curl: string; python: string };
  manual_steps?: string[];
  impact?: string;
  impact_detail?: string;
  root_cause?: string;
  mechanism?: string;
  affected_scope?: string;
  param_analysis?: string;
  http_raw?: string;
  expected_result?: string;
  expected_signals?: string[];
  prerequisites?: string;
  remediation?: string;
  cvss_explanation?: string;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: Finding[];
  intents?: GraphIntent[];
  frontier?: { open?: number; strategies?: number; disproved?: number; verified?: number; by_status?: Record<string, number> };
  rce_path: { path: string[]; paths?: string[][]; likelihood: number; frontier_mode?: boolean };
  stats: Stats;
}

export interface Project {
  id: string;
  name: string;
  kind: string;
  target?: string;
  ports?: number[];
  scope: any;
  config: any;
  status: string;
  parent_id?: string;
  created_at: number;
  updated_at: number;
  stats?: Stats;
  running?: boolean;
  /** 已启动但还在等项目并发槽（未真正开跑） */
  queued?: boolean;
  graph?: Graph;
  run_id?: string;
}

export interface RTEvent {
  id?: string | number;
  type: string;
  ts: number;
  run_id?: string;
  payload: any;
}
