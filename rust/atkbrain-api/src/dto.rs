use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize)]
pub struct ErrorInfo {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub error: ErrorInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct Health {
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Pubkey {
    pub alg: String,
    pub pem: String,
    pub ticket: String,
    pub ttl: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthMe {
    pub required: bool,
    pub authenticated: bool,
    pub username: Option<String>,
    pub totp_enabled: bool,
    pub must_change_password: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub ticket: String,
    pub totp: Option<String>,
    pub pending_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub must_change_password: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub need_totp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OkBody {
    pub ok: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasswordResult {
    pub ok: bool,
    pub must_change_password: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TotpSetup {
    pub otpauth_url: String,
    pub secret: String,
    pub setup_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TotpConfirmRequest {
    pub setup_id: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TotpConfirmResult {
    pub ok: bool,
    pub totp_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSettings {
    pub secondary_verify: bool,
    pub redteam_rating: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Settings {
    pub review: ReviewSettings,
    pub hunt_clocks: Map<String, Value>,
    pub concurrency: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConcurrencyRequest {
    pub value: i64,
    pub track: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConcurrencyResult {
    pub ok: bool,
    pub value: i64,
    pub track: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub url: String,
    pub severities: Vec<String>,
    pub projects: Vec<String>,
    pub assets: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookResult {
    pub webhook: Webhook,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookRetry {
    pub sent: i64,
    pub failed: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub enabled: bool,
    pub nodes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyEnabledRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyEnabledResult {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyPoolRequest {
    pub custom_text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyPoolResult {
    pub ok: bool,
    pub enabled: bool,
    pub nodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyVerify {
    pub ok: bool,
    pub alive: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextBody {
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TextResult {
    pub ok: bool,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmProfile {
    pub format: String,
    pub model: String,
    pub base_url: String,
    pub api_key_set: bool,
    pub api_key_hint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LlmTestResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub version: String,
    pub update_available: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionApply {
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub status: String,
    pub objective: String,
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateProject {
    pub name: String,
    pub objective: String,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatchProject {
    pub name: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutputLangRequest {
    pub output_lang: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputLangResult {
    pub ok: bool,
    pub output_lang: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdsRequest {
    pub ids: Vec<String>,
    #[serde(default)]
    pub confirm_restart: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdsResult {
    pub ok: bool,
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusResult {
    pub ok: bool,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SteerRequest {
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RcePath {
    pub path: Vec<String>,
    pub likelihood: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphStats {
    pub nodes: i64,
    pub edges: i64,
    pub findings: i64,
    pub critical: i64,
    pub has_shell: bool,
    pub frontier_open: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Graph {
    pub nodes: Vec<Value>,
    pub edges: Vec<Value>,
    pub findings: Vec<Value>,
    pub intents: Vec<Value>,
    pub frontier: Map<String, Value>,
    pub rce_path: RcePath,
    pub stats: GraphStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct RtEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub payload: Map<String, Value>,
    pub ts: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Memory {
    pub episodes: Vec<Value>,
    pub playbook: Vec<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportBody {
    pub format: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportJob {
    pub job_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub project_id: String,
    pub title: String,
    pub severity: String,
    pub verification_status: String,
    pub category: String,
    pub evidence: String,
    pub redteam_rating: String,
    pub redteam_rating_rationale: String,
    pub secondary_verified: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReviewRequest {
    pub secondary_verified: bool,
    pub redteam_rating: String,
    pub redteam_rating_rationale: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewJob {
    pub job_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Poc {
    pub curl: String,
    pub python: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetestResult {
    pub ok: bool,
    pub job_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetGroup {
    pub primary: String,
    pub zone: String,
    pub vhosts: Vec<String>,
    pub ports: Vec<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AssetPreviewRequest {
    pub text: String,
    pub objective: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetPreview {
    pub group_count: i64,
    pub hosts: i64,
    pub lines_kept: i64,
    pub skipped_dup_count: i64,
    pub skipped_header: Vec<String>,
    pub groups: Vec<AssetGroup>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilesResult {
    pub ok: bool,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveResult {
    pub ok: bool,
    pub archived: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateResult {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Template {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FromTemplate {
    pub template_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TemplateName {
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandRequest {
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportProgress {
    pub status: String,
    pub done: i64,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Scoreboard {
    pub rows: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfirmQuery {
    #[serde(default)]
    pub confirm_restart: bool,
    #[serde(default)]
    pub unfinished_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HuntClocksResult {
    pub hunt_clocks: Map<String, Value>,
}

pub fn empty_map() -> Map<String, Value> {
    Map::new()
}
