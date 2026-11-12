use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::Map;
use serde_json::Value;

use crate::dto::*;
use crate::error::ApiError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/settings", get(settings))
        .route("/api/settings/review", post(review))
        .route("/api/settings/hunt-clocks", post(clocks))
        .route("/api/settings/concurrency", post(concurrency))
        .route("/api/settings/webhook", post(webhook))
        .route("/api/settings/webhook/retry", post(webhook_retry))
        .route("/api/proxy/status", get(proxy_status))
        .route("/api/proxy/pool", get(proxy_pool).post(proxy_pool_set))
        .route("/api/proxy/enabled", post(proxy_enabled))
        .route("/api/proxy/verify", post(proxy_verify))
        .route("/api/settings/pi-models", get(pi_models).post(pi_models_set))
        .route("/api/settings/llm", get(llm).post(llm_set))
        .route("/api/settings/llm/test", post(llm_test))
        .route("/api/version", get(version))
        .route("/api/version/apply", post(version_apply))
}

async fn settings(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<Settings>, ApiError> {
    Ok(Json(st.settings(&headers)?))
}
async fn review(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<ReviewSettings>) -> Result<Json<ReviewWrap>, ApiError> {
    Ok(Json(ReviewWrap { review: st.set_review(&headers, body)? }))
}
async fn clocks(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<Map<String, Value>>) -> Result<Json<HuntClocksResult>, ApiError> {
    Ok(Json(st.set_clocks(&headers, body)?))
}
async fn concurrency(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<ConcurrencyRequest>) -> Result<Json<ConcurrencyResult>, ApiError> {
    Ok(Json(st.set_concurrency(&headers, body)?))
}
async fn webhook(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<Webhook>) -> Result<Json<WebhookResult>, ApiError> {
    Ok(Json(st.set_webhook(&headers, body)?))
}
async fn webhook_retry(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<WebhookRetry>, ApiError> {
    Ok(Json(st.retry_webhook(&headers)?))
}
async fn proxy_status(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<ProxyStatus>, ApiError> {
    Ok(Json(st.proxy_status(&headers)?))
}
async fn proxy_pool(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<ProxyPoolResult>, ApiError> {
    Ok(Json(st.proxy_pool(&headers)?))
}
async fn proxy_pool_set(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<ProxyPoolRequest>) -> Result<Json<OkBody>, ApiError> {
    Ok(Json(st.set_proxy_pool(&headers, body)?))
}
async fn proxy_enabled(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<ProxyEnabledRequest>) -> Result<Json<ProxyEnabledResult>, ApiError> {
    Ok(Json(st.set_proxy_enabled(&headers, body)?))
}
async fn proxy_verify(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<ProxyVerify>, ApiError> {
    Ok(Json(st.verify_proxy(&headers)?))
}
async fn pi_models(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<TextBody>, ApiError> {
    Ok(Json(st.pi_models(&headers)?))
}
async fn pi_models_set(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<TextBody>) -> Result<Json<TextResult>, ApiError> {
    Ok(Json(st.set_pi_models(&headers, body)?))
}
async fn llm(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<LlmProfile>, ApiError> {
    Ok(Json(st.llm(&headers)?))
}
async fn llm_set(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<LlmProfile>) -> Result<Json<LlmProfile>, ApiError> {
    Ok(Json(st.set_llm(&headers, body)?))
}
async fn llm_test(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<LlmProfile>) -> Result<Json<LlmTestResult>, ApiError> {
    Ok(Json(st.test_llm(&headers, body)?))
}
async fn version(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<VersionInfo>, ApiError> {
    Ok(Json(st.version(&headers)?))
}
async fn version_apply(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<VersionApply>, ApiError> {
    Ok(Json(st.apply_version(&headers)?))
}

#[derive(serde::Serialize)]
struct ReviewWrap {
    review: ReviewSettings,
}
