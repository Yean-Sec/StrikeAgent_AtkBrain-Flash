use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::dto::*;
use crate::error::ApiError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/findings", get(list))
        .route("/api/review-jobs/{job_id}", get(job))
        .route("/api/projects/{id}/findings/{fid}", get(one))
        .route("/api/projects/{id}/findings/{fid}/review", post(review))
        .route("/api/projects/{id}/findings/{fid}/poc", get(poc))
        .route("/api/projects/{id}/findings/{fid}/retest", post(retest))
        .route("/api/projects/{id}/findings/{fid}/report", get(report))
}

async fn list(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<Finding>>, ApiError> {
    Ok(Json(st.findings(&headers)?))
}
async fn one(State(st): State<AppState>, headers: HeaderMap, Path((id, fid)): Path<(String, String)>) -> Result<Json<Finding>, ApiError> {
    Ok(Json(st.finding(&headers, &id, &fid)?))
}
async fn review(State(st): State<AppState>, headers: HeaderMap, Path((id, fid)): Path<(String, String)>, Json(body): Json<ReviewRequest>) -> Result<Json<Finding>, ApiError> {
    Ok(Json(st.review(&headers, &id, &fid, body)?))
}
async fn job(State(st): State<AppState>, headers: HeaderMap, Path(job_id): Path<String>) -> Result<Json<ReviewJob>, ApiError> {
    Ok(Json(st.review_job(&headers, &job_id)?))
}
async fn poc(State(st): State<AppState>, headers: HeaderMap, Path((id, fid)): Path<(String, String)>) -> Result<Json<Poc>, ApiError> {
    Ok(Json(st.poc(&headers, &id, &fid)?))
}
async fn retest(State(st): State<AppState>, headers: HeaderMap, Path((id, fid)): Path<(String, String)>) -> Result<Json<RetestResult>, ApiError> {
    Ok(Json(st.retest(&headers, &id, &fid)?))
}
async fn report(State(st): State<AppState>, headers: HeaderMap, Path((id, fid)): Path<(String, String)>) -> Result<Json<ReportBody>, ApiError> {
    let row = st.finding(&headers, &id, &fid)?;
    Ok(Json(ReportBody { format: "md".into(), body: format!("# {}\n", row.title) }))
}
