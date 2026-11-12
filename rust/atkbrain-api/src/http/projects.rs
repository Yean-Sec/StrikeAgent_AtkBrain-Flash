use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use axum::{Json, Router};

use crate::dto::*;
use crate::error::ApiError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/projects", get(list).post(create))
        .route("/api/projects/batch_delete", post(batch_delete))
        .route("/api/projects/batch_start", post(batch_start))
        .route("/api/projects/batch_stop", post(batch_stop))
        .route("/api/projects/archive", post(archive_many))
        .route("/api/projects/assets/preview", post(preview))
        .route("/api/projects/from-template", post(from_template))
        .route("/api/project-templates", get(templates))
        .route("/api/projects/{id}", get(one).patch(patch_one).delete(delete_one))
        .route("/api/projects/{id}/output_lang", patch(lang))
        .route("/api/projects/{id}/start", post(start))
        .route("/api/projects/{id}/stop", post(stop))
        .route("/api/projects/{id}/start_all", post(start_all))
        .route("/api/projects/{id}/stop_all", post(stop_all))
        .route("/api/projects/{id}/steer", post(steer))
        .route("/api/projects/{id}/graph", get(graph))
        .route("/api/projects/{id}/events", get(events))
        .route("/api/projects/{id}/runs", get(runs))
        .route("/api/projects/{id}/memory", get(memory))
        .route("/api/projects/{id}/flags", get(flags))
        .route("/api/projects/{id}/subprojects", get(subs))
        .route("/api/projects/{id}/import_progress", get(progress))
        .route("/api/projects/{id}/benchmark/scoreboard", get(scoreboard))
        .route("/api/projects/{id}/benchmark/import", post(import_bench))
        .route("/api/projects/{id}/report", get(report))
        .route("/api/projects/{id}/report/export", post(export))
        .route("/api/projects/{id}/report/export/{job_id}", get(export_status))
        .route("/api/projects/{id}/report/export/{job_id}/file", get(export_file))
        .route("/api/projects/{id}/triage", post(triage))
        .route("/api/projects/{id}/refold_machines", post(refold))
        .route("/api/projects/{id}/import_pause", post(pause))
        .route("/api/projects/{id}/import_resume", post(resume))
        .route("/api/projects/{id}/assets", post(assets))
        .route("/api/projects/{id}/challenge-files", post(files))
        .route("/api/projects/{id}/archive", post(archive_one))
        .route("/api/projects/{id}/template", post(template))
        .route("/api/projects/{id}/intents/{iid}/pause", post(intent_pause))
        .route("/api/projects/{id}/intents/{iid}/steer", post(intent_steer))
        .route("/api/projects/{id}/commands/{cid}", post(command))
        .route("/api/projects/{id}/ws", get(ws))
}

async fn list(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<Project>>, ApiError> {
    Ok(Json(st.list_projects(&headers)?))
}
async fn create(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<CreateProject>) -> Result<Json<Project>, ApiError> {
    Ok(Json(st.create_project(&headers, body)?))
}
async fn one(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<Project>, ApiError> {
    Ok(Json(st.project(&headers, &id)?))
}
async fn patch_one(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<PatchProject>) -> Result<Json<Project>, ApiError> {
    Ok(Json(st.patch_project(&headers, &id, body)?))
}
async fn delete_one(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<OkBody>, ApiError> {
    Ok(Json(st.delete_project(&headers, &id)?))
}
async fn lang(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<OutputLangRequest>) -> Result<Json<OutputLangResult>, ApiError> {
    Ok(Json(st.set_lang(&headers, &id, body)?))
}
async fn batch_delete(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<IdsRequest>) -> Result<Json<IdsResult>, ApiError> {
    Ok(Json(st.batch(&headers, body.ids, "delete", false)?))
}
async fn batch_start(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<IdsRequest>) -> Result<Json<IdsResult>, ApiError> {
    Ok(Json(st.batch(&headers, body.ids, "start", body.confirm_restart)?))
}
async fn batch_stop(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<IdsRequest>) -> Result<Json<IdsResult>, ApiError> {
    Ok(Json(st.batch(&headers, body.ids, "stop", false)?))
}
async fn start(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<ConfirmQuery>) -> Result<Json<StatusResult>, ApiError> {
    Ok(Json(st.start(&headers, &id, q.confirm_restart)?))
}
async fn stop(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<StatusResult>, ApiError> {
    Ok(Json(st.stop(&headers, &id)?))
}
async fn start_all(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<ConfirmQuery>) -> Result<Json<StatusResult>, ApiError> {
    let _ = q.unfinished_only;
    Ok(Json(st.start(&headers, &id, q.confirm_restart)?))
}
async fn stop_all(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<StatusResult>, ApiError> {
    Ok(Json(st.stop(&headers, &id)?))
}
async fn steer(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<SteerRequest>) -> Result<Json<OkBody>, ApiError> {
    Ok(Json(st.steer(&headers, &id, body)?))
}
async fn graph(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<Graph>, ApiError> {
    Ok(Json(st.graph(&headers, &id)?))
}
async fn events(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<AfterQuery>) -> Result<Json<Vec<RtEvent>>, ApiError> {
    Ok(Json(st.events(&headers, &id, q.after.unwrap_or(0.0))?))
}
async fn runs(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    Ok(Json(st.runs(&headers, &id)?))
}
async fn memory(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<Memory>, ApiError> {
    Ok(Json(st.memory(&headers, &id)?))
}
async fn flags(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    Ok(Json(st.flags(&headers, &id)?))
}
async fn subs(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<Vec<Project>>, ApiError> {
    Ok(Json(st.subprojects(&headers, &id)?))
}
async fn progress(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<ImportProgress>, ApiError> {
    Ok(Json(st.import_progress(&headers, &id)?))
}
async fn scoreboard(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<Scoreboard>, ApiError> {
    Ok(Json(st.scoreboard(&headers, &id)?))
}
async fn import_bench(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<OkBody>, ApiError> {
    Ok(Json(st.simple(&headers, &id)?))
}
async fn report(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<FormatQuery>) -> Result<Json<ReportBody>, ApiError> {
    Ok(Json(st.report(&headers, &id, q.format.unwrap_or_else(|| "md".into()))?))
}
async fn export(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<ExportJob>, ApiError> {
    Ok(Json(st.export(&headers, &id)?))
}
async fn export_status(State(st): State<AppState>, headers: HeaderMap, Path((id, job_id)): Path<(String, String)>) -> Result<Json<ExportJob>, ApiError> {
    Ok(Json(st.export_status(&headers, &id, &job_id)?))
}
async fn export_file(State(st): State<AppState>, headers: HeaderMap, Path((id, job_id)): Path<(String, String)>) -> Result<String, ApiError> {
    Ok(st.export_file(&headers, &id, &job_id)?)
}
async fn triage(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<OkBody>, ApiError> {
    Ok(Json(st.simple(&headers, &id)?))
}
async fn refold(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<OkBody>, ApiError> {
    Ok(Json(st.simple(&headers, &id)?))
}
async fn pause(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<OkBody>, ApiError> {
    Ok(Json(st.simple(&headers, &id)?))
}
async fn resume(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<OkBody>, ApiError> {
    Ok(Json(st.simple(&headers, &id)?))
}
async fn assets(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<AssetPreviewRequest>) -> Result<Json<FilesResult>, ApiError> {
    Ok(Json(st.add_assets(&headers, &id, body)?))
}
async fn files(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<FilesResult>, ApiError> {
    Ok(Json(st.challenge_files(&headers, &id)?))
}
async fn archive_one(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<ArchiveResult>, ApiError> {
    Ok(Json(st.archive_one(&headers, &id)?))
}
async fn archive_many(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<IdsRequest>) -> Result<Json<ArchiveResult>, ApiError> {
    Ok(Json(st.archive_many(&headers, body.ids)?))
}
async fn template(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<TemplateName>) -> Result<Json<TemplateResult>, ApiError> {
    Ok(Json(st.save_template(&headers, &id, body.name)?))
}
async fn templates(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<Template>>, ApiError> {
    Ok(Json(st.templates(&headers)?))
}
async fn from_template(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<FromTemplate>) -> Result<Json<Project>, ApiError> {
    Ok(Json(st.from_template(&headers, body)?))
}
async fn preview(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<AssetPreviewRequest>) -> Result<Json<AssetPreview>, ApiError> {
    Ok(Json(st.preview(&headers, body)?))
}
async fn intent_pause(State(st): State<AppState>, headers: HeaderMap, Path((id, _iid)): Path<(String, String)>) -> Result<Json<OkBody>, ApiError> {
    Ok(Json(st.intent_cmd(&headers, &id)?))
}
async fn intent_steer(State(st): State<AppState>, headers: HeaderMap, Path((id, _iid)): Path<(String, String)>, Json(body): Json<SteerRequest>) -> Result<Json<OkBody>, ApiError> {
    if body.message.trim().is_empty() { return Err(ApiError::invalid("消息不能为空")); }
    Ok(Json(st.intent_cmd(&headers, &id)?))
}
async fn command(State(st): State<AppState>, headers: HeaderMap, Path((id, _cid)): Path<(String, String)>, Json(body): Json<CommandRequest>) -> Result<Json<OkBody>, ApiError> {
    Ok(Json(st.command(&headers, &id, body.allow)?))
}

async fn ws(State(st): State<AppState>, headers: HeaderMap, Path(_id): Path<String>, upgrade: WebSocketUpgrade) -> Result<impl IntoResponse, ApiError> {
    st.ready(&headers)?;
    Ok(upgrade.on_upgrade(|_socket| async {}))
}

#[derive(serde::Deserialize)]
pub struct AfterQuery {
    pub after: Option<f64>,
}
#[derive(serde::Deserialize)]
pub struct FormatQuery {
    pub format: Option<String>,
}
