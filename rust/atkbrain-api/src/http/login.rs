use axum::extract::State;
use axum::http::{header::SET_COOKIE, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::dto::*;
use crate::error::ApiError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/me", get(me))
        .route("/api/auth/pubkey", get(pubkey))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/password", post(password))
        .route("/api/auth/totp/setup", get(totp_setup))
        .route("/api/auth/totp/confirm", post(totp_confirm))
}

pub async fn health() -> Json<Health> {
    Json(Health { ok: true })
}

async fn me(State(st): State<AppState>, headers: HeaderMap) -> Json<AuthMe> {
    Json(st.me(&headers))
}

async fn pubkey(State(st): State<AppState>) -> Json<Pubkey> {
    Json(st.pubkey())
}

async fn login(State(st): State<AppState>, Json(body): Json<LoginRequest>) -> Result<Response, ApiError> {
    let (body, cookie) = st.login(&body)?;
    let mut res = (StatusCode::OK, Json(body)).into_response();
    if !cookie.is_empty() {
        if let Ok(value) = cookie.parse() {
            res.headers_mut().insert(SET_COOKIE, value);
        }
    }
    Ok(res)
}

async fn logout(State(st): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let cookie = st.logout(&headers)?;
    let mut res = Json(OkBody { ok: true }).into_response();
    if let Ok(value) = cookie.parse() {
        res.headers_mut().insert(SET_COOKIE, value);
    }
    Ok(res)
}

async fn password(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<PasswordRequest>) -> Result<Json<PasswordResult>, ApiError> {
    Ok(Json(st.change_password(&headers, &body)?))
}

async fn totp_setup(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<TotpSetup>, ApiError> {
    Ok(Json(st.totp_setup(&headers)?))
}

async fn totp_confirm(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<TotpConfirmRequest>) -> Result<Json<TotpConfirmResult>, ApiError> {
    Ok(Json(st.totp_confirm(&headers, &body)?))
}
