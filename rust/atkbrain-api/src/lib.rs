pub mod auth;
pub mod dto;
pub mod error;
pub mod http;
pub mod sqlite_http;
pub mod state;
pub mod tasks;

use crate::state::AppState;

pub fn app(state: AppState) -> axum::Router {
    http::router(state)
}
