mod findings;
mod login;
mod projects;
mod settings;

use axum::http::{HeaderValue, Method};
use axum::routing::get;
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let app = Router::new()
        .merge(login::routes())
        .merge(settings::routes())
        .merge(projects::routes())
        .merge(findings::routes())
        .route("/api/health", get(login::health))
        .with_state(state);
    if std::env::var("ATKBRAIN_DEV").ok().as_deref() == Some("1") {
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::exact(HeaderValue::from_static("http://localhost:3000")))
            .allow_credentials(true)
            .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
            .allow_headers([axum::http::header::CONTENT_TYPE]);
        app.layer(cors)
    } else {
        app
    }
}
