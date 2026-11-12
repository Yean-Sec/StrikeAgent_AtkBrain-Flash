use std::collections::HashMap;
use std::path::PathBuf;

use atkbrain_core::config::Settings;
use atkbrain_core::console_auth::encrypt_password_blob_current;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

fn settings(dir: &std::path::Path) -> Settings {
    let mut env = HashMap::new();
    env.insert("ATKBRAIN_SECURITY_ENTRY".into(), "off".into());
    env.insert("ATKBRAIN_FORCE_HTTPS".into(), "false".into());
    env.insert("ATKBRAIN_ADMIN_PASSWORD".into(), "admin".into());
    env.insert("ATKBRAIN_DATA_DIR".into(), dir.display().to_string());
    env.insert("ATKBRAIN_DB_PATH".into(), dir.join("t.db").display().to_string());
    let mut settings = Settings::from_map(&env, PathBuf::from("/tmp/no-such-repo").as_path());
    settings.data_dir = dir.to_path_buf();
    settings.db_path = dir.join("t.db");
    settings.workspaces_dir = dir.join("workspaces");
    settings.loot_dir = dir.join("loot");
    settings.reports_dir = dir.join("reports");
    settings
}

#[tokio::test]
async fn login_then_list_projects() {
    let dir = std::env::temp_dir().join(format!("atk-http-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state = atkbrain_api::sqlite_http::open_state(settings(&dir)).unwrap();
    let app = atkbrain_api::sqlite_http::router(state.clone());
    let denied = app
        .clone()
        .oneshot(Request::builder().uri("/api/projects").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let app = atkbrain_api::sqlite_http::router(state.clone());
    let res = app
        .oneshot(Request::builder().uri("/api/auth/pubkey").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let pubkey: Value = serde_json::from_slice(&body).unwrap();
    let ticket = pubkey.get("ticket").and_then(Value::as_str).unwrap();
    let cipher = encrypt_password_blob_current(&dir, "admin", ticket, None, None).unwrap();
    let payload = serde_json::json!({"username": "admin", "ticket": ticket, "password_cipher": cipher});
    let app = atkbrain_api::sqlite_http::router(state);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let set_cookie = res.headers().get("set-cookie").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(set_cookie.contains("atkbrain_session="));
    let _ = std::fs::remove_dir_all(&dir);
}
