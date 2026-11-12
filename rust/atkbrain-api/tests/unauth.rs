use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn start_without_cookie_is_401() {
    let app = atkbrain_api::app(atkbrain_api::state::AppState::new());
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/projects/p1/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
