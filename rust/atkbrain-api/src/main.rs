use atkbrain_api::state::AppState;
use atkbrain_api::{app, tasks};

#[tokio::main]
async fn main() {
    let state = AppState::new();
    tasks::spawn(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:2333").await.expect("bind");
    axum::serve(listener, app(state)).await.expect("serve");
}
