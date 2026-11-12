use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::dto::{ErrorBody, ErrorInfo};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "未登录")
    }
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "必须先修改口令")
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid", message)
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "不存在")
    }
    pub fn conflict() -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", "状态不允许这次流转")
    }
    pub fn locked() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "locked", "登录已暂时锁定")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorInfo { code: self.code.to_string(), message: self.message },
        };
        (self.status, Json(body)).into_response()
    }
}
