use axum::response::{IntoResponse, Response};
use http::StatusCode;


#[derive(Debug)]
pub enum AppError{
    Other(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("app error: {:#?}", self);
        match self {
            AppError::Other(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("err: {e}"))
                .into_response(),
        }
    }
}
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(e: E) -> Self {
        AppError::Other(e.into())
    }
}

