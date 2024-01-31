use anyhow::{Context, Result};
use async_session::{async_trait, MemoryStore, Session, SessionStore};
use axum::{
    extract::{FromRef, FromRequestParts, Query, State},
    http::{header::SET_COOKIE, HeaderMap},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    RequestPartsExt, Router,
};
use axum_extra::{headers, typed_header::TypedHeaderRejectionReason, TypedHeader};
use http::{header, request::Parts, StatusCode};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::env;

use crate::error::AppError;

pub static COOKIE_NAME: &str = "auth";

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub avatar: Option<String>,
    pub discriminator: String,
}
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub code: String,
    pub state: String,
}
pub struct AuthRedirect;
impl IntoResponse for AuthRedirect {
    fn into_response(self) -> axum::response::Response {
        Redirect::temporary("/auth/discord").into_response()
    }
}
#[async_trait]
impl<S> FromRequestParts<S> for User
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = MemoryStore::from_ref(state);
        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect,
                    _ => panic!("unexpected error getting cookie headers {:#?}", e),
                },
                _ => panic!("unexpected error getting cookies {:#?}", e),
            })?;
        let sess_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;
        let sess = store
            .load_session(sess_cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect)?;
        let u = sess.get::<User>("user").ok_or(AuthRedirect)?;
        Ok(u)
    }
}

pub async fn index(user: Option<User>) -> impl IntoResponse {
    match user {
        Some(u) => format!(
            "Hey {}! You're logged in!\nYou may now access `/protected`.\nLog out with `/logout`.",
            u.username
        ),
        None => String::from("You're not logged in.\nVisit `/auth/discord` to do so."),
    }
}

pub async fn protected(user: User) -> impl IntoResponse {
    format!("Welcome to the protected area {user:?}!\n")
}

pub async fn logout(
    State(store): State<MemoryStore>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoResponse, AppError> {
    let cookie = cookies
        .get(COOKIE_NAME)
        .context("unexpected err getting cookie name")?;
    let sess = match store
        .load_session(cookie.to_string())
        .await
        .context("failed to load session")?
    {
        Some(s) => s,
        None => return Ok(Redirect::to("/")),
    };
    store
        .destroy_session(sess)
        .await
        .context("failed to destroy session")?;
    Ok(Redirect::to("/"))
}
