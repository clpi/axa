use anyhow::{Context, Result};
use async_session::{MemoryStore, Session, SessionStore};
use axa::{
    models::user,
    state::{discord_auth, oauth_client, AppState},
};
use axum::{
    async_trait,
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
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn init_sub() -> () {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_oauth=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[tokio::main]
async fn main() {
    init_sub();
    let store = MemoryStore::new();
    let oauth_client = oauth_client().unwrap();
    let app_state = AppState {
        store,
        oauth_client,
    };
    let app = Router::new()
        .route("/", get(user::index))
        .route("/auth/discord", get(discord_auth))
        .route("/protected/", get(user::protected))
        .route("/logout", get(user::logout))
        .with_state(app_state);
    let lstnr = tokio::net::TcpListener::bind("127.0.0.1:3003")
        .await
        .context("failed to bind tcp listener")
        .unwrap();
    let ldisplay = lstnr
        .local_addr()
        .context("failed to return local addr")
        .unwrap();
    tracing::debug!("listening on {}", ldisplay);
    axum::serve(lstnr, app).await.unwrap();
}
