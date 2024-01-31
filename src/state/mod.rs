pub mod auth;

use anyhow::Context;
use async_session::MemoryStore;
use axum::{extract::{FromRef, State}, response::{IntoResponse, Redirect}};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl};
use std::env::{self, VarError};

use crate::error::AppError;

#[derive(Clone, Debug)]
pub struct AppState {
    pub store: MemoryStore,
    pub oauth_client: BasicClient,
}
impl FromRef<AppState> for MemoryStore {
    fn from_ref(input: &AppState) -> Self {
        input.store.clone()
    }
}
impl FromRef<AppState> for BasicClient {
    fn from_ref(input: &AppState) -> Self {
        input.oauth_client.clone()
    }
}
fn getenv(var: &'static str) -> Result<String, anyhow::Error> {
    env::var(var).context(format!("Missing {var}"))
}
pub fn oauth_client() -> Result<BasicClient, AppError> {
    let clientid = getenv("CLIENT_ID")?;
    let clientsec = getenv("CLIENT_SECRET")?;
    let redirect_url = env::var("REDIRECT_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000/auth/authorized".to_string());
    let auth_url = env::var("AUTH_URL").unwrap_or_else(|_| {
        "https://discord.com/api/oauth/authorize?response_type=code".to_string()
    });
    let tk_url = env::var("TOKEN_URL")
        .unwrap_or_else(|_| "https://discord.com/api/oauth2/token".to_string());
    Ok(BasicClient::new(
        ClientId::new(clientid),
        Some(ClientSecret::new(clientsec)),
        AuthUrl::new(auth_url).context("failed to create new auth server url")?,
        Some(TokenUrl::new(tk_url).context("failed to make new token endpoint url")?),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).context("failed to create new redirect url")?))
}

pub async fn discord_auth(State(client): State<BasicClient>) -> impl IntoResponse {
    let (authurl, _csrftk) = client.authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".into()))
        .url();
    Redirect::to(authurl.as_ref())
}


// Environment variables (* = required):
// *"CLIENT_ID"     "REPLACE_ME";
// *"CLIENT_SECRET" "REPLACE_ME";
//  "REDIRECT_URL"  "http://127.0.0.1:3000/auth/authorized";
//  "AUTH_URL"      "https://discord.com/api/oauth2/authorize?response_type=code";
//  "TOKEN_URL"     "https://discord.com/api/oauth2/token";
