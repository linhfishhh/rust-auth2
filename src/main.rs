use std::{collections::HashMap, env};

use anyhow::{Context, Error, Ok, Result};
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use http::{uri::Port, StatusCode};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use tracing::debug;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Deserialize, Serialize)]
struct GithubTokenResponse {
    accessToken: String,
    refreshToken: Option<String>,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_oauth=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let auth_client = github_auth_client().unwrap();

    let app = Router::new()
        .route("/github/auth", get(github_auth))
        .route("/github/authorized", get(authorized))
        .with_state(auth_client);

    let host = env::var("HOST").unwrap();

    let port = env::var("PORT").unwrap();

    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}"))
        .await
        .context("failed to bind TcpListener")
        .unwrap();

    debug!("server listening on {}:{}", host, port);

    axum::serve(listener, app).await.unwrap();
}

fn github_auth_client() -> Result<BasicClient, anyhow::Error> {
    let github_client_id = env::var("GITHUB_CLIENT_ID").expect("github client id not configured");

    let github_client_secret =
        env::var("GITHUB_CLIENT_SECRET").expect("github client secret not configured");

    let github_auth_url = env::var("GITHUB_AUTH_URL").expect("github auth url not configured");

    let github_token_url = env::var("GITHUB_TOKEN_URL").expect("github token url not configured");

    let redirect_url = env::var("REDIRECT_URL").expect("redirect url not configured");

    Ok(BasicClient::new(
        ClientId::new(github_client_id),
        Some(ClientSecret::new(github_client_secret)),
        AuthUrl::new(github_auth_url).context("failed to create new authorization server url")?,
        Some(TokenUrl::new(github_token_url).context("fail to craete new token url")?),
    )
    .set_redirect_uri(
        RedirectUrl::new(redirect_url).context("failed to cretate new redirect url")?,
    ))
}

async fn github_auth(State(client): State<BasicClient>) -> impl IntoResponse {
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("public_repo".to_string()))
        .add_scope(Scope::new("user:email".to_string()))
        .url();

    Redirect::to(auth_url.as_ref())
}

async fn authorized(
    Query(query): Query<HashMap<String, String>>,
    State(client): State<BasicClient>,
) -> (StatusCode, impl IntoResponse) {
    let code = query.get("code").unwrap().to_string();
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await
        .context("failed to get token")
        .unwrap();
    (
        StatusCode::OK,
        Json(GithubTokenResponse {
            accessToken: token.access_token().secret().to_string(),
            refreshToken: None,
        }),
    )
}
