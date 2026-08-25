use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use suprnova::{
    App, Auth, AutoLinkPolicy, DB, FrameworkAbuseLimiter, FrameworkError, HttpResponse,
    MagnetarConfig, MagnetarOAuthHostConfig, MagnetarOAuthProviderConfig, OAuthAuthorizationConfig,
    OAuthHttpTransport, RateLimiterDriver, Request, ReqwestOAuthTransport, Response, SecretString,
    init_magnetar,
};
use suprnova_oauth_github::{
    GitHubEndpoints, GitHubOAuthProvider, GitHubOAuthTransport, GitHubProviderConfig,
};

/// Register GitHub OAuth during application bootstrap.
pub async fn register_github_oauth() -> Result<(), FrameworkError> {
    let client_id = required_env("GITHUB_OAUTH_CLIENT_ID")?;
    let client_secret = required_env("GITHUB_OAUTH_CLIENT_SECRET")?;
    let redirect_uri = required_env("GITHUB_OAUTH_REDIRECT_URI")?;
    let user_agent = required_env("GITHUB_OAUTH_USER_AGENT")?;
    let endpoints = GitHubEndpoints::default();

    let base: Arc<dyn OAuthHttpTransport> = Arc::new(ReqwestOAuthTransport::try_default()?);
    let transport = Arc::new(
        GitHubOAuthTransport::try_new(base, endpoints.clone())
            .map_err(|error| FrameworkError::internal(error.to_string()))?,
    );
    let provider = Arc::new(
        GitHubOAuthProvider::try_new(
            GitHubProviderConfig {
                client_id,
                client_secret: SecretString::from(client_secret),
                user_agent,
                endpoints,
            },
            transport.clone(),
        )
        .map_err(|error| FrameworkError::internal(error.to_string()))?,
    );
    let limiter = Arc::new(FrameworkAbuseLimiter::new(App::resolve_make::<
        dyn RateLimiterDriver,
    >()?));
    let oauth = MagnetarOAuthHostConfig::new(
        vec![MagnetarOAuthProviderConfig {
            provider,
            redirect_uri,
            scopes: vec!["user:email".to_owned()],
        }],
        transport,
        limiter,
        OAuthAuthorizationConfig::default(),
        AutoLinkPolicy::default(),
    )
    .map_err(|_| FrameworkError::internal("invalid GitHub OAuth host configuration"))?;

    let database = DB::connection()?;
    init_magnetar(MagnetarConfig::from_sea_orm(database.inner().clone()).oauth(oauth)).await
}

/// Redirect the browser to GitHub.
pub async fn start(_request: Request) -> Response {
    start_inner().await.map_err(HttpResponse::from)
}

async fn start_inner() -> Result<HttpResponse, FrameworkError> {
    let kickoff = Auth::oauth("github").begin().await?;
    Ok(HttpResponse::new()
        .status(302)
        .header("Location", kickoff.authorization_url))
}

/// Complete GitHub's authorization-code callback.
pub async fn callback(request: Request) -> Response {
    callback_inner(request).await.map_err(HttpResponse::from)
}

async fn callback_inner(request: Request) -> Result<HttpResponse, FrameworkError> {
    let params = query_parameters(&request);
    if params.contains_key("error") {
        return Err(FrameworkError::bad_request(
            "GitHub authorization was denied",
        ));
    }
    let code = params
        .get("code")
        .ok_or_else(|| FrameworkError::bad_request("missing GitHub OAuth code"))?;
    let state = params
        .get("state")
        .ok_or_else(|| FrameworkError::bad_request("missing GitHub OAuth state"))?;

    let (_user, _session) = Auth::oauth("github").complete(code, state).await?;
    Ok(HttpResponse::new().status(302).header("Location", "/"))
}

fn query_parameters(request: &Request) -> HashMap<String, String> {
    url::form_urlencoded::parse(request.query().unwrap_or("").as_bytes())
        .into_owned()
        .collect()
}

fn required_env(name: &'static str) -> Result<String, FrameworkError> {
    env::var(name).map_err(|_| FrameworkError::internal(format!("{name} is not set")))
}

fn main() {}
