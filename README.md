# GitHub OAuth for Suprnova

`suprnova-oauth-github` is an external GitHub OAuth provider plugin for Suprnova. It uses only the public API exported by `suprnova` v1.3.2. It doesn't depend directly on `suprnova-magnetar`, use a Suprnova workspace path, or access framework internals.

The plugin provides:

- GitHub OAuth App authorization-code sign-in with Suprnova-managed state and PKCE.
- GitHub's required REST headers, including `User-Agent`, `Accept`, and `X-GitHub-Api-Version`.
- A transport adapter that fetches both `GET /user` and `GET /user/emails`.
- Identity mapping by GitHub's stable numeric user ID.
- Verified-email handling that accepts only a verified primary GitHub address.
- GitHub grant revocation with HTTP Basic client authentication and a JSON request body.
- GitHub.com defaults and validated endpoint overrides for tests and compatible GitHub Enterprise Server installations.

## How identity verification works

GitHub's `GET /user` response includes `email` only when the user made that address public. Public visibility does not prove that the address is verified.

This plugin requests the `user:email` scope and calls `GET /user/emails`. It accepts an address only when GitHub returns both `primary: true` and `verified: true`. It ignores the `email` field from `GET /user` and doesn't fall back to a secondary address.

Suprnova keeps `OAuthProvider::resolve_identity` free of network I/O. `GitHubOAuthTransport` therefore wraps Suprnova's public `ReqwestOAuthTransport`, performs the two GitHub REST requests, and passes one combined response to `GitHubOAuthProvider`.

The implementation follows GitHub's current public contracts:

- [Authorizing OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [Get the authenticated user](https://docs.github.com/en/rest/users/users?apiVersion=2026-03-10#get-the-authenticated-user)
- [List email addresses for the authenticated user](https://docs.github.com/en/rest/users/emails?apiVersion=2026-03-10#list-email-addresses-for-the-authenticated-user)
- [Delete an app authorization](https://docs.github.com/en/rest/apps/oauth-applications?apiVersion=2026-03-10#delete-an-app-authorization)

## Requirements

You need:

- Rust 1.94.0 or later.
- Suprnova v1.3.2.
- A GitHub OAuth App.
- `SessionMiddleware` on the OAuth start and callback routes.
- A configured Suprnova `RateLimiterDriver`. Production deployments normally use the shared Redis driver.

## Create a GitHub OAuth App

1. Open [GitHub Developer settings](https://github.com/settings/developers).
2. Select **OAuth Apps**.
3. Select **New OAuth App**.
4. Enter your application's public URL as the **Homepage URL**.
5. Enter your callback route as the **Authorization callback URL**. For example:

   ```text
   https://app.example.com/auth/github/callback
   ```

6. Create the app and generate a client secret.
7. Store the client ID and client secret in your deployment's secret manager.

Use a separate OAuth App for each environment when the environments have different callback URLs.

## Add the dependencies

Add Suprnova, this plugin, and `secrecy` to your application's `Cargo.toml`:

```toml
[dependencies]
suprnova = { git = "https://github.com/eas4ai/suprnova.git", tag = "v1.3.2" }
suprnova-oauth-github = { git = "https://github.com/eas4ai/suprnova-oauth-github.git", tag = "v0.1.0" }
url = "2"
```

The plugin uses `suprnova::SecretString`, so your application doesn't need a
direct Magnetar dependency. The controller uses `url` to decode callback query
parameters.

## Configure the environment

Set these values through your deployment's secret and configuration system:

```dotenv
GITHUB_OAUTH_CLIENT_ID=your_github_oauth_client_id
GITHUB_OAUTH_CLIENT_SECRET=your_github_oauth_client_secret
GITHUB_OAUTH_REDIRECT_URI=https://app.example.com/auth/github/callback
GITHUB_OAUTH_USER_AGENT=example-app/1.0 (security@example.com)
```

GitHub requires a `User-Agent` on REST requests. Use a stable product identifier and a monitored contact address. Don't put credentials in the value.

## Register the provider

Register GitHub on the same `MagnetarConfig` that initializes the rest of authentication. Suprnova publishes the password, passkey, and OAuth engines atomically.

```rust
use std::env;
use std::sync::Arc;

use suprnova::{
    App, AutoLinkPolicy, DB, FrameworkAbuseLimiter, FrameworkError,
    MagnetarConfig, MagnetarOAuthHostConfig, MagnetarOAuthProviderConfig,
    OAuthAuthorizationConfig, OAuthHttpTransport, RateLimiterDriver,
    ReqwestOAuthTransport, SecretString, init_magnetar,
};
use suprnova_oauth_github::{
    GitHubEndpoints, GitHubOAuthProvider, GitHubOAuthTransport,
    GitHubProviderConfig,
};

pub async fn register_github_oauth() -> Result<(), FrameworkError> {
    let client_id = required_env("GITHUB_OAUTH_CLIENT_ID")?;
    let client_secret = required_env("GITHUB_OAUTH_CLIENT_SECRET")?;
    let redirect_uri = required_env("GITHUB_OAUTH_REDIRECT_URI")?;
    let user_agent = required_env("GITHUB_OAUTH_USER_AGENT")?;
    let endpoints = GitHubEndpoints::default();

    let base: Arc<dyn OAuthHttpTransport> =
        Arc::new(ReqwestOAuthTransport::try_default()?);
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
    let limiter = Arc::new(FrameworkAbuseLimiter::new(
        App::resolve_make::<dyn RateLimiterDriver>()?,
    ));
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
    .map_err(|_| {
        FrameworkError::internal("invalid GitHub OAuth host configuration")
    })?;

    let database = DB::connection()?;
    init_magnetar(
        MagnetarConfig::from_sea_orm(database.inner().clone()).oauth(oauth),
    )
    .await
}

fn required_env(name: &'static str) -> Result<String, FrameworkError> {
    env::var(name)
        .map_err(|_| FrameworkError::internal(format!("{name} is not set")))
}
```

Call `register_github_oauth().await` during application bootstrap after the database, encryption key, session store, and rate limiter driver are registered. Call `init_magnetar` only once.

`ReqwestOAuthTransport::try_default()` disables redirects, applies a 30-second timeout, limits responses to 1 MiB, and supplies a default Suprnova `User-Agent`. The provider-specific value in `GITHUB_OAUTH_USER_AGENT` replaces that default on GitHub REST requests.

## Add the routes

Add a start route and a callback route:

```rust
get!("/auth/github", controllers::github_oauth::start),
get!(
    "/auth/github/callback",
    controllers::github_oauth::callback
),
```

Apply `SessionMiddleware` to both routes. Suprnova binds the OAuth ceremony to the initiating session, so the callback must use the same browser session and session cookie.

## Add the controller

Create `src/controllers/github_oauth.rs`:

```rust
use std::collections::HashMap;

use suprnova::{
    Auth, FrameworkError, HttpResponse, Request, Response,
};

pub async fn start(_request: Request) -> Response {
    start_inner().await.map_err(HttpResponse::from)
}

async fn start_inner() -> Result<HttpResponse, FrameworkError> {
    let kickoff = Auth::oauth("github").begin().await?;

    Ok(HttpResponse::new()
        .status(302)
        .header("Location", kickoff.authorization_url))
}

pub async fn callback(request: Request) -> Response {
    callback_inner(request).await.map_err(HttpResponse::from)
}

async fn callback_inner(
    request: Request,
) -> Result<HttpResponse, FrameworkError> {
    let params = query_parameters(&request);
    if params.contains_key("error") {
        return Err(FrameworkError::bad_request(
            "GitHub authorization was denied",
        ));
    }

    let code = params
        .get("code")
        .ok_or_else(|| {
            FrameworkError::bad_request("missing GitHub OAuth code")
        })?;
    let state = params
        .get("state")
        .ok_or_else(|| {
            FrameworkError::bad_request("missing GitHub OAuth state")
        })?;

    let (_user, _session) = Auth::oauth("github")
        .complete(code, state)
        .await?;

    Ok(HttpResponse::new().status(302).header("Location", "/"))
}

fn query_parameters(request: &Request) -> HashMap<String, String> {
    url::form_urlencoded::parse(
        request.query().unwrap_or("").as_bytes(),
    )
    .into_owned()
    .collect()
}
```

The repository's [`examples/suprnova_app.rs`](examples/suprnova_app.rs) file contains the bootstrap and controller code in one file. The example is compiled by the project checks.

## Test the sign-in flow

1. Start the application with the four `GITHUB_OAUTH_*` values set.
2. Open `/auth/github` in a browser.
3. Approve the `user:email` permission on GitHub.
4. Confirm that GitHub returns to the exact callback URL configured in the OAuth App.
5. Confirm that the callback creates or resolves the Suprnova account and redirects to `/`.
6. Sign out and repeat the flow to confirm that Suprnova resolves the same linked account by GitHub's numeric user ID.

Do not test by sending a callback `code` without first starting the flow in the same browser session. State and PKCE validation are intentionally session-bound.

## Handle an unavailable verified primary email

When GitHub doesn't return exactly one verified primary address, the plugin returns `email: None`. It never treats a public, unverified, or secondary address as proof of account ownership.

In this case, `Auth::oauth("github").complete(...)` returns an HTTP `409 Conflict` response with the message `OAuth identity requires verified email completion`. A basic application can ask the user to verify a primary email in GitHub and restart sign-in. If your application implements a separate verified-email completion or explicit account-linking flow, route the conflict into that flow instead of weakening the provider's email policy.

## Configure GitHub Enterprise Server

For GitHub Enterprise Server, provide explicit endpoints:

```rust
let endpoints = GitHubEndpoints {
    authorization: "https://github.example.com/login/oauth/authorize".into(),
    token: "https://github.example.com/login/oauth/access_token".into(),
    user: "https://github.example.com/api/v3/user".into(),
    emails: "https://github.example.com/api/v3/user/emails?per_page=100".into(),
    revocation: concat!(
        "https://github.example.com/api/v3/applications/",
        "{client_id}/grant",
    )
    .into(),
};
```

The plugin requires HTTPS for non-loopback endpoints. The `user` and `emails` endpoints must have the same origin because the transport forwards the same bearer token to both endpoints. Loopback HTTP is accepted only for local integration tests.

Verify that your GitHub Enterprise Server version supports PKCE and the configured REST API version before deployment. If the server requires a different REST API version, use a plugin release that explicitly supports that server rather than removing the version header at runtime.

## Revoke GitHub access

Suprnova calls the provider's `revoke` method with an access token when it needs to revoke the GitHub grant. The plugin sends:

```text
DELETE /applications/{client_id}/grant
Authorization: Basic base64(client_id:client_secret)
Accept: application/vnd.github+json
X-GitHub-Api-Version: 2026-03-10
Content-Type: application/json

{"access_token":"..."}
```

GitHub deletes the application grant and all OAuth tokens associated with that user. The plugin doesn't enable GitHub's optional expiring-token and refresh-token mode in v0.1.0.

## Security properties

The plugin preserves these boundaries:

- Suprnova generates and validates OAuth state and PKCE values.
- The provider never performs network I/O inside `resolve_identity`.
- Suprnova owns the bearer `Authorization` header for userinfo requests.
- The transport forwards that bearer only between validated same-origin user and email endpoints.
- Provider and protocol errors don't format response bodies, access tokens, or client secrets.
- The numeric GitHub `id`, not the mutable `login`, is the external subject.
- Public and secondary email addresses don't trigger account linking.
- Redirects remain disabled in the default production transport.

Don't log callback codes, access tokens, refresh tokens, client secrets, combined userinfo bodies, or authorization headers.

## Run the plugin checks

The repository test suite uses an in-process mock GitHub server. It doesn't contact GitHub.com.

```bash
cargo fmt --all --check
cargo clippy --all-targets
cargo test --all-targets
cargo check --example suprnova_app
```

The `public_sdk_firewall` test verifies that the manifest uses the public Suprnova `v1.3.2` Git tag, has no path dependency, and has no direct Magnetar dependency or import.

## License

This project is available under the MIT License.
