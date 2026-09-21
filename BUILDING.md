# Build an external OAuth provider for Suprnova

This tutorial builds a GitHub OAuth provider as an ordinary third-party Suprnova developer. The finished crate lives outside the Suprnova workspace, depends on the public `v2.1.0` Git tag, and imports every SDK type through `suprnova::`.

The goal is not to configure an existing provider. The goal is to implement the provider, transport adapter, identity rules, revocation behavior, tests, and downstream registration proof that make a provider safe to publish.

The finished implementation is the [`suprnova-oauth-github`](https://github.com/eas4ai/suprnova-oauth-github) repository. You can follow the same structure for another OAuth provider by replacing GitHub's dossier facts.

## Understand the SDK boundary

A Suprnova OAuth integration has two separate responsibilities:

- `OAuthProvider` contains provider-specific data and pure verification logic. It declares request shapes and endpoints, maps an already-fetched response into a `ProviderIdentity`, and renders a `RevocationRequest`.
- `OAuthHttpTransport` and `RevocationTransport` perform network I/O using host-selected TLS, proxy, timeout, redirect, and observability policy.

`OAuthProvider::resolve_identity` must not perform I/O. Suprnova calls the provider only after the host has fetched the configured user-information response.

That division matters for GitHub. A safe GitHub identity needs both `GET /user` and `GET /user/emails`, while the provider receives one `ProviderResponse`. We will solve that with a transport adapter, not by bypassing the provider contract.

The complete data flow is:

```text
Auth::oauth("github").begin()
    -> GitHubOAuthProvider authorization shape and endpoint
    -> GitHub authorization page
    -> callback code and state
    -> Suprnova token exchange through OAuthHttpTransport
    -> GitHubOAuthTransport fetches /user and /user/emails
    -> GitHubOAuthProvider resolves one combined response
    -> Suprnova identity policy, factor gate, and session issuer
```

## Create a standalone crate

Create the plugin outside the Suprnova repository:

```bash
cargo new --lib suprnova-oauth-github
cd suprnova-oauth-github
git init -b main
```

Use Rust 1.94.0 and edition 2024. The relevant manifest entries are:

```toml
[package]
name = "suprnova-oauth-github"
version = "0.2.2"
edition = "2024"
rust-version = "1.94.0"
license = "MIT"
publish = false

[dependencies]
base64 = "0.22"
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
suprnova = { version = "=2.1.0", git = "https://github.com/eas4ai/suprnova.git", tag = "v2.1.0" }
thiserror = "2"
url = "2"
```

Do not add `suprnova-magnetar`. Do not use a path dependency while developing the plugin. Compiling against the public Git tag is part of the implementation, not a final packaging detail.

The extra dependencies serve narrow roles:

- `secrecy` exposes the client secret only while rendering authenticated requests.
- `base64` renders GitHub's HTTP Basic revocation credentials.
- `serde` and `serde_json` parse GitHub responses and serialize the combined body.
- `url` validates endpoint origins before a bearer token can be forwarded.
- `thiserror` defines configuration errors without leaking configured values.

## Record GitHub's provider dossier

Before writing trait methods, record the provider facts that drive them:

```rust
pub const GITHUB_JSON_MEDIA_TYPE: &str = "application/vnd.github+json";
pub const GITHUB_API_VERSION: &str = "2026-03-10";

const AUTHORIZATION_ENDPOINT: &str =
    "https://github.com/login/oauth/authorize";
const TOKEN_ENDPOINT: &str =
    "https://github.com/login/oauth/access_token";
const USER_ENDPOINT: &str = "https://api.github.com/user";
const EMAILS_ENDPOINT: &str =
    "https://api.github.com/user/emails?per_page=100";
const REVOCATION_ENDPOINT: &str =
    "https://api.github.com/applications/{client_id}/grant";
```

GitHub's contract determines several design choices:

- The authorization-code flow supports and recommends PKCE with `S256`.
- The token endpoint accepts `client_id` and `client_secret` in the request body.
- Asking for `Accept: application/json` avoids GitHub's form-encoded token response.
- GitHub REST requests require a `User-Agent` and should send the recommended media type and API version.
- `/user` does not prove email ownership.
- `/user/emails` requires `user:email` and exposes `primary` and `verified`.
- Grant revocation uses HTTP Basic authentication and a JSON body.

Keep endpoint overrides in a dedicated value so tests can point every request at a loopback server:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubEndpoints {
    pub authorization: String,
    pub token: String,
    pub user: String,
    pub emails: String,
    pub revocation: String,
}
```

The provider configuration owns credentials, the required user agent, and those endpoints:

```rust
#[derive(Clone, Debug)]
pub struct GitHubProviderConfig {
    pub client_id: String,
    pub client_secret: suprnova::SecretString,
    pub user_agent: String,
    pub endpoints: GitHubEndpoints,
}
```

Validate this configuration before the provider enters the registry. Reject empty credentials, HTTP control characters in the user agent, relative URLs, cleartext non-loopback URLs, and a user/email endpoint pair with different origins.

The same-origin check prevents the transport adapter from forwarding GitHub's bearer token to an unrelated host.

## Implement the provider shell

The provider stores its validated configuration and a host-supplied revocation transport:

```rust
use std::sync::Arc;

use suprnova::{OAuthProvider, RevocationTransport};

pub struct GitHubOAuthProvider {
    config: GitHubProviderConfig,
    revocation: Arc<dyn RevocationTransport>,
}

impl GitHubOAuthProvider {
    pub fn try_new(
        config: GitHubProviderConfig,
        revocation: Arc<dyn RevocationTransport>,
    ) -> Result<Self, GitHubConfigError> {
        validate_config(&config)?;
        Ok(Self { config, revocation })
    }
}
```

Use `#[suprnova::async_trait]` on the implementation. The macro is re-exported by the SDK, so the plugin does not need to import a private macro crate.

The endpoint and provider-key methods are direct translations of the dossier:

```rust
#[suprnova::async_trait]
impl OAuthProvider for GitHubOAuthProvider {
    fn name(&self) -> &'static str {
        "github"
    }

    fn client_id(&self) -> &str {
        &self.config.client_id
    }

    fn authorization_endpoint(&self) -> String {
        self.config.endpoints.authorization.clone()
    }

    fn token_endpoint(&self) -> String {
        self.config.endpoints.token.clone()
    }

    fn userinfo_endpoint(&self) -> Option<String> {
        Some(self.config.endpoints.user.clone())
    }

    // Remaining methods follow below.
}
```

The stable provider key becomes the value applications pass to `Auth::oauth("github")`.

## Declare authorization and token request shapes

GitHub uses the SDK defaults for parameter names and scope delimiters. The default authorization shape also requires PKCE:

```rust
fn authorization_shape(&self) -> suprnova::AuthorizationRequestShape {
    suprnova::AuthorizationRequestShape::default()
}

fn token_shape(&self) -> suprnova::TokenRequestShape {
    suprnova::TokenRequestShape::default()
}
```

The client secret belongs in the token request body. Add `Accept: application/json` at the same public seam so Suprnova's token parser receives JSON:

```rust
use secrecy::ExposeSecret;

async fn client_authentication(
    &self,
) -> suprnova::OAuthResult<suprnova::ClientAuthenticationMaterial> {
    Ok(suprnova::ClientAuthenticationMaterial {
        params: vec![(
            "client_secret".to_owned(),
            self.config.client_secret.expose_secret().to_owned(),
        )],
        headers: vec![(
            "Accept".to_owned(),
            "application/json".to_owned(),
        )],
    })
}
```

Version `0.2.2` does not opt into GitHub's optional expiring-token mode, so its refresh policy is explicit:

```rust
fn refresh_policy(&self) -> suprnova::RefreshPolicy {
    suprnova::RefreshPolicy {
        supported: false,
        token_client_authentication:
            suprnova::ClientAuthentication::RequestBody,
        extra_authorization_params: Vec::new(),
        required_scopes: Vec::new(),
        requires_reconsent_for_reissue: false,
        invalid_grant_meaning:
            suprnova::InvalidGrantMeaning::OrdinaryRevocation,
    }
}
```

Do not claim refresh support until the plugin handles GitHub's optional access-token and refresh-token lifecycle end to end.

## Add GitHub's required user-information headers

Suprnova owns the bearer `Authorization` header. The provider contributes only GitHub-specific headers:

```rust
fn userinfo_headers(&self) -> Vec<(String, String)> {
    vec![
        ("User-Agent".to_owned(), self.config.user_agent.clone()),
        (
            "Accept".to_owned(),
            GITHUB_JSON_MEDIA_TYPE.to_owned(),
        ),
        (
            "X-GitHub-Api-Version".to_owned(),
            GITHUB_API_VERSION.to_owned(),
        ),
    ]
}
```

Never add `Authorization` here. The framework rejects a provider that tries to override the host-owned bearer credential.

## Define the combined identity response

The provider must remain I/O-free, but GitHub identity needs two responses. Define a private envelope containing the raw JSON strings returned by the transport adapter:

```rust
#[derive(serde::Deserialize)]
struct CombinedUserInfo {
    user: String,
    emails: String,
}

#[derive(serde::Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
    name: Option<String>,
}

#[derive(serde::Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}
```

The GitHub numeric `id` is the stable subject. Do not use `login`, because a user can rename it.

Resolve the identity by parsing both bodies and selecting only a verified primary address:

```rust
async fn resolve_identity(
    &self,
    response: suprnova::ProviderResponse,
) -> suprnova::OAuthResult<suprnova::ProviderIdentity> {
    let suprnova::ProviderResponse::UserInfo { body } = response else {
        return Err(malformed(
            "GitHub identity resolution requires a UserInfo response",
        ));
    };

    let combined: CombinedUserInfo = serde_json::from_str(&body)
        .map_err(|_| malformed("invalid combined userinfo body"))?;
    let user: GitHubUser = serde_json::from_str(&combined.user)
        .map_err(|_| malformed("invalid /user response"))?;
    let emails: Vec<GitHubEmail> = serde_json::from_str(&combined.emails)
        .map_err(|_| malformed("invalid /user/emails response"))?;

    if user.id == 0 || user.login.trim().is_empty() {
        return Err(malformed("GitHub user identity is incomplete"));
    }

    let mut verified_primary = emails
        .into_iter()
        .filter(|candidate| {
            candidate.primary
                && candidate.verified
                && !candidate.email.trim().is_empty()
        })
        .map(|candidate| candidate.email);
    let email = verified_primary.next();
    if verified_primary.next().is_some() {
        return Err(malformed(
            "multiple verified primary addresses",
        ));
    }

    let email_verified = email.is_some();
    let display_name = user
        .name
        .filter(|name| !name.trim().is_empty())
        .or(Some(user.login));

    Ok(suprnova::ProviderIdentity {
        provider: "github".to_owned(),
        subject: user.id.to_string(),
        email,
        email_verified,
        display_name,
    })
}
```

The production implementation preserves parse details in the private diagnostic field while relying on `OAuthProtocolError`'s redacted `Display` and `Debug` implementations. Do not include response bodies, access tokens, or email values in public error formatting.

Three choices are deliberate:

1. Ignore `/user.email` even when it is present.
2. Do not fall back to a verified secondary address.
3. Fail closed if the response contains more than one verified primary address.

When no verified primary address exists, return `email: None` and `email_verified: false`. Suprnova then chooses its email-completion outcome instead of treating an unproven address as ownership.

## Build the two-request transport adapter

Wrap the host's public transport rather than constructing a second HTTP client:

```rust
#[derive(Clone)]
pub struct GitHubOAuthTransport {
    inner: Arc<dyn suprnova::OAuthHttpTransport>,
    endpoints: GitHubEndpoints,
}

impl GitHubOAuthTransport {
    pub fn try_new(
        inner: Arc<dyn suprnova::OAuthHttpTransport>,
        endpoints: GitHubEndpoints,
    ) -> Result<Self, GitHubConfigError> {
        validate_transport_endpoints(&endpoints)?;
        Ok(Self { inner, endpoints })
    }
}
```

Implement `OAuthHttpTransport::send` with one interception rule:

- If the request is not `GET` to the configured `/user` endpoint, delegate it unchanged. This includes token requests.
- For `/user`, send the original request first.
- If `/user` succeeds, send `GET /user/emails` with the same headers and an empty body.
- Return non-success responses unchanged so Suprnova classifies the provider failure.
- Combine successful UTF-8 bodies into one JSON envelope.

The core implementation looks like this:

```rust
#[derive(serde::Serialize)]
struct CombinedUserInfoRef<'a> {
    user: &'a str,
    emails: &'a str,
}

#[suprnova::async_trait]
impl suprnova::OAuthHttpTransport for GitHubOAuthTransport {
    async fn send(
        &self,
        request: suprnova::OAuthHttpRequest,
    ) -> suprnova::MagnetarResult<suprnova::OAuthHttpResponse> {
        if !request.method.eq_ignore_ascii_case("GET")
            || request.url != self.endpoints.user
        {
            return self.inner.send(request).await;
        }

        let headers = request.headers.clone();
        let user = self.inner.send(request).await?;
        if !(200..300).contains(&user.status) {
            return Ok(user);
        }

        let emails = self.inner.send(suprnova::OAuthHttpRequest {
            method: "GET".to_owned(),
            url: self.endpoints.emails.clone(),
            headers,
            body: Vec::new(),
        }).await?;
        if !(200..300).contains(&emails.status) {
            return Ok(emails);
        }

        let user = String::from_utf8(user.body)
            .map_err(|_| dependency_error("/user was not UTF-8"))?;
        let emails = String::from_utf8(emails.body)
            .map_err(|_| dependency_error("/user/emails was not UTF-8"))?;
        let body = serde_json::to_vec(&CombinedUserInfoRef {
            user: &user,
            emails: &emails,
        })
        .map_err(|_| dependency_error("could not combine userinfo"))?;

        Ok(suprnova::OAuthHttpResponse {
            status: 200,
            headers: vec![(
                "Content-Type".to_owned(),
                "application/json".to_owned(),
            )],
            body,
        })
    }
}
```

The adapter does not parse or trust identity fields. It only combines bounded responses fetched by the host transport. Identity decisions stay in the provider.

## Implement GitHub grant revocation

GitHub does not use a generic RFC 7009 form for this operation. The provider renders:

```text
DELETE /applications/{client_id}/grant
Authorization: Basic base64(client_id:client_secret)
Accept: application/vnd.github+json
X-GitHub-Api-Version: 2026-03-10

access_token=<token>
```

The `OAuthProvider::revoke` method should reject `TokenHint::Refresh`, build the endpoint from the validated client ID, add the Basic header, and hand one `RevocationRequest` to the injected transport.

The public `RevocationRequest` represents body or query parameters. GitHub requires JSON, so `GitHubOAuthTransport` also implements `RevocationTransport`. It validates the request shape, serializes the single `access_token` parameter as JSON, adds `Content-Type: application/json`, and sends an `OAuthHttpRequest` through the same host transport.

```rust
let body = serde_json::to_vec(&serde_json::json!({
    "access_token": access_token,
}))?;

let response = self.inner.send(suprnova::OAuthHttpRequest {
    method: "DELETE".to_owned(),
    url: request.endpoint,
    headers,
    body,
}).await?;
```

Treat only an HTTP success status as confirmed revocation. Map transport failures and non-success responses to `OAuthProtocolError::UpstreamUnavailable` without formatting the token or response body.

## Export the public plugin surface

Keep private response types and validation helpers private. Export only what an application needs:

```rust
mod provider;
mod transport;

pub use provider::{
    GITHUB_API_VERSION, GITHUB_JSON_MEDIA_TYPE, GitHubConfigError,
    GitHubEndpoints, GitHubOAuthProvider, GitHubProviderConfig,
};
pub use transport::GitHubOAuthTransport;
```

A small public surface gives the plugin room to change its internal response envelope without breaking applications.

## Prove the provider contract before using a network

Start with behavior-focused provider tests using a recording `RevocationTransport`:

- The provider key is `github`.
- Authorization and token shapes match the dossier.
- Token client authentication adds `client_secret` and `Accept: application/json`.
- User-information headers contain the required GitHub values and never contain `Authorization`.
- A verified primary email is accepted.
- A public unverified address is ignored.
- A verified secondary address is ignored.
- Two verified primary addresses fail closed.
- The numeric user ID becomes the subject.
- Revocation uses `DELETE`, the client-specific grant URL, HTTP Basic, and one access-token parameter.

Then test the transport with a scripted fake:

- `/user` followed by `/user/emails` produces one combined response.
- The second request receives the same bearer and GitHub headers.
- Token requests pass through unchanged.
- A failed email response is not converted into success.
- Revocation becomes a JSON request.

These tests protect the provider and adapter contracts independently.

## Exercise the real HTTP stack offline

Add an integration test with `wiremock` and the public `ReqwestOAuthTransport`. Point every GitHub endpoint at the loopback server and assert:

- `POST /login/oauth/access_token` receives the client ID, client secret, callback code, and PKCE verifier.
- The token request asks for JSON.
- `GET /user` receives the host-owned bearer header and provider headers.
- `GET /user/emails?per_page=100` receives the same bearer.
- The resolved identity contains the numeric subject and verified primary email.
- `DELETE /applications/{client_id}/grant` uses a JSON body.

Do not contact GitHub.com from the test suite. Endpoint overrides exist so the provider's complete wire contract can be exercised deterministically.

## Prove downstream registration through the public SDK

A trait implementation compiling inside the plugin crate is not enough. Add a test that behaves like an application:

1. Open an in-memory database.
2. Construct the public `ReqwestOAuthTransport`.
3. Wrap it with `GitHubOAuthTransport`.
4. Construct `GitHubOAuthProvider`.
5. Register it through `MagnetarOAuthHostConfig` and `MagnetarConfig::oauth`.
6. Call `init_magnetar`.
7. Start the flow with `Auth::oauth("github").begin()`.
8. Complete the identity exchange with `verify_oauth_identity(...)` against the mock server.

The test must import SDK types from `suprnova::`, not from Magnetar. This catches missing re-exports, private types in trait signatures, engine installation problems, and transport assumptions that provider unit tests cannot see.

## Add a no-cheating firewall

Make the external boundary executable. Parse `Cargo.toml` in a test and require:

```text
suprnova git = https://github.com/eas4ai/suprnova.git
suprnova tag = v2.1.0
suprnova path = absent
suprnova-magnetar direct dependency = absent
```

Scan `src/` for direct `magnetar::` or `suprnova_magnetar` imports. The framework will still resolve Magnetar transitively, which is expected. The plugin must not name or depend on it directly.

Finally, compile a clean consumer after publishing the plugin tag. That consumer should depend on both public Git tags and construct the provider, adapter, and `MagnetarOAuthHostConfig`. This is the proof that the repository does not rely on your local checkout.

## Register the finished provider in an application

Once the provider crate is complete, an application uses the same public pieces you tested:

```rust
let endpoints = GitHubEndpoints::default();
let base: Arc<dyn OAuthHttpTransport> =
    Arc::new(ReqwestOAuthTransport::try_default()?);
let transport = Arc::new(
    GitHubOAuthTransport::try_new(base, endpoints.clone())?,
);
let provider = Arc::new(GitHubOAuthProvider::try_new(
    GitHubProviderConfig {
        client_id,
        client_secret: SecretString::from(client_secret),
        user_agent,
        endpoints,
    },
    transport.clone(),
)?);

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
)?;
```

Full Magnetar applications pass `oauth` to `MagnetarConfig::oauth` and call
`init_magnetar`. Applications that keep an existing user provider and
framework-session stack instead call:

```rust
init_magnetar_oauth_only(
    MagnetarOAuthOnlyConfig::from_sea_orm(database, oauth),
)
.await?;
```

Their callback uses `verify_oauth_identity`, maps the stable provider subject
into the application's own OAuth-account table, and calls `Auth::login`.
OAuth-only initialization deliberately leaves password and passkey authority
uninstalled so legacy framework sessions remain valid.

The application-specific routes remain small because the plugin and SDK own the protocol work:

```rust
let kickoff = Auth::oauth("github").begin().await?;
let (user, session) = Auth::oauth("github")
    .complete(&code, &state)
    .await?;
```

This final registration snippet is not the tutorial's implementation shortcut. It is the consumer proof after every provider-specific boundary has already been built and tested.

## Verify and release

Run the crate checks:

```bash
cargo fmt --all --check
cargo clippy --all-targets
cargo test --all-targets
cargo check --example suprnova_app
cargo doc --no-deps
cargo package --list
```

Create an annotated tag and a GitHub Release only after the standalone crate and a clean released-tag consumer compile.

The published GitHub plugin used this sequence for `v0.2.2`. Its final suite covered provider behavior, transport behavior, real HTTP requests against a mock server, complete public-SDK identity exchange, and the dependency firewall.

## Reuse the pattern for another provider

For another OAuth provider, keep the architecture and replace only dossier-driven behavior:

- Endpoint URLs
- Parameter names and scope delimiter
- PKCE and nonce posture
- Client authentication
- Required request headers
- Token response quirks
- Stable subject field
- Verified email semantics
- Refresh and invalid-grant meaning
- Revocation method, authentication, parameter placement, and success response

Do not add provider-name branches to the Suprnova engine. If the provider needs extra network work, build a public transport adapter. If it needs a response verification rule, keep that rule in `resolve_identity`. If a claim cannot be proved from the provider's response, fail closed and hand control back to Suprnova's identity policy.
