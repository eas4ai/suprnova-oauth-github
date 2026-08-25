use std::sync::Arc;

use base64::Engine as _;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use suprnova::{
    AuthorizationRequestShape, ClientAuthentication, ClientAuthenticationMaterial,
    InvalidGrantMeaning, OAuthProtocolError, OAuthProvider, OAuthResult, ParamPlacement,
    ProviderIdentity, ProviderResponse, RefreshPolicy, RevocationRequest, RevocationTransport,
    TokenHint, TokenRequestShape,
};
use thiserror::Error;
use url::Url;

/// GitHub's recommended REST response media type.
pub const GITHUB_JSON_MEDIA_TYPE: &str = "application/vnd.github+json";

/// The GitHub REST API version used by this plugin.
pub const GITHUB_API_VERSION: &str = "2026-03-10";

const DEFAULT_AUTHORIZATION_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
const DEFAULT_TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";
const DEFAULT_USER_ENDPOINT: &str = "https://api.github.com/user";
const DEFAULT_EMAILS_ENDPOINT: &str = "https://api.github.com/user/emails?per_page=100";
const DEFAULT_REVOCATION_ENDPOINT: &str = "https://api.github.com/applications/{client_id}/grant";

/// GitHub OAuth and REST endpoints used by the provider and transport.
///
/// Use [`Default`] for GitHub.com. Explicit endpoints support GitHub Enterprise
/// Server and loopback-only integration tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubEndpoints {
    /// The browser authorization endpoint.
    pub authorization: String,
    /// The authorization-code token endpoint.
    pub token: String,
    /// The authenticated-user endpoint.
    pub user: String,
    /// The authenticated user's email-address endpoint.
    pub emails: String,
    /// The grant-revocation endpoint template. It must contain `{client_id}`.
    pub revocation: String,
}

impl Default for GitHubEndpoints {
    fn default() -> Self {
        Self {
            authorization: DEFAULT_AUTHORIZATION_ENDPOINT.to_owned(),
            token: DEFAULT_TOKEN_ENDPOINT.to_owned(),
            user: DEFAULT_USER_ENDPOINT.to_owned(),
            emails: DEFAULT_EMAILS_ENDPOINT.to_owned(),
            revocation: DEFAULT_REVOCATION_ENDPOINT.to_owned(),
        }
    }
}

/// Configuration for [`GitHubOAuthProvider`].
#[derive(Clone, Debug)]
pub struct GitHubProviderConfig {
    /// The client ID from the GitHub OAuth App settings.
    pub client_id: String,
    /// The client secret from the GitHub OAuth App settings.
    pub client_secret: SecretString,
    /// A product-specific HTTP `User-Agent`, including a way to contact the app owner.
    pub user_agent: String,
    /// GitHub.com, GitHub Enterprise Server, or loopback test endpoints.
    pub endpoints: GitHubEndpoints,
}

/// Invalid GitHub provider configuration.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum GitHubConfigError {
    /// A required string was empty.
    #[error("GitHub OAuth {field} must not be empty")]
    Empty {
        /// The invalid field.
        field: &'static str,
    },
    /// The user agent could not be represented as an HTTP header value.
    #[error("GitHub OAuth user_agent contains an HTTP control character")]
    InvalidUserAgent,
    /// A URL was missing, relative, or otherwise malformed.
    #[error("GitHub OAuth {field} must be an absolute URL")]
    InvalidEndpoint {
        /// The invalid endpoint field.
        field: &'static str,
    },
    /// A non-loopback endpoint used cleartext HTTP.
    #[error("GitHub OAuth {field} must use HTTPS outside loopback tests")]
    InsecureEndpoint {
        /// The insecure endpoint field.
        field: &'static str,
    },
    /// The user and email endpoints could not safely share a bearer token.
    #[error("GitHub OAuth user and emails endpoints must have the same origin")]
    UserinfoOriginMismatch,
    /// The revocation endpoint cannot identify the configured OAuth app.
    #[error("GitHub OAuth revocation endpoint must contain `{{client_id}}`")]
    MissingClientIdPlaceholder,
    /// The client ID cannot safely be substituted into a URL path segment.
    #[error("GitHub OAuth client_id contains unsupported characters")]
    InvalidClientId,
}

/// GitHub's `OAuthProvider` implementation for Suprnova.
pub struct GitHubOAuthProvider {
    config: GitHubProviderConfig,
    revocation: Arc<dyn RevocationTransport>,
}

impl GitHubOAuthProvider {
    /// Validate the provider configuration and compose a GitHub provider.
    pub fn try_new(
        config: GitHubProviderConfig,
        revocation: Arc<dyn RevocationTransport>,
    ) -> Result<Self, GitHubConfigError> {
        validate_config(&config)?;
        Ok(Self { config, revocation })
    }

    fn malformed(message: impl Into<String>) -> OAuthProtocolError {
        OAuthProtocolError::MalformedProviderResponse {
            provider: "github",
            message: message.into(),
        }
    }

    fn required_headers(&self) -> Vec<(String, String)> {
        vec![
            ("User-Agent".to_owned(), self.config.user_agent.clone()),
            ("Accept".to_owned(), GITHUB_JSON_MEDIA_TYPE.to_owned()),
            (
                "X-GitHub-Api-Version".to_owned(),
                GITHUB_API_VERSION.to_owned(),
            ),
        ]
    }

    fn basic_authorization(&self) -> String {
        let credentials = format!(
            "{}:{}",
            self.config.client_id,
            self.config.client_secret.expose_secret()
        );
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        )
    }
}

#[derive(Deserialize)]
struct CombinedUserInfo {
    user: String,
    emails: String,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[suprnova::async_trait]
impl OAuthProvider for GitHubOAuthProvider {
    fn name(&self) -> &'static str {
        "github"
    }

    fn authorization_shape(&self) -> AuthorizationRequestShape {
        AuthorizationRequestShape::default()
    }

    fn token_shape(&self) -> TokenRequestShape {
        TokenRequestShape::default()
    }

    async fn resolve_identity(&self, response: ProviderResponse) -> OAuthResult<ProviderIdentity> {
        let ProviderResponse::UserInfo { body } = response else {
            return Err(Self::malformed(
                "GitHub identity resolution requires a UserInfo response",
            ));
        };
        let combined: CombinedUserInfo = serde_json::from_str(&body)
            .map_err(|error| Self::malformed(format!("invalid combined userinfo body: {error}")))?;
        let user: GitHubUser = serde_json::from_str(&combined.user)
            .map_err(|error| Self::malformed(format!("invalid /user response: {error}")))?;
        let emails: Vec<GitHubEmail> = serde_json::from_str(&combined.emails)
            .map_err(|error| Self::malformed(format!("invalid /user/emails response: {error}")))?;

        if user.id == 0 {
            return Err(Self::malformed("/user response contains an invalid `id`"));
        }
        if user.login.trim().is_empty() {
            return Err(Self::malformed("/user response contains an empty `login`"));
        }

        let mut verified_primary = emails
            .into_iter()
            .filter(|candidate| {
                candidate.primary && candidate.verified && !candidate.email.trim().is_empty()
            })
            .map(|candidate| candidate.email);
        let email = verified_primary.next();
        if verified_primary.next().is_some() {
            return Err(Self::malformed(
                "/user/emails response contains multiple verified primary addresses",
            ));
        }
        let email_verified = email.is_some();
        let display_name = user
            .name
            .filter(|name| !name.trim().is_empty())
            .or(Some(user.login));

        Ok(ProviderIdentity {
            provider: "github".to_owned(),
            subject: user.id.to_string(),
            email,
            email_verified,
            display_name,
        })
    }

    async fn revoke(&self, token: &str, hint: TokenHint) -> OAuthResult<()> {
        if hint != TokenHint::Access {
            return Err(OAuthProtocolError::ProviderConfiguration {
                provider: "github",
                message: "GitHub grant revocation requires an access token".to_owned(),
            });
        }
        let mut headers = self.required_headers();
        headers.push(("Authorization".to_owned(), self.basic_authorization()));
        self.revocation
            .send(RevocationRequest {
                method: "DELETE",
                endpoint: self
                    .config
                    .endpoints
                    .revocation
                    .replace("{client_id}", &self.config.client_id),
                placement: ParamPlacement::Body,
                params: vec![("access_token".to_owned(), token.to_owned())],
                headers,
            })
            .await
    }

    fn client_id(&self) -> &str {
        &self.config.client_id
    }

    fn token_endpoint(&self) -> String {
        self.config.endpoints.token.clone()
    }

    fn authorization_endpoint(&self) -> String {
        self.config.endpoints.authorization.clone()
    }

    fn userinfo_endpoint(&self) -> Option<String> {
        Some(self.config.endpoints.user.clone())
    }

    fn userinfo_headers(&self) -> Vec<(String, String)> {
        self.required_headers()
    }

    fn refresh_policy(&self) -> RefreshPolicy {
        RefreshPolicy {
            supported: false,
            token_client_authentication: ClientAuthentication::RequestBody,
            extra_authorization_params: Vec::new(),
            required_scopes: Vec::new(),
            requires_reconsent_for_reissue: false,
            invalid_grant_meaning: InvalidGrantMeaning::OrdinaryRevocation,
        }
    }

    async fn client_authentication(&self) -> OAuthResult<ClientAuthenticationMaterial> {
        Ok(ClientAuthenticationMaterial {
            params: vec![(
                "client_secret".to_owned(),
                self.config.client_secret.expose_secret().to_owned(),
            )],
            headers: vec![("Accept".to_owned(), "application/json".to_owned())],
        })
    }
}

fn validate_config(config: &GitHubProviderConfig) -> Result<(), GitHubConfigError> {
    if config.client_id.is_empty() {
        return Err(GitHubConfigError::Empty { field: "client_id" });
    }
    if !config
        .client_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(GitHubConfigError::InvalidClientId);
    }
    if config.client_secret.expose_secret().is_empty() {
        return Err(GitHubConfigError::Empty {
            field: "client_secret",
        });
    }
    if config.user_agent.trim().is_empty() {
        return Err(GitHubConfigError::Empty {
            field: "user_agent",
        });
    }
    if config
        .user_agent
        .bytes()
        .any(|byte| byte.is_ascii_control())
    {
        return Err(GitHubConfigError::InvalidUserAgent);
    }
    if !config.endpoints.revocation.contains("{client_id}") {
        return Err(GitHubConfigError::MissingClientIdPlaceholder);
    }

    validate_endpoint("authorization endpoint", &config.endpoints.authorization)?;
    validate_endpoint("token endpoint", &config.endpoints.token)?;
    validate_endpoint(
        "revocation endpoint",
        &config
            .endpoints
            .revocation
            .replace("{client_id}", &config.client_id),
    )?;
    validate_transport_endpoints(&config.endpoints)?;
    Ok(())
}

pub(crate) fn validate_transport_endpoints(
    endpoints: &GitHubEndpoints,
) -> Result<(), GitHubConfigError> {
    let user = validate_endpoint("user endpoint", &endpoints.user)?;
    let emails = validate_endpoint("emails endpoint", &endpoints.emails)?;
    if user.origin() != emails.origin() {
        return Err(GitHubConfigError::UserinfoOriginMismatch);
    }
    Ok(())
}

fn validate_endpoint(field: &'static str, value: &str) -> Result<Url, GitHubConfigError> {
    let parsed = Url::parse(value).map_err(|_| GitHubConfigError::InvalidEndpoint { field })?;
    if parsed.cannot_be_a_base() || parsed.host_str().is_none() {
        return Err(GitHubConfigError::InvalidEndpoint { field });
    }
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_loopback(&parsed)) {
        return Err(GitHubConfigError::InsecureEndpoint { field });
    }
    Ok(parsed)
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}
