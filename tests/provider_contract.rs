use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use suprnova::{
    ClientAuthentication, OAuthProvider, ParamPlacement, ProviderResponse, RevocationRequest,
    RevocationTransport, TokenHint,
};
use suprnova_oauth_github::{
    GITHUB_API_VERSION, GITHUB_JSON_MEDIA_TYPE, GitHubEndpoints, GitHubOAuthProvider,
    GitHubProviderConfig,
};

#[derive(Debug, Eq, PartialEq)]
struct CapturedRevocation {
    method: &'static str,
    endpoint: String,
    placement: ParamPlacement,
    params: Vec<(String, String)>,
    headers: Vec<(String, String)>,
}

#[derive(Default)]
struct RecordingRevocationTransport {
    captured: Mutex<Option<CapturedRevocation>>,
}

#[suprnova::async_trait]
impl RevocationTransport for RecordingRevocationTransport {
    async fn send(&self, request: RevocationRequest) -> suprnova::OAuthResult<()> {
        *self.captured.lock().expect("capture revocation") = Some(CapturedRevocation {
            method: request.method,
            endpoint: request.endpoint,
            placement: request.placement,
            params: request.params,
            headers: request.headers,
        });
        Ok(())
    }
}

fn endpoints() -> GitHubEndpoints {
    GitHubEndpoints {
        authorization: "https://github.test/login/oauth/authorize".to_owned(),
        token: "https://github.test/login/oauth/access_token".to_owned(),
        user: "https://api.github.test/user".to_owned(),
        emails: "https://api.github.test/user/emails?per_page=100".to_owned(),
        revocation: "https://api.github.test/applications/{client_id}/grant".to_owned(),
    }
}

fn provider(revocation: Arc<dyn RevocationTransport>) -> GitHubOAuthProvider {
    GitHubOAuthProvider::try_new(
        GitHubProviderConfig {
            client_id: "github-client".to_owned(),
            client_secret: SecretString::from("github-secret".to_owned()),
            user_agent: "example-app/1.0 (security@example.com)".to_owned(),
            endpoints: endpoints(),
        },
        revocation,
    )
    .expect("valid GitHub provider")
}

#[tokio::test]
async fn exposes_github_oauth_contract_and_required_headers() {
    let provider = provider(Arc::new(RecordingRevocationTransport::default()));

    assert_eq!(provider.name(), "github");
    assert_eq!(
        provider.authorization_endpoint(),
        "https://github.test/login/oauth/authorize"
    );
    assert_eq!(
        provider.token_endpoint(),
        "https://github.test/login/oauth/access_token"
    );
    assert_eq!(
        provider.userinfo_endpoint().as_deref(),
        Some("https://api.github.test/user")
    );
    assert_eq!(provider.authorization_shape(), Default::default());
    assert_eq!(provider.token_shape(), Default::default());

    let headers = provider.userinfo_headers();
    assert!(headers.contains(&(
        "User-Agent".to_owned(),
        "example-app/1.0 (security@example.com)".to_owned()
    )));
    assert!(headers.contains(&("Accept".to_owned(), GITHUB_JSON_MEDIA_TYPE.to_owned())));
    assert!(headers.contains(&(
        "X-GitHub-Api-Version".to_owned(),
        GITHUB_API_VERSION.to_owned()
    )));

    let client_auth = provider
        .client_authentication()
        .await
        .expect("client authentication");
    assert_eq!(
        client_auth.params,
        vec![("client_secret".to_owned(), "github-secret".to_owned())]
    );
    assert!(
        client_auth
            .headers
            .contains(&("Accept".to_owned(), "application/json".to_owned()))
    );

    let refresh = provider.refresh_policy();
    assert!(!refresh.supported);
    assert_eq!(
        refresh.token_client_authentication,
        ClientAuthentication::RequestBody
    );
}

#[tokio::test]
async fn resolves_only_the_verified_primary_email() {
    let provider = provider(Arc::new(RecordingRevocationTransport::default()));
    let combined = serde_json::json!({
        "user": r#"{"id":583231,"login":"octocat","name":"The Octocat","email":"public-but-unverified@example.com"}"#,
        "emails": r#"[
            {"email":"secondary@example.com","primary":false,"verified":true,"visibility":null},
            {"email":"primary@example.com","primary":true,"verified":true,"visibility":"private"}
        ]"#
    });

    let identity = provider
        .resolve_identity(ProviderResponse::UserInfo {
            body: combined.to_string(),
        })
        .await
        .expect("resolve GitHub identity");

    assert_eq!(identity.provider, "github");
    assert_eq!(identity.subject, "583231");
    assert_eq!(identity.email.as_deref(), Some("primary@example.com"));
    assert!(identity.email_verified);
    assert_eq!(identity.display_name.as_deref(), Some("The Octocat"));
}

#[tokio::test]
async fn requires_email_completion_without_a_verified_primary_email() {
    let provider = provider(Arc::new(RecordingRevocationTransport::default()));
    let combined = serde_json::json!({
        "user": r#"{"id":583231,"login":"octocat","name":null,"email":"public@example.com"}"#,
        "emails": r#"[
            {"email":"public@example.com","primary":true,"verified":false,"visibility":"public"},
            {"email":"verified-secondary@example.com","primary":false,"verified":true,"visibility":null}
        ]"#
    });

    let identity = provider
        .resolve_identity(ProviderResponse::UserInfo {
            body: combined.to_string(),
        })
        .await
        .expect("resolve GitHub identity");

    assert_eq!(identity.email, None);
    assert!(!identity.email_verified);
    assert_eq!(identity.display_name.as_deref(), Some("octocat"));
}

#[tokio::test]
async fn rejects_ambiguous_verified_primary_emails() {
    let provider = provider(Arc::new(RecordingRevocationTransport::default()));
    let combined = serde_json::json!({
        "user": r#"{"id":583231,"login":"octocat","name":null}"#,
        "emails": r#"[
            {"email":"first@example.com","primary":true,"verified":true,"visibility":null},
            {"email":"second@example.com","primary":true,"verified":true,"visibility":null}
        ]"#
    });

    let error = provider
        .resolve_identity(ProviderResponse::UserInfo {
            body: combined.to_string(),
        })
        .await
        .expect_err("ambiguous primary email must fail closed");

    let suprnova::OAuthProtocolError::MalformedProviderResponse { message, .. } = error else {
        panic!("expected malformed provider response");
    };
    assert!(message.contains("multiple verified primary"));
    assert!(!message.contains("first@example.com"));
    assert!(!message.contains("second@example.com"));
}

#[tokio::test]
async fn renders_github_grant_revocation_with_basic_authentication() {
    let transport = Arc::new(RecordingRevocationTransport::default());
    let provider = provider(transport.clone());

    provider
        .revoke("gho_access_token", TokenHint::Access)
        .await
        .expect("render revocation");

    let captured = transport
        .captured
        .lock()
        .expect("read capture")
        .take()
        .expect("revocation captured");
    assert_eq!(captured.method, "DELETE");
    assert_eq!(
        captured.endpoint,
        "https://api.github.test/applications/github-client/grant"
    );
    assert_eq!(captured.placement, ParamPlacement::Body);
    assert_eq!(
        captured.params,
        vec![("access_token".to_owned(), "gho_access_token".to_owned())]
    );
    assert!(captured.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("authorization") && value.starts_with("Basic ")
    }));
    assert!(
        captured
            .headers
            .contains(&("Accept".to_owned(), GITHUB_JSON_MEDIA_TYPE.to_owned()))
    );
    assert!(captured.headers.contains(&(
        "X-GitHub-Api-Version".to_owned(),
        GITHUB_API_VERSION.to_owned()
    )));
}
