use std::sync::Arc;

use sea_orm::Database;
use secrecy::SecretString;
use suprnova::{
    AbuseLimiter, AbusePolicy, Auth, AutoLinkPolicy, Crypt, EncryptionKey, MagnetarConfig,
    MagnetarOAuthHostConfig, MagnetarOAuthProviderConfig, MagnetarResult, OAuthAuthorizationConfig,
    OAuthHttpTransport, Permit, ReqwestOAuthTransport, init_magnetar,
};
use suprnova_oauth_github::{
    GITHUB_API_VERSION, GITHUB_JSON_MEDIA_TYPE, GitHubEndpoints, GitHubOAuthProvider,
    GitHubOAuthTransport, GitHubProviderConfig,
};
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct AllowAll;

#[suprnova::async_trait]
impl AbuseLimiter for AllowAll {
    async fn acquire(&self, _key: &str, _policy: AbusePolicy) -> MagnetarResult<Permit> {
        Ok(Permit::Allowed { retry_after: None })
    }
}

#[tokio::test]
async fn external_crate_completes_identity_exchange_through_public_sdk() {
    let github = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(header("accept", "application/json"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("client_id=external-github-client"))
        .and(body_string_contains("client_secret=external-github-secret"))
        .and(body_string_contains("code=temporary-code"))
        .and(body_string_contains("code_verifier="))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "gho_external_test",
            "token_type": "bearer",
            "scope": "user:email"
        })))
        .expect(1)
        .mount(&github)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", "Bearer gho_external_test"))
        .and(header(
            "user-agent",
            "external-suprnova-app/1.0 (security@example.com)",
        ))
        .and(header("accept", GITHUB_JSON_MEDIA_TYPE))
        .and(header("x-github-api-version", GITHUB_API_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 583231,
            "login": "octocat",
            "name": "The Octocat",
            "email": "ignored-public@example.com"
        })))
        .expect(1)
        .mount(&github)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/emails"))
        .and(query_param("per_page", "100"))
        .and(header("authorization", "Bearer gho_external_test"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "email": "verified-primary@example.com",
                "primary": true,
                "verified": true,
                "visibility": "private"
            }])),
        )
        .expect(1)
        .mount(&github)
        .await;

    Crypt::init(EncryptionKey::generate());
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("connect SQLite");
    let endpoints = GitHubEndpoints {
        authorization: "https://github.com/login/oauth/authorize".to_owned(),
        token: format!("{}/login/oauth/access_token", github.uri()),
        user: format!("{}/user", github.uri()),
        emails: format!("{}/user/emails?per_page=100", github.uri()),
        revocation: format!("{}/applications/{{client_id}}/grant", github.uri()),
    };
    let inner: Arc<dyn OAuthHttpTransport> =
        Arc::new(ReqwestOAuthTransport::try_default().expect("reqwest transport"));
    let transport = Arc::new(
        GitHubOAuthTransport::try_new(inner, endpoints.clone()).expect("GitHub transport"),
    );
    let provider = Arc::new(
        GitHubOAuthProvider::try_new(
            GitHubProviderConfig {
                client_id: "external-github-client".to_owned(),
                client_secret: SecretString::from("external-github-secret".to_owned()),
                user_agent: "external-suprnova-app/1.0 (security@example.com)".to_owned(),
                endpoints,
            },
            transport.clone(),
        )
        .expect("GitHub provider"),
    );
    let oauth = MagnetarOAuthHostConfig::new(
        vec![MagnetarOAuthProviderConfig {
            provider,
            redirect_uri: "https://app.example.com/auth/github/callback".to_owned(),
            scopes: vec!["user:email".to_owned()],
        }],
        transport,
        Arc::new(AllowAll),
        OAuthAuthorizationConfig::default(),
        AutoLinkPolicy::default(),
    )
    .expect("GitHub OAuth host configuration");
    init_magnetar(MagnetarConfig::from_sea_orm(database).oauth(oauth))
        .await
        .expect("publish GitHub through the default engine");

    let session = suprnova::session::new_session_slot_for_test();
    let kickoff = suprnova::session::session_scope_for_test(session.clone(), async {
        Auth::oauth("github").begin().await
    })
    .await
    .expect("start GitHub OAuth flow through Auth facade");
    let authorization = url::Url::parse(&kickoff.authorization_url).expect("authorization URL");
    assert_eq!(authorization.host_str(), Some("github.com"));
    let params = authorization.query_pairs().collect::<Vec<_>>();
    assert!(
        params
            .iter()
            .any(|(name, value)| { name == "client_id" && value == "external-github-client" })
    );
    assert!(
        params
            .iter()
            .any(|(name, value)| { name == "scope" && value == "user:email" })
    );
    assert!(
        params
            .iter()
            .any(|(name, value)| { name == "code_challenge_method" && value == "S256" })
    );

    let identity = suprnova::session::session_scope_for_test(session, async {
        Auth::oauth("github")
            .verify_oauth_identity("temporary-code", &kickoff.state)
            .await
    })
    .await
    .expect("complete GitHub identity exchange through Auth facade");
    assert_eq!(identity.provider, "github");
    assert_eq!(identity.subject, "583231");
    assert_eq!(
        identity.email.as_deref(),
        Some("verified-primary@example.com")
    );
    assert_eq!(identity.name.as_deref(), Some("The Octocat"));
}
