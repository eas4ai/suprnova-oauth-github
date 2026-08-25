use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use suprnova::{
    MagnetarError, MagnetarResult, OAuthHttpRequest, OAuthHttpResponse, OAuthHttpTransport,
    OAuthProvider, ParamPlacement, ReqwestOAuthTransport, RevocationRequest, RevocationTransport,
    TokenHint,
};
use suprnova_oauth_github::{
    GITHUB_API_VERSION, GITHUB_JSON_MEDIA_TYPE, GitHubEndpoints, GitHubOAuthProvider,
    GitHubOAuthTransport, GitHubProviderConfig,
};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Default)]
struct ScriptedTransport {
    requests: Mutex<Vec<OAuthHttpRequest>>,
    responses: Mutex<VecDeque<OAuthHttpResponse>>,
}

impl ScriptedTransport {
    fn with_responses(responses: Vec<OAuthHttpResponse>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into()),
        }
    }
}

#[suprnova::async_trait]
impl OAuthHttpTransport for ScriptedTransport {
    async fn send(&self, request: OAuthHttpRequest) -> MagnetarResult<OAuthHttpResponse> {
        self.requests.lock().expect("capture request").push(request);
        self.responses
            .lock()
            .expect("scripted responses")
            .pop_front()
            .ok_or_else(|| MagnetarError::Internal {
                message: "missing scripted response".to_owned(),
            })
    }
}

fn response(status: u16, body: &str) -> OAuthHttpResponse {
    OAuthHttpResponse {
        status,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: body.as_bytes().to_vec(),
    }
}

fn test_endpoints(origin: &str) -> GitHubEndpoints {
    GitHubEndpoints {
        authorization: format!("{origin}/login/oauth/authorize"),
        token: format!("{origin}/login/oauth/access_token"),
        user: format!("{origin}/user"),
        emails: format!("{origin}/user/emails?per_page=100"),
        revocation: format!("{origin}/applications/{{client_id}}/grant"),
    }
}

#[tokio::test]
async fn aggregates_user_and_email_responses_without_provider_io() {
    let inner = Arc::new(ScriptedTransport::with_responses(vec![
        response(
            200,
            r#"{"id":583231,"login":"octocat","name":"The Octocat"}"#,
        ),
        response(
            200,
            r#"[{"email":"octocat@example.com","primary":true,"verified":true,"visibility":"private"}]"#,
        ),
    ]));
    let endpoints = test_endpoints("https://api.github.test");
    let transport = GitHubOAuthTransport::try_new(inner.clone(), endpoints.clone())
        .expect("valid transport endpoints");
    let headers = vec![
        ("Authorization".to_owned(), "Bearer gho_test".to_owned()),
        ("User-Agent".to_owned(), "example-app/1.0".to_owned()),
        ("Accept".to_owned(), GITHUB_JSON_MEDIA_TYPE.to_owned()),
        (
            "X-GitHub-Api-Version".to_owned(),
            GITHUB_API_VERSION.to_owned(),
        ),
    ];

    let combined = OAuthHttpTransport::send(
        &transport,
        OAuthHttpRequest {
            method: "GET".to_owned(),
            url: endpoints.user,
            headers: headers.clone(),
            body: Vec::new(),
        },
    )
    .await
    .expect("aggregate GitHub userinfo");

    assert_eq!(combined.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&combined.body).expect("combined JSON");
    assert!(body["user"].as_str().expect("user body").contains("583231"));
    assert!(
        body["emails"]
            .as_str()
            .expect("emails body")
            .contains("octocat@example.com")
    );

    let requests = inner.requests.lock().expect("captured requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url, "https://api.github.test/user");
    assert_eq!(
        requests[1].url,
        "https://api.github.test/user/emails?per_page=100"
    );
    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].headers, headers);
    assert!(requests[1].body.is_empty());
}

#[tokio::test]
async fn delegates_non_userinfo_requests_unchanged() {
    let inner = Arc::new(ScriptedTransport::with_responses(vec![response(
        200,
        r#"{"access_token":"gho_test","token_type":"bearer"}"#,
    )]));
    let endpoints = test_endpoints("https://api.github.test");
    let transport = GitHubOAuthTransport::try_new(inner.clone(), endpoints.clone())
        .expect("valid transport endpoints");
    let request = OAuthHttpRequest {
        method: "POST".to_owned(),
        url: endpoints.token,
        headers: vec![("Accept".to_owned(), "application/json".to_owned())],
        body: b"code=temporary".to_vec(),
    };

    let result = OAuthHttpTransport::send(&transport, request.clone())
        .await
        .expect("delegate token request");

    assert_eq!(result.status, 200);
    assert_eq!(
        inner.requests.lock().expect("captured requests").as_slice(),
        &[request]
    );
}

#[tokio::test]
async fn sends_github_revocation_as_json() {
    let inner = Arc::new(ScriptedTransport::with_responses(vec![response(204, "")]));
    let endpoints = test_endpoints("https://api.github.test");
    let transport = GitHubOAuthTransport::try_new(inner.clone(), endpoints.clone())
        .expect("valid transport endpoints");

    RevocationTransport::send(
        &transport,
        RevocationRequest {
            method: "DELETE",
            endpoint: endpoints.revocation.replace("{client_id}", "github-client"),
            placement: ParamPlacement::Body,
            params: vec![("access_token".to_owned(), "gho_test".to_owned())],
            headers: vec![("Authorization".to_owned(), "Basic credentials".to_owned())],
        },
    )
    .await
    .expect("send GitHub revocation");

    let requests = inner.requests.lock().expect("captured requests");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "DELETE");
    assert_eq!(
        request.url,
        "https://api.github.test/applications/github-client/grant"
    );
    assert!(
        request
            .headers
            .contains(&("Content-Type".to_owned(), "application/json".to_owned()))
    );
    let body: serde_json::Value = serde_json::from_slice(&request.body).expect("JSON body");
    assert_eq!(body["access_token"], "gho_test");
}

#[tokio::test]
async fn works_with_the_public_reqwest_transport_against_mock_github() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", "Bearer gho_live_shape"))
        .and(header("user-agent", "example-app/1.0"))
        .and(header("accept", GITHUB_JSON_MEDIA_TYPE))
        .and(header("x-github-api-version", GITHUB_API_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 583231,
            "login": "octocat",
            "name": "The Octocat",
            "email": "ignored-public@example.com"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/emails"))
        .and(query_param("per_page", "100"))
        .and(header("authorization", "Bearer gho_live_shape"))
        .and(header("user-agent", "example-app/1.0"))
        .and(header("accept", GITHUB_JSON_MEDIA_TYPE))
        .and(header("x-github-api-version", GITHUB_API_VERSION))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "email": "verified@example.com",
                "primary": true,
                "verified": true,
                "visibility": "private"
            }])),
        )
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/applications/github-client/grant"))
        .and(header("accept", GITHUB_JSON_MEDIA_TYPE))
        .and(header("x-github-api-version", GITHUB_API_VERSION))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let endpoints = test_endpoints(&server.uri());
    let inner: Arc<dyn OAuthHttpTransport> =
        Arc::new(ReqwestOAuthTransport::try_default().expect("reqwest transport"));
    let transport = Arc::new(
        GitHubOAuthTransport::try_new(inner, endpoints.clone()).expect("GitHub transport"),
    );
    let provider = GitHubOAuthProvider::try_new(
        GitHubProviderConfig {
            client_id: "github-client".to_owned(),
            client_secret: SecretString::from("github-secret".to_owned()),
            user_agent: "example-app/1.0".to_owned(),
            endpoints: endpoints.clone(),
        },
        transport.clone(),
    )
    .expect("GitHub provider");

    let combined = OAuthHttpTransport::send(
        transport.as_ref(),
        OAuthHttpRequest {
            method: "GET".to_owned(),
            url: endpoints.user,
            headers: vec![
                (
                    "Authorization".to_owned(),
                    "Bearer gho_live_shape".to_owned(),
                ),
                ("User-Agent".to_owned(), "example-app/1.0".to_owned()),
                ("Accept".to_owned(), GITHUB_JSON_MEDIA_TYPE.to_owned()),
                (
                    "X-GitHub-Api-Version".to_owned(),
                    GITHUB_API_VERSION.to_owned(),
                ),
            ],
            body: Vec::new(),
        },
    )
    .await
    .expect("GitHub userinfo requests");
    let identity = provider
        .resolve_identity(suprnova::ProviderResponse::UserInfo {
            body: String::from_utf8(combined.body).expect("combined UTF-8"),
        })
        .await
        .expect("resolve combined identity");
    assert_eq!(identity.email.as_deref(), Some("verified@example.com"));

    provider
        .revoke("gho_live_shape", TokenHint::Access)
        .await
        .expect("revoke GitHub grant");
}
