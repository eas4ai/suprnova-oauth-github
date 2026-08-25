use std::sync::Arc;

use serde::Serialize;
use suprnova::{
    MagnetarError, MagnetarResult, OAuthHttpRequest, OAuthHttpResponse, OAuthHttpTransport,
    OAuthProtocolError, OAuthResult, ParamPlacement, RevocationRequest, RevocationTransport,
};

use crate::provider::{GitHubConfigError, GitHubEndpoints, validate_transport_endpoints};

/// OAuth HTTP adapter that combines GitHub's `/user` and `/user/emails`
/// responses before Suprnova calls the provider's I/O-free identity resolver.
///
/// The adapter also serializes GitHub grant revocation as JSON. All network
/// I/O remains delegated to the host's public [`OAuthHttpTransport`], such as
/// [`suprnova::ReqwestOAuthTransport`].
#[derive(Clone)]
pub struct GitHubOAuthTransport {
    inner: Arc<dyn OAuthHttpTransport>,
    endpoints: GitHubEndpoints,
}

impl GitHubOAuthTransport {
    /// Validate the userinfo endpoint pair and wrap a host transport.
    pub fn try_new(
        inner: Arc<dyn OAuthHttpTransport>,
        endpoints: GitHubEndpoints,
    ) -> Result<Self, GitHubConfigError> {
        validate_transport_endpoints(&endpoints)?;
        Ok(Self { inner, endpoints })
    }

    fn dependency_error(message: impl Into<String>) -> MagnetarError {
        MagnetarError::DependencyUnavailable {
            dependency: "GitHub OAuth".to_owned(),
            message: message.into(),
        }
    }

    fn protocol_error(message: impl Into<String>) -> OAuthProtocolError {
        OAuthProtocolError::ProviderConfiguration {
            provider: "github",
            message: message.into(),
        }
    }

    fn is_revocation_endpoint(&self, endpoint: &str) -> bool {
        let Some((prefix, suffix)) = self.endpoints.revocation.split_once("{client_id}") else {
            return false;
        };
        endpoint.starts_with(prefix)
            && endpoint.ends_with(suffix)
            && endpoint.len() > prefix.len() + suffix.len()
    }
}

#[derive(Serialize)]
struct CombinedUserInfo<'a> {
    user: &'a str,
    emails: &'a str,
}

#[suprnova::async_trait]
impl OAuthHttpTransport for GitHubOAuthTransport {
    async fn send(&self, request: OAuthHttpRequest) -> MagnetarResult<OAuthHttpResponse> {
        if !request.method.eq_ignore_ascii_case("GET") || request.url != self.endpoints.user {
            return self.inner.send(request).await;
        }

        let headers = request.headers.clone();
        let user = self.inner.send(request).await?;
        if !(200..300).contains(&user.status) {
            return Ok(user);
        }
        let emails = self
            .inner
            .send(OAuthHttpRequest {
                method: "GET".to_owned(),
                url: self.endpoints.emails.clone(),
                headers,
                body: Vec::new(),
            })
            .await?;
        if !(200..300).contains(&emails.status) {
            return Ok(emails);
        }

        let user_body = String::from_utf8(user.body)
            .map_err(|_| Self::dependency_error("GitHub /user response was not UTF-8"))?;
        let emails_body = String::from_utf8(emails.body)
            .map_err(|_| Self::dependency_error("GitHub /user/emails response was not UTF-8"))?;
        let body = serde_json::to_vec(&CombinedUserInfo {
            user: &user_body,
            emails: &emails_body,
        })
        .map_err(|_| Self::dependency_error("failed to combine GitHub userinfo responses"))?;

        Ok(OAuthHttpResponse {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body,
        })
    }
}

#[suprnova::async_trait]
impl RevocationTransport for GitHubOAuthTransport {
    async fn send(&self, request: RevocationRequest) -> OAuthResult<()> {
        if request.method != "DELETE"
            || request.placement != ParamPlacement::Body
            || !self.is_revocation_endpoint(&request.endpoint)
        {
            return Err(Self::protocol_error(
                "invalid GitHub grant revocation request shape",
            ));
        }
        let mut params = request.params.into_iter();
        let Some((name, access_token)) = params.next() else {
            return Err(Self::protocol_error(
                "GitHub grant revocation requires an access_token",
            ));
        };
        if name != "access_token" || access_token.is_empty() || params.next().is_some() {
            return Err(Self::protocol_error(
                "GitHub grant revocation requires exactly one access_token",
            ));
        }

        let mut headers = request.headers;
        headers.retain(|(name, _)| !name.eq_ignore_ascii_case("content-type"));
        headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        let body = serde_json::to_vec(&serde_json::json!({ "access_token": access_token }))
            .map_err(|_| Self::protocol_error("failed to serialize GitHub revocation request"))?;
        let response = self
            .inner
            .send(OAuthHttpRequest {
                method: request.method.to_owned(),
                url: request.endpoint,
                headers,
                body,
            })
            .await
            .map_err(|_| OAuthProtocolError::UpstreamUnavailable {
                provider: "github",
                message: "revocation request failed".to_owned(),
                retry_after_seconds: None,
            })?;
        if (200..300).contains(&response.status) {
            Ok(())
        } else {
            Err(OAuthProtocolError::UpstreamUnavailable {
                provider: "github",
                message: format!("revocation endpoint returned HTTP {}", response.status),
                retry_after_seconds: None,
            })
        }
    }
}
