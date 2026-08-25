#![forbid(unsafe_code)]

//! GitHub OAuth provider plugin for Suprnova.

mod provider;
mod transport;

pub use provider::{
    GITHUB_API_VERSION, GITHUB_JSON_MEDIA_TYPE, GitHubConfigError, GitHubEndpoints,
    GitHubOAuthProvider, GitHubProviderConfig,
};
pub use transport::GitHubOAuthTransport;
