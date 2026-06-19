use super::ProxyClient;
use anyhow::Result;

/// Fluent builder for [`ProxyClient`].
///
/// The builder keeps process configuration assembly out of the request-path
/// implementation and gives optional proxy features explicit defaults.
#[derive(Debug, Clone)]
pub struct ProxyClientBuilder {
    upstream: String,
    timeout_secs: u64,
    allow_private_upstream: bool,
    internal_header_name: Option<String>,
    upstream_ca: Option<String>,
}

impl ProxyClientBuilder {
    #[must_use]
    pub fn new(upstream: impl Into<String>) -> Self {
        Self {
            upstream: upstream.into(),
            timeout_secs: 30,
            allow_private_upstream: false,
            internal_header_name: None,
            upstream_ca: None,
        }
    }

    #[must_use]
    pub const fn timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    #[must_use]
    pub const fn allow_private_upstream(mut self, allow: bool) -> Self {
        self.allow_private_upstream = allow;
        self
    }

    #[must_use]
    pub fn internal_header_name(mut self, name: impl Into<String>) -> Self {
        self.internal_header_name = Some(name.into());
        self
    }

    #[must_use]
    pub fn upstream_ca(mut self, path: impl Into<String>) -> Self {
        self.upstream_ca = Some(path.into());
        self
    }

    /// Build and validate the proxy client.
    ///
    /// # Errors
    /// Returns an error for invalid/unsafe upstream URLs, invalid internal
    /// header names, or an unreadable CA bundle.
    pub fn build(self) -> Result<ProxyClient> {
        ProxyClient::new(
            &self.upstream,
            self.timeout_secs,
            self.allow_private_upstream,
            self.internal_header_name,
            self.upstream_ca.as_deref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyClientBuilder;

    #[test]
    fn builder_constructs_private_http_upstream_when_explicitly_allowed() {
        let client = ProxyClientBuilder::new("http://127.0.0.1:9077")
            .timeout_secs(5)
            .allow_private_upstream(true)
            .internal_header_name("x-krakenwaf-internal")
            .build();
        assert!(client.is_ok());
    }

    #[test]
    fn builder_rejects_private_upstream_by_default() {
        let client = ProxyClientBuilder::new("http://127.0.0.1:9077").build();
        assert!(client.is_err());
    }
}
