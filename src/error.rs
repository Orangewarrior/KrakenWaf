use thiserror::Error;

/// Top-level error type used by `KrakenWaf`.
///
/// Most of the codebase propagates `anyhow::Error` for ergonomics; this typed
/// enum is reserved for the few conditions a caller needs to match on (TLS
/// bootstrap and upstream proxying).
#[derive(Debug, Error)]
pub enum KrakenError {
    /// Returned when the configured SNI map does not contain any usable default certificate.
    #[error("no default TLS certificate could be loaded")]
    MissingDefaultCertificate,

    /// Returned when a request cannot be proxied upstream.
    #[error("upstream request failed: {0}")]
    Upstream(String),
}
