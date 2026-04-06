use thiserror::Error;

/// Top-level error type used by KrakenWaf.
#[derive(Debug, Error)]
pub enum KrakenError {
    /// Returned when a request body exceeds the configured route limit.
//    #[error("request body exceeded route limit of {limit} bytes")]
//    BodyTooLarge { limit: usize },

    /// Returned when the configured SNI map does not contain any usable default certificate.
    #[error("no default TLS certificate could be loaded")]
    MissingDefaultCertificate,

    /// Returned when a request cannot be proxied upstream.
    #[error("upstream request failed: {0}")]
    Upstream(String),
}
