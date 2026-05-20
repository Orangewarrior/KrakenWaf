use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};

/// HTTP protocol configuration loaded from `conf/network.yaml`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub http2: Http2Config,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // upstream_enabled, max_concurrent_streams, and initial_connection_window_size are surfaced for operators via YAML; not yet read on the server-side fast path.
pub struct Http2Config {
    /// Enable HTTP/2 on the server (inbound) side.
    /// Default: true — clients may negotiate h2 via ALPN.
    #[serde(default = "default_true")]
    pub server_enabled: bool,

    /// Enable HTTP/2 on the upstream (outbound) side.
    /// Default: false — upstream stays HTTP/1.1 unless explicitly opted in.
    #[serde(default)]
    pub upstream_enabled: bool,

    /// Maximum number of concurrent streams per HTTP/2 connection.
    /// Default: 256 (nginx default).
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,

    /// Initial connection-level flow-control window (bytes).
    /// Default: 65535 (RFC 9113 minimum).
    #[serde(default = "default_initial_window_size")]
    pub initial_connection_window_size: u32,
}

fn default_true() -> bool { true }
fn default_max_concurrent_streams() -> u32 { 256 }
fn default_initial_window_size() -> u32 { 65535 }

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            server_enabled: true,
            upstream_enabled: false,
            max_concurrent_streams: 256,
            initial_connection_window_size: 65535,
        }
    }
}

impl NetworkConfig {
    /// Load from `conf/network.yaml` relative to `root`. Returns defaults if the file does not exist.
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join("conf").join("network.yaml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))
    }
}
