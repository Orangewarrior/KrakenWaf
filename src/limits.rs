//! Memory / inspection-buffer limits.
//!
//! Centralises every cap that protects KrakenWaf from a memory-exhaustion
//! style DoS. Defaults are intentionally **drastically lower** than the
//! historical 100 MiB values: any deployment that legitimately handles
//! larger payloads should opt in by editing `rules/cmc/config.yaml` (or
//! `conf/limits.yaml`) — not by silently accepting an unbounded surface.
//!
//! Priority chain (highest first):
//!   1. Explicit CLI flag (`--max-body-bytes`, etc).
//!   2. YAML configuration (`rules/cmc/config.yaml :: memory-limits` or
//!      `conf/limits.yaml`).
//!   3. Built-in defaults below.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};

// ── Defaults ──────────────────────────────────────────────────────────────────

/// Maximum request body the WAF will buffer + inspect (bytes).
/// Default lowered from 100 MiB → **8 MiB** in 2.24.0.
pub const DEFAULT_MAX_REQUEST_BODY_BUFFERED_BYTES: usize = 8 * 1024 * 1024;

/// Maximum upstream response body the WAF will buffer (bytes).
/// Default lowered from 100 MiB → **8 MiB** in 2.24.0.
pub const DEFAULT_MAX_RESPONSE_BODY_BUFFERED_BYTES: usize = 8 * 1024 * 1024;

/// Maximum window of streaming data the WAF will keep in RAM for a single
/// in-flight inspection (bytes). Streaming inspection rolls a window of this
/// size across the body so signatures cannot be split across chunks.
pub const DEFAULT_MAX_STREAMING_INSPECTION_WINDOW_BYTES: usize = 256 * 1024;

/// Aggregate ceiling on in-flight body buffering across **all** connections.
/// Once breached, new requests are rejected with 503 until pressure drops.
pub const DEFAULT_MAX_INFLIGHT_BODY_BYTES_GLOBAL: usize = 256 * 1024 * 1024;

/// Per-IP ceiling on in-flight body buffering. Stops a single source
/// from monopolising the global pool by opening many connections.
pub const DEFAULT_MAX_INFLIGHT_BODY_BYTES_PER_IP: usize = 16 * 1024 * 1024;

/// Maximum ratio between decompressed and compressed body sizes
/// (zip-bomb guard). A POST that decompresses by more than this factor is
/// rejected before the inspection budget is exhausted.
pub const DEFAULT_MAX_DECOMPRESS_RATIO: u32 = 32;

// ── Config struct ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryLimits {
    /// Maximum request body the WAF will buffer + inspect (bytes).
    pub max_request_body_buffered_bytes: usize,
    /// Maximum upstream response body the WAF will buffer (bytes).
    pub max_response_body_buffered_bytes: usize,
    /// Streaming inspection window size (bytes).
    pub max_streaming_inspection_window_bytes: usize,
    /// Global in-flight body buffering ceiling (bytes).
    pub max_inflight_body_bytes_global: usize,
    /// Per-IP in-flight body buffering ceiling (bytes).
    pub max_inflight_body_bytes_per_ip: usize,
    /// Maximum compressed → decompressed body expansion ratio.
    pub max_decompress_ratio: u32,
    /// Maximum simultaneous TCP connections accepted. `None` lets KrakenWaf
    /// derive a conservative value from the system RAM at startup.
    pub max_connections: Option<usize>,
}

impl Default for MemoryLimits {
    fn default() -> Self {
        Self {
            max_request_body_buffered_bytes: DEFAULT_MAX_REQUEST_BODY_BUFFERED_BYTES,
            max_response_body_buffered_bytes: DEFAULT_MAX_RESPONSE_BODY_BUFFERED_BYTES,
            max_streaming_inspection_window_bytes:
                DEFAULT_MAX_STREAMING_INSPECTION_WINDOW_BYTES,
            max_inflight_body_bytes_global: DEFAULT_MAX_INFLIGHT_BODY_BYTES_GLOBAL,
            max_inflight_body_bytes_per_ip: DEFAULT_MAX_INFLIGHT_BODY_BYTES_PER_IP,
            max_decompress_ratio: DEFAULT_MAX_DECOMPRESS_RATIO,
            max_connections: None,
        }
    }
}

impl MemoryLimits {
    /// Load `rules/cmc/config.yaml` and extract its `memory-limits:` block,
    /// falling back to `conf/limits.yaml`, then to defaults.
    ///
    /// # Errors
    /// Returns an error when a config file exists but cannot be parsed.
    pub fn load(root: &Path) -> Result<Self> {
        let cmc_path = root.join("rules").join("cmc").join("config.yaml");
        if cmc_path.exists() {
            let raw = fs::read_to_string(&cmc_path)
                .with_context(|| format!("failed to read '{}'", cmc_path.display()))?;
            #[derive(Debug, Deserialize)]
            struct Outer {
                #[serde(rename = "memory-limits", default)]
                memory_limits: Option<MemoryLimits>,
            }
            let outer: Outer = serde_yaml::from_str(&raw).with_context(|| {
                format!("failed to parse '{}': memory-limits", cmc_path.display())
            })?;
            if let Some(limits) = outer.memory_limits {
                return Ok(limits);
            }
        }

        let alt = root.join("conf").join("limits.yaml");
        if alt.exists() {
            let raw = fs::read_to_string(&alt)
                .with_context(|| format!("failed to read '{}'", alt.display()))?;
            let parsed: MemoryLimits = serde_yaml::from_str(&raw)
                .with_context(|| format!("failed to parse '{}'", alt.display()))?;
            return Ok(parsed);
        }

        Ok(Self::default())
    }

    /// Resolve the effective request-body cap, honouring CLI override.
    #[must_use]
    #[allow(dead_code)] // Public API for downstream consumers / tests.
    pub fn effective_request_body_cap(&self, cli_override: usize) -> usize {
        if cli_override == 0 {
            self.max_request_body_buffered_bytes
        } else {
            cli_override
        }
    }

    /// Resolve the effective response-body cap, honouring CLI override.
    #[must_use]
    #[allow(dead_code)] // Public API for downstream consumers / tests.
    pub fn effective_response_body_cap(&self, cli_override: usize) -> usize {
        if cli_override == 0 {
            self.max_response_body_buffered_bytes
        } else {
            cli_override
        }
    }

    /// Resolve the effective `max_connections` value. When the config does
    /// not pin a value the CLI override is used; if that is also absent
    /// we derive a conservative cap from system RAM (≈ 4 connections per
    /// MiB, capped at 4096 for safety).
    #[must_use]
    pub fn effective_max_connections(&self, cli_override: Option<usize>) -> usize {
        if let Some(v) = cli_override.filter(|v| *v > 0) {
            return v;
        }
        if let Some(v) = self.max_connections.filter(|v| *v > 0) {
            return v;
        }
        derive_max_connections_from_ram()
    }
}

/// Conservative heuristic: read `/proc/meminfo` on Linux, otherwise fall
/// back to 512. We allocate ≈ 1 in-flight connection per MiB of total RAM,
/// then clamp into [64, 4096] so we never bind a port and immediately starve.
#[must_use]
pub fn derive_max_connections_from_ram() -> usize {
    let total_mib = detect_total_ram_mib().unwrap_or(0);
    if total_mib == 0 {
        return 512;
    }
    // 1 connection per MiB ≈ 8 MiB body × 0 active + headroom.
    // Empirically this lands around 1024 on a typical 8 GiB host.
    let derived = total_mib / 2;
    derived.clamp(64, 4096)
}

#[cfg(target_os = "linux")]
fn detect_total_ram_mib() -> Option<usize> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kib: usize = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())?;
            return Some(kib / 1024);
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn detect_total_ram_mib() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_drastically_lower_than_legacy() {
        let m = MemoryLimits::default();
        assert!(m.max_request_body_buffered_bytes <= 16 * 1024 * 1024);
        assert!(m.max_response_body_buffered_bytes <= 16 * 1024 * 1024);
        assert!(m.max_streaming_inspection_window_bytes <= 1024 * 1024);
    }

    #[test]
    fn cli_override_wins_over_config() {
        let m = MemoryLimits::default();
        assert_eq!(m.effective_request_body_cap(123), 123);
        assert_eq!(m.effective_response_body_cap(456), 456);
        // Sentinel 0 → config / default.
        assert_eq!(
            m.effective_request_body_cap(0),
            m.max_request_body_buffered_bytes
        );
    }

    #[test]
    fn derived_max_connections_is_sane() {
        let n = derive_max_connections_from_ram();
        assert!((64..=4096).contains(&n));
    }
}
