//! WebSocket control policy for `ws://` / `wss://` upgrade requests.
//!
//! Loaded from `conf/websocket.yaml` (or `--websocket-conf <path>`) at startup.
//! The file is wrapped in a top-level `web_socket:` mapping:
//!
//! ```yaml
//! web_socket:
//!   enable_ws_control: true
//!   allowed_paths:
//!     - /ws
//!     - /wss
//!   idle_timeout_secs: 60
//!   max_session_secs: 3600
//!   max_connections_per_ip: 8
//!   inspect_handshake: true
//! ```
//!
//! When `enable_ws_control` is `false` no limit applies and WebSocket upgrades
//! are tunneled transparently. When `true` the WAF enforces, on the handshake
//! (before opening the upstream tunnel):
//!
//! * **`allowed_paths`** — a normalized request path not on the list is rejected
//!   with HTTP 403. An empty list permits any path.
//! * **`max_connections_per_ip`** — a per-source-IP cap on simultaneous live
//!   sessions; the excess handshake is rejected with HTTP 429 + `Retry-After`.
//! * **`inspect_handshake`** — run the full inspection engine over the upgrade
//!   request (URI + headers) and block on a detection.
//!
//! and, on the established tunnel:
//!
//! * **`idle_timeout_secs`** — close the tunnel after this long with no frame in
//!   either direction (anti–half-open / Slowloris).
//! * **`max_session_secs`** — hard cap on total session lifetime.
//!
//! Defaults (used when the file is absent) keep `enable_ws_control` **on** with
//! conservative values that support ordinary WebSocket traffic without flooding
//! or context abuse.

use anyhow::{Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::Path,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ── Config ─────────────────────────────────────────────────────────────────

/// On-disk wrapper: `conf/websocket.yaml` nests every field under `web_socket:`.
#[derive(Debug, Clone, Deserialize)]
struct WebSocketFile {
    web_socket: WebSocketConfig,
}

/// Parsed WebSocket control policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebSocketConfig {
    /// Master switch. `false` disables every limit (transparent tunnel).
    #[serde(default = "default_enable")]
    pub enable_ws_control: bool,

    /// Request paths permitted to upgrade. Empty ⇒ any path is allowed.
    #[serde(default = "default_allowed_paths")]
    pub allowed_paths: Vec<String>,

    /// Idle timeout (seconds) — no frame either way for this long closes the
    /// tunnel. 0 disables the idle bound.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// Hard cap (seconds) on a single session's total lifetime. 0 disables it.
    #[serde(default = "default_max_session_secs")]
    pub max_session_secs: u64,

    /// Maximum simultaneous sessions per source IP. 0 disables the cap.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,

    /// Run the inspection engine over the upgrade handshake before tunneling.
    #[serde(default = "default_inspect_handshake")]
    pub inspect_handshake: bool,
}

fn default_enable() -> bool { true }
fn default_allowed_paths() -> Vec<String> { vec!["/ws".to_string(), "/wss".to_string()] }
fn default_idle_timeout_secs() -> u64 { 60 }
fn default_max_session_secs() -> u64 { 3600 }
fn default_max_connections_per_ip() -> usize { 8 }
fn default_inspect_handshake() -> bool { true }

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            enable_ws_control: default_enable(),
            allowed_paths: default_allowed_paths(),
            idle_timeout_secs: default_idle_timeout_secs(),
            max_session_secs: default_max_session_secs(),
            max_connections_per_ip: default_max_connections_per_ip(),
            inspect_handshake: default_inspect_handshake(),
        }
    }
}

impl WebSocketConfig {
    /// Load `<root>/conf/websocket.yaml`; returns [`Default`] when absent.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load(root: &Path) -> Result<Self> {
        Self::load_from(&root.join("conf").join("websocket.yaml"))
    }

    /// Load from an explicit path; returns [`Default`] when the file is absent.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read '{}'", path.display()))?;
        let parsed: WebSocketFile = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed to parse '{}'", path.display()))?;
        parsed
            .web_socket
            .validate()
            .with_context(|| format!("invalid websocket config '{}'", path.display()))?;
        Ok(parsed.web_socket)
    }

    /// Validate semantic constraints. Run on load so a malformed policy is
    /// rejected at startup rather than silently mis-limiting traffic.
    ///
    /// # Errors
    /// Returns an error when an allowed path does not begin with `/`.
    pub fn validate(&self) -> Result<()> {
        for p in &self.allowed_paths {
            anyhow::ensure!(
                p.starts_with('/'),
                "websocket allowed_paths entry '{p}' must be an absolute path beginning with '/'"
            );
        }
        Ok(())
    }

    /// Idle timeout as a [`Duration`], or `None` when disabled (0).
    #[must_use]
    pub fn idle_timeout(&self) -> Option<Duration> {
        (self.idle_timeout_secs > 0).then(|| Duration::from_secs(self.idle_timeout_secs))
    }

    /// Max session lifetime as a [`Duration`], or `None` when disabled (0).
    #[must_use]
    pub fn max_session(&self) -> Option<Duration> {
        (self.max_session_secs > 0).then(|| Duration::from_secs(self.max_session_secs))
    }
}

// ── Runtime control ──────────────────────────────────────────────────────────

/// Runtime state for WebSocket control: the parsed policy plus a per-IP live
/// session counter used to enforce `max_connections_per_ip`.
pub struct WebSocketControl {
    config: WebSocketConfig,
    /// Live WebSocket sessions per source IP. Entries are reaped by the shared
    /// IP-map janitor once their counter reaches zero.
    ip_sessions: DashMap<String, Arc<AtomicUsize>>,
}

impl WebSocketControl {
    #[must_use]
    pub fn new(config: WebSocketConfig) -> Self {
        Self { config, ip_sessions: DashMap::new() }
    }

    #[must_use]
    pub fn config(&self) -> &WebSocketConfig {
        &self.config
    }

    /// Whether the control policy is active.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.config.enable_ws_control
    }

    /// Whether `inspect_handshake` is on.
    #[must_use]
    pub fn inspect_handshake(&self) -> bool {
        self.config.inspect_handshake
    }

    /// True when `path` is permitted to upgrade. An empty `allowed_paths`
    /// permits any path. Otherwise a path matches when it equals a configured
    /// entry, or descends from it on a `/` boundary (so `/ws` covers `/ws/chat`
    /// but not `/wsfoo`).
    #[must_use]
    pub fn path_allowed(&self, path: &str) -> bool {
        if self.config.allowed_paths.is_empty() {
            return true;
        }
        self.config.allowed_paths.iter().any(|entry| {
            path == entry
                || (path.len() > entry.len()
                    && path.starts_with(entry.as_str())
                    && path.as_bytes().get(entry.len()) == Some(&b'/'))
        })
    }

    /// Attempt to reserve a session slot for `ip`. Returns an RAII guard that
    /// releases the slot on drop, or `None` when the per-IP cap is reached.
    /// A cap of 0 disables the limit (always succeeds, no tracking).
    #[must_use]
    pub fn try_acquire(&self, ip: &str) -> Option<WsConnGuard> {
        let limit = self.config.max_connections_per_ip;
        if limit == 0 {
            return Some(WsConnGuard { counter: None });
        }
        let counter = self
            .ip_sessions
            .entry(ip.to_string())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();
        let acquired = counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < limit).then_some(current + 1)
            })
            .is_ok();
        if !acquired {
            return None;
        }
        Some(WsConnGuard { counter: Some(counter) })
    }

    /// Reap per-IP session entries whose counter is zero. Called by the shared
    /// IP-map janitor so the map cannot grow without bound under IP rotation.
    pub fn sweep_idle(&self) {
        self.ip_sessions
            .retain(|_, counter| counter.load(Ordering::Relaxed) > 0);
    }
}

/// RAII guard decrementing the per-IP live-session counter on drop. Moved into
/// the tunnel task so the slot is held for the session's lifetime.
pub struct WsConnGuard {
    counter: Option<Arc<AtomicUsize>>,
}

impl Drop for WsConnGuard {
    fn drop(&mut self) {
        if let Some(counter) = &self.counter {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

// ── Tunnel with idle + session bounds ────────────────────────────────────────

/// Coarse wall-clock seconds since the Unix epoch — good enough for the idle
/// watchdog, which only needs second resolution.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Copy one direction, stamping `activity` after every forwarded chunk so the
/// watchdog can detect an idle tunnel. Shuts the writer down cleanly on EOF.
async fn copy_half<R, W>(mut reader: R, mut writer: W, activity: &AtomicU64) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        activity.store(now_secs(), Ordering::Relaxed);
    }
}

/// Returns once the tunnel has been idle longer than `idle` or has lived longer
/// than `max_session`. With both `None` it never returns (no bound).
async fn watchdog(activity: Arc<AtomicU64>, idle: Option<Duration>, max_session: Option<Duration>) {
    if idle.is_none() && max_session.is_none() {
        std::future::pending::<()>().await;
        return;
    }
    let start = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Some(max) = max_session {
            if start.elapsed() >= max {
                return;
            }
        }
        if let Some(idle) = idle {
            let last = activity.load(Ordering::Relaxed);
            if now_secs().saturating_sub(last) >= idle.as_secs() {
                return;
            }
        }
    }
}

/// Pump bytes bidirectionally between `downstream` (client) and `upstream`
/// (backend) until either side closes, the idle timeout elapses, or the session
/// lifetime cap is reached. `guard` is held for the session's lifetime so the
/// per-IP counter is released exactly when the tunnel ends.
pub async fn tunnel<D, U>(
    downstream: D,
    upstream: U,
    idle: Option<Duration>,
    max_session: Option<Duration>,
    guard: Option<WsConnGuard>,
) where
    D: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let _guard = guard;
    let (dr, dw) = tokio::io::split(downstream);
    let (ur, uw) = tokio::io::split(upstream);
    let activity = Arc::new(AtomicU64::new(now_secs()));

    let to_upstream = copy_half(dr, uw, &activity);
    let to_downstream = copy_half(ur, dw, &activity);
    tokio::pin!(to_upstream, to_downstream);

    tokio::select! {
        _ = &mut to_upstream => {}
        _ = &mut to_downstream => {}
        () = watchdog(activity.clone(), idle, max_session) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_control_with_sane_values() {
        let cfg = WebSocketConfig::default();
        assert!(cfg.enable_ws_control);
        assert_eq!(cfg.allowed_paths, vec!["/ws".to_string(), "/wss".to_string()]);
        assert_eq!(cfg.idle_timeout_secs, 60);
        assert_eq!(cfg.max_session_secs, 3600);
        assert_eq!(cfg.max_connections_per_ip, 8);
        assert!(cfg.inspect_handshake);
    }

    #[test]
    fn parses_nested_web_socket_mapping() {
        let yaml = "\
web_socket:
  enable_ws_control: true
  allowed_paths:
    - /ws
    - /wss
  idle_timeout_secs: 30
  max_session_secs: 120
  max_connections_per_ip: 4
  inspect_handshake: false
";
        let parsed: WebSocketFile = serde_yaml::from_str(yaml).expect("parses");
        let cfg = parsed.web_socket;
        assert!(cfg.enable_ws_control);
        assert_eq!(cfg.idle_timeout_secs, 30);
        assert_eq!(cfg.max_session_secs, 120);
        assert_eq!(cfg.max_connections_per_ip, 4);
        assert!(!cfg.inspect_handshake);
    }

    #[test]
    fn partial_yaml_fills_defaults() {
        let yaml = "web_socket:\n  enable_ws_control: false\n";
        let parsed: WebSocketFile = serde_yaml::from_str(yaml).expect("parses");
        let cfg = parsed.web_socket;
        assert!(!cfg.enable_ws_control);
        // Unspecified fields fall back to the conservative defaults.
        assert_eq!(cfg.idle_timeout_secs, 60);
        assert_eq!(cfg.max_connections_per_ip, 8);
    }

    #[test]
    fn path_allow_list_matches_exact_and_subpaths() {
        let ctrl = WebSocketControl::new(WebSocketConfig::default());
        assert!(ctrl.path_allowed("/ws"));
        assert!(ctrl.path_allowed("/wss"));
        assert!(ctrl.path_allowed("/ws/chat"));
        assert!(!ctrl.path_allowed("/wsfoo"));
        assert!(!ctrl.path_allowed("/socket"));
    }

    #[test]
    fn empty_allow_list_permits_any_path() {
        let mut cfg = WebSocketConfig::default();
        cfg.allowed_paths.clear();
        let ctrl = WebSocketControl::new(cfg);
        assert!(ctrl.path_allowed("/anything"));
    }

    #[test]
    fn per_ip_cap_blocks_excess_and_releases_on_drop() {
        let cfg = WebSocketConfig { max_connections_per_ip: 2, ..Default::default() };
        let ctrl = WebSocketControl::new(cfg);
        let g1 = ctrl.try_acquire("1.2.3.4");
        let g2 = ctrl.try_acquire("1.2.3.4");
        assert!(g1.is_some() && g2.is_some());
        assert!(ctrl.try_acquire("1.2.3.4").is_none(), "3rd must be capped");
        // A different IP is unaffected.
        assert!(ctrl.try_acquire("5.6.7.8").is_some());
        drop(g1);
        assert!(ctrl.try_acquire("1.2.3.4").is_some(), "slot freed on drop");
    }

    #[test]
    fn zero_cap_disables_per_ip_limit() {
        let cfg = WebSocketConfig { max_connections_per_ip: 0, ..Default::default() };
        let ctrl = WebSocketControl::new(cfg);
        for _ in 0..1000 {
            assert!(ctrl.try_acquire("9.9.9.9").is_some());
        }
    }

    #[test]
    fn validate_rejects_relative_allowed_path() {
        let cfg = WebSocketConfig {
            allowed_paths: vec!["ws".to_string()],
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
