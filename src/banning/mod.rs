//! BAN list management.
//!
//! When `conf/banning.yaml :: Banning_mode` is `true` the WAF tracks how
//! many times each source IP has been blocked. Once an IP reaches
//! `tolerance_block_count` (or — when `security_scanners` is `true` —
//! triggers the `Detect_bots_n_scanners` CMC module a single time), it is
//! added to the BAN list and every subsequent request is short-circuited
//! at the server layer with HTTP 403 and a `Low`-severity log entry
//! (`title = "Banned IP — request rejected"`).
//!
//! The store is hybrid:
//! * **Redis/Valkey** when the rate-limiter's `redis:` section is set in
//!   `conf/ratelimit.yaml` (the same pool is reused).
//! * **`SQLite`** (`logs/db/banning.db`) otherwise — durable, ACID,
//!   single-node.
//!
//! All state — `banned_until`, `ban_count`, `occurrences` — is wiped 30
//! days after an IP's last block so long-quiet attackers do not accumulate
//! against current operators forever.

mod config;
mod redis_store;
mod sqlite_store;

#[allow(unused_imports)]
pub use config::{BanConfig, BanConfigFile};
pub use redis_store::RedisBanStore;
pub use sqlite_store::SqliteBanStore;

use anyhow::Result;
use chrono::Utc;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::time::interval;
use tracing::{info, warn};

/// Why a block is being counted toward the BAN-list threshold.
///
/// Kept open as a small enum so the call-site self-documents which
/// detection module triggered the increment.
#[derive(Debug, Copy, Clone)]
pub enum BlockReason {
    /// Block by the `Detect_bots_n_scanners` CMC module — when
    /// `security_scanners: true` this fast-tracks the IP to the BAN list.
    SecurityScanner,
    /// Block by any rule/regex/CMC/libinjection detection.
    RuleDetection,
    /// Block by Spamhaus/Firehol/blocklist/allowlist IP reputation lists.
    IpReputation,
    /// Block by rate-limit / per-IP concurrency exhaustion.
    RateLimit,
}

/// Returned when a ban transition occurs.
#[derive(Debug, Clone)]
pub struct BanRecord {
    /// Unix epoch (seconds) at which the ban expires.
    pub banned_until: i64,
    /// Cumulative ban count for this IP (drives the asymptotic extension).
    pub ban_count: i64,
}

/// Result of recording a single block.
#[derive(Debug, Default, Clone)]
pub struct RecordOutcome {
    /// `true` when the IP was already banned at the time of the record.
    #[allow(dead_code)]
    pub already_banned: bool,
    /// `Some` when this specific record opened a new ban window.
    pub triggered_ban: Option<BanRecord>,
    /// Current occurrence counter after recording this event (0 when a
    /// ban was just triggered — the counter resets at that point).
    #[allow(dead_code)]
    pub occurrences: u32,
}

enum BanStore {
    Sqlite(SqliteBanStore),
    Redis(RedisBanStore),
}

/// Public entry-point used by the server / proxy layers.
pub struct BanManager {
    cfg: BanConfig,
    store: BanStore,
}

impl BanManager {
    /// Build a no-op manager. All methods become cheap no-ops.
    #[must_use]
    pub fn disabled() -> Arc<Self> {
        Arc::new(Self {
            cfg: BanConfig::disabled(),
            // An in-memory SQLite is guaranteed to open, but the disabled
            // config short-circuits every method before touching it.
            store: BanStore::Sqlite(SqliteBanStore::in_memory_or_fallback()),
        })
    }

    /// Build a SQLite-backed manager (the always-available default).
    ///
    /// # Errors
    /// Returns an error if the `SQLite` database cannot be opened.
    pub fn new_sqlite(cfg: BanConfig, root: &Path) -> Result<Arc<Self>> {
        let path = root.join("logs").join("db").join("banning.db");
        let store = SqliteBanStore::open(&path)?;
        Ok(Self::wrap(cfg, BanStore::Sqlite(store)))
    }

    /// Build a Redis-backed manager reusing an existing `fred` pool.
    #[must_use]
    pub fn new_redis(cfg: BanConfig, pool: fred::clients::Pool, key_prefix: impl Into<String>) -> Arc<Self> {
        Self::wrap(cfg, BanStore::Redis(RedisBanStore::new(pool, key_prefix)))
    }

    fn wrap(cfg: BanConfig, store: BanStore) -> Arc<Self> {
        let arc = Arc::new(Self { cfg, store });
        arc.clone().spawn_purge_task();
        arc
    }

    /// Whether the operator turned banning on. Cheap.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// Whether `security_scanners` fast-track is on. Cheap.
    #[must_use]
    #[allow(dead_code)]
    pub fn security_scanners_fast_track(&self) -> bool {
        self.cfg.enabled && self.cfg.security_scanners
    }

    /// Check whether `ip` is currently banned. Returns `Some(banned_until)`
    /// (unix epoch seconds) when the IP must be rejected, otherwise `None`.
    pub async fn check(&self, ip: &str) -> Option<i64> {
        if !self.cfg.enabled {
            return None;
        }
        let now = Utc::now().timestamp();
        match &self.store {
            BanStore::Sqlite(s) => s.lookup(ip, now),
            BanStore::Redis(r) => r.lookup(ip, now).await,
        }
    }

    /// Record one block occurrence for `ip`. Returns the [`RecordOutcome`]
    /// so the caller can emit a structured ban-triggered log.
    ///
    /// `reason` is used together with the config to decide whether the
    /// `security_scanners` fast-track applies — block reasons other than
    /// [`BlockReason::SecurityScanner`] always follow the
    /// `tolerance_block_count` threshold.
    pub async fn record_block(&self, ip: &str, reason: BlockReason) -> Option<RecordOutcome> {
        if !self.cfg.enabled {
            return None;
        }

        let force = matches!(reason, BlockReason::SecurityScanner) && self.cfg.security_scanners;
        let now = Utc::now().timestamp();
        let ban_wait_secs = i64::try_from(self.cfg.ban_wait_time.as_secs()).unwrap_or(i64::MAX);

        let outcome = match &self.store {
            BanStore::Sqlite(s) => s
                .record_block(ip, now, self.cfg.tolerance_block_count, ban_wait_secs, force)
                .map_err(|err| {
                    warn!(target: "krakenwaf", error = %err, ip, "sqlite ban record failed");
                    err
                })
                .ok()?,
            BanStore::Redis(r) => r
                .record_block(ip, now, self.cfg.tolerance_block_count, ban_wait_secs, force)
                .await
                .ok()?,
        };

        if let Some(rec) = &outcome.triggered_ban {
            info!(
                target: "krakenwaf",
                ip = %ip,
                ban_count = rec.ban_count,
                banned_until = rec.banned_until,
                reason = ?reason,
                "IP added to BAN list"
            );
        }

        Some(outcome)
    }

    fn spawn_purge_task(self: Arc<Self>) {
        if !self.cfg.enabled {
            return;
        }
        // Only the SQLite backend needs an explicit purge; Redis HSETs
        // expire automatically via EXPIRE.
        if !matches!(self.store, BanStore::Sqlite(_)) {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            // Purge once per hour — cheap, bounded, and a far cry from the
            // 30-day retention window.
            let mut ticker = interval(Duration::from_hours(1));
            ticker.tick().await; // skip the immediate first tick
            loop {
                ticker.tick().await;
                if let BanStore::Sqlite(s) = &me.store {
                    match s.purge_stale(Utc::now().timestamp()) {
                        Ok(0) => {}
                        Ok(removed) => info!(
                            target: "krakenwaf",
                            removed,
                            "banning store: purged stale rows"
                        ),
                        Err(err) => warn!(
                            target: "krakenwaf",
                            error = %err,
                            "banning store: purge failed"
                        ),
                    }
                }
            }
        });
    }
}

impl SqliteBanStore {
    /// Fallible-but-infallible helper used by the disabled constructor —
    /// the resulting store is never queried.
    pub(crate) fn in_memory_or_fallback() -> Self {
        Self::in_memory().expect("opening an in-memory SQLite must succeed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_manager_short_circuits() {
        let m = BanManager::disabled();
        assert!(!m.enabled());
        assert!(m.check("1.2.3.4").await.is_none());
        assert!(m.record_block("1.2.3.4", BlockReason::RuleDetection).await.is_none());
    }
}
