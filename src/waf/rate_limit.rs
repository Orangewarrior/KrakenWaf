
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::{fs, sync::Mutex, time::interval};
use tracing::warn;

/// Maximum number of distinct client IPs we will track simultaneously. Prevents an
/// attacker who can spoof or rotate source IPs (especially when behind a trusted
/// proxy that the attacker can influence via `X-Forwarded-For`) from forcing the
/// counters map to grow without bound.
const MAX_TRACKED_IPS: usize = 100_000;

/// Upper bound on snapshot file size we are willing to deserialize at startup. The
/// snapshot is operator-owned but a hostile container volume could otherwise feed
/// us an arbitrary-size payload.
const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;

/// How often the background sweeper drops counters whose window has expired.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// How often the background task flushes counters to disk.
const PERSIST_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    counters: Mutex<HashMap<String, Counter>>,
    snapshot_path: PathBuf,
}

#[derive(Debug, Clone)]
struct Counter {
    count: u32,
    started_at_epoch_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCounter {
    ip: String,
    count: u32,
    started_at_epoch_secs: u64,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration, snapshot_path: PathBuf) -> Result<Self> {
        let counters = tokio::task::block_in_place(|| load_snapshot(&snapshot_path));

        Ok(Self {
            limit,
            window,
            counters: Mutex::new(counters),
            snapshot_path,
        })
    }

    pub fn spawn_persistence_task(self: std::sync::Arc<Self>) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let sweeper = self.clone();
            handle.spawn(async move {
                let mut ticker = interval(SWEEP_INTERVAL);
                loop {
                    ticker.tick().await;
                    sweeper.sweep_expired().await;
                }
            });

            let persister = self;
            handle.spawn(async move {
                let mut ticker = interval(PERSIST_INTERVAL);
                loop {
                    ticker.tick().await;
                    if let Err(err) = persister.persist().await {
                        warn!(target: "krakenwaf", error=%err, "rate limiter snapshot write failed");
                    }
                }
            });
        }
    }

    /// Per-request hot path. Critical-section work is bounded to O(1) amortized:
    /// the previously O(n) `retain` was moved to a periodic sweeper task above.
    pub async fn check(&self, ip: &str) -> bool {
        let mut map = self.counters.lock().await;
        let now = epoch_secs();
        let window_secs = self.window.as_secs();

        if map.len() >= MAX_TRACKED_IPS && !map.contains_key(ip) {
            evict_one(&mut map, now, window_secs);
        }

        let entry = map.entry(ip.to_string()).or_insert(Counter {
            count: 0,
            started_at_epoch_secs: now,
        });

        if now.saturating_sub(entry.started_at_epoch_secs) >= window_secs {
            entry.count = 0;
            entry.started_at_epoch_secs = now;
        }

        entry.count = entry.count.saturating_add(1);
        entry.count <= self.limit
    }

    async fn sweep_expired(&self) {
        let now = epoch_secs();
        let window_secs = self.window.as_secs();
        let mut map = self.counters.lock().await;
        map.retain(|_, v| now.saturating_sub(v.started_at_epoch_secs) < window_secs);
    }

    pub async fn persist(&self) -> Result<()> {
        let rows: Vec<PersistedCounter> = {
            let map = self.counters.lock().await;
            map.iter().map(|(ip, item)| PersistedCounter {
                ip: ip.clone(),
                count: item.count,
                started_at_epoch_secs: item.started_at_epoch_secs,
            }).collect()
        };

        if let Some(parent) = self.snapshot_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let payload = serde_json::to_vec_pretty(&rows)?;
        // Write to a sibling temp file then rename so readers never see a
        // partial JSON file if the process crashes mid-write.
        let tmp_path = self.snapshot_path.with_extension("json.tmp");
        fs::write(&tmp_path, &payload).await?;
        fs::rename(&tmp_path, &self.snapshot_path).await?;
        Ok(())
    }
}

fn load_snapshot(path: &std::path::Path) -> HashMap<String, Counter> {
    if !path.exists() {
        return HashMap::new();
    }

    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(err) => {
            warn!(target: "krakenwaf", error=%err, path=%path.display(), "rate limiter snapshot stat failed");
            return HashMap::new();
        }
    };
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        warn!(
            target: "krakenwaf",
            size = metadata.len(),
            limit = MAX_SNAPSHOT_BYTES,
            path = %path.display(),
            "rate limiter snapshot exceeds size limit; ignoring"
        );
        return HashMap::new();
    }

    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) => {
            warn!(target: "krakenwaf", error=%err, path=%path.display(), "rate limiter snapshot read failed");
            return HashMap::new();
        }
    };

    let parsed: Vec<PersistedCounter> = serde_json::from_str(&raw).unwrap_or_default();
    parsed
        .into_iter()
        .take(MAX_TRACKED_IPS)
        .map(|item| (item.ip, Counter { count: item.count, started_at_epoch_secs: item.started_at_epoch_secs }))
        .collect()
}

/// Evict either an expired entry (preferred) or the oldest non-expired entry,
/// keeping map size bounded under hostile IP-rotation patterns.
fn evict_one(map: &mut HashMap<String, Counter>, now: u64, window_secs: u64) {
    let mut oldest_key: Option<String> = None;
    let mut oldest_started: u64 = u64::MAX;
    let mut expired_key: Option<String> = None;

    for (key, value) in map.iter() {
        if now.saturating_sub(value.started_at_epoch_secs) >= window_secs {
            expired_key = Some(key.clone());
            break;
        }
        if value.started_at_epoch_secs < oldest_started {
            oldest_started = value.started_at_epoch_secs;
            oldest_key = Some(key.clone());
        }
    }

    if let Some(k) = expired_key.or(oldest_key) {
        map.remove(&k);
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
