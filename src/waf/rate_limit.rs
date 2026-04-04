
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::{sync::Mutex, time::interval};

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
        let counters = if snapshot_path.exists() {
            let raw = fs::read_to_string(&snapshot_path).unwrap_or_default();
            serde_json::from_str::<Vec<PersistedCounter>>(&raw)
                .unwrap_or_default()
                .into_iter()
                .map(|item| (item.ip, Counter { count: item.count, started_at_epoch_secs: item.started_at_epoch_secs }))
                .collect()
        } else {
            HashMap::new()
        };

        Ok(Self {
            limit,
            window,
            counters: Mutex::new(counters),
            snapshot_path,
        })
    }

    pub fn spawn_persistence_task(self: std::sync::Arc<Self>) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let mut ticker = interval(Duration::from_secs(30));
                loop {
                    ticker.tick().await;
                    let _ = self.persist().await;
                }
            });
        }
    }

    pub async fn check(&self, ip: &str) -> bool {
        let mut map = self.counters.lock().await;
        let now = epoch_secs();

        map.retain(|_, v| now.saturating_sub(v.started_at_epoch_secs) < self.window.as_secs());

        let entry = map.entry(ip.to_string()).or_insert(Counter {
            count: 0,
            started_at_epoch_secs: now,
        });

        if now.saturating_sub(entry.started_at_epoch_secs) >= self.window.as_secs() {
            entry.count = 0;
            entry.started_at_epoch_secs = now;
        }

        entry.count += 1;
        entry.count <= self.limit
    }

    pub async fn persist(&self) -> Result<()> {
        let map = self.counters.lock().await;
        let rows = map.iter().map(|(ip, item)| PersistedCounter {
            ip: ip.clone(),
            count: item.count,
            started_at_epoch_secs: item.started_at_epoch_secs,
        }).collect::<Vec<_>>();
        if let Some(parent) = self.snapshot_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.snapshot_path, serde_json::to_vec_pretty(&rows)?)?;
        Ok(())
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
