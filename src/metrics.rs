
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

const LATENCY_UPPER_BOUNDS_MS: [u64; 6] = [1, 5, 10, 50, 100, 1000];

/// Lightweight runtime counters exported via the /metrics endpoint.
#[derive(Debug, Default)]
pub struct WafMetrics {
    pub requests_inspected: AtomicU64,
    pub requests_blocked: AtomicU64,
    pub rate_limit_hits: AtomicU64,
    pub anomaly_score_blocks: AtomicU64,
    /// Histogram buckets: <1ms, <5ms, <10ms, <50ms, <100ms, <1s, >=1s.
    latency_buckets: [AtomicU64; 7],
    /// Per-rule hit counters keyed by rule_id.
    rule_hits: RwLock<HashMap<String, Arc<AtomicU64>>>,
}

impl WafMetrics {
    pub fn inc_inspected(&self) {
        self.requests_inspected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_blocked(&self) {
        self.requests_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rate_limit_hits(&self) {
        self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_anomaly_score_blocks(&self) {
        self.anomaly_score_blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_latency(&self, elapsed: Duration) {
        let ms = elapsed.as_millis() as u64;
        let bucket = LATENCY_UPPER_BOUNDS_MS
            .iter()
            .position(|&b| ms < b)
            .unwrap_or(LATENCY_UPPER_BOUNDS_MS.len());
        self.latency_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rule_hit(&self, rule_id: &str) {
        // Fast path: read lock only.
        if let Ok(map) = self.rule_hits.read() {
            if let Some(counter) = map.get(rule_id) {
                counter.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Slow path: insert new counter under write lock.
        if let Ok(mut map) = self.rule_hits.write() {
            map.entry(rule_id.to_string())
                .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        out.push_str("# TYPE krakenwaf_requests_inspected_total counter\n");
        out.push_str(&format!(
            "krakenwaf_requests_inspected_total {}\n",
            self.requests_inspected.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE krakenwaf_requests_blocked_total counter\n");
        out.push_str(&format!(
            "krakenwaf_requests_blocked_total {}\n",
            self.requests_blocked.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE krakenwaf_rate_limit_hits_total counter\n");
        out.push_str(&format!(
            "krakenwaf_rate_limit_hits_total {}\n",
            self.rate_limit_hits.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE krakenwaf_anomaly_score_blocks_total counter\n");
        out.push_str(&format!(
            "krakenwaf_anomaly_score_blocks_total {}\n",
            self.anomaly_score_blocks.load(Ordering::Relaxed)
        ));

        // Request latency histogram (Prometheus-compatible cumulative buckets).
        out.push_str("# TYPE krakenwaf_request_duration_ms histogram\n");
        let labels = ["1", "5", "10", "50", "100", "1000", "+Inf"];
        let mut cumulative: u64 = 0;
        for (i, label) in labels.iter().enumerate() {
            cumulative += self.latency_buckets[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "krakenwaf_request_duration_ms_bucket{{le=\"{label}\"}} {cumulative}\n"
            ));
        }
        out.push_str(&format!("krakenwaf_request_duration_ms_count {cumulative}\n"));

        // Per-rule hit counters.
        if let Ok(map) = self.rule_hits.read() {
            if !map.is_empty() {
                out.push_str("# TYPE krakenwaf_rule_hits_total counter\n");
                let mut pairs: Vec<_> = map
                    .iter()
                    .map(|(id, c)| (id.clone(), c.load(Ordering::Relaxed)))
                    .collect();
                pairs.sort_by(|a, b| a.0.cmp(&b.0));
                for (id, count) in pairs {
                    out.push_str(&format!(
                        "krakenwaf_rule_hits_total{{rule_id=\"{id}\"}} {count}\n"
                    ));
                }
            }
        }

        out
    }
}
