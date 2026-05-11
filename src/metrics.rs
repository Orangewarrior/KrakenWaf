
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Lightweight runtime counters exported via the `/metrics` endpoint.
///
/// Global counters are `AtomicU64`; per-module block counters are lazily
/// inserted into a `DashMap` keyed by `"engine:module"` (e.g.
/// `"cmc:sqli_comments_detect"`).
#[derive(Debug, Default)]
pub struct WafMetrics {
    pub requests_inspected: AtomicU64,
    pub requests_blocked: AtomicU64,
    pub rate_limit_hits: AtomicU64,
    /// Per-engine/module block counter.
    /// Key format: `"<engine>:<module>"` — e.g. `"cmc:java_deserialize_detect"`,
    /// `"keyword:uri"`, `"libinjection:sqli"`.
    blocks_by_label: DashMap<String, AtomicU64>,
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

    /// Increment the counter for a specific engine+module label.
    /// `label` should be `"<engine>:<module>"`, e.g. `"cmc:overflow_detect"`.
    pub fn inc_blocked_by_label(&self, label: &str) {
        self.blocks_by_label
            .entry(label.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Render all counters in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = format!(
            concat!(
                "# TYPE krakenwaf_requests_inspected_total counter\n",
                "krakenwaf_requests_inspected_total {}\n",
                "# TYPE krakenwaf_requests_blocked_total counter\n",
                "krakenwaf_requests_blocked_total {}\n",
                "# TYPE krakenwaf_rate_limit_hits_total counter\n",
                "krakenwaf_rate_limit_hits_total {}\n",
            ),
            self.requests_inspected.load(Ordering::Relaxed),
            self.requests_blocked.load(Ordering::Relaxed),
            self.rate_limit_hits.load(Ordering::Relaxed),
        );

        // Per-engine/module breakdown
        if !self.blocks_by_label.is_empty() {
            out.push_str(
                "# TYPE krakenwaf_module_blocks_total counter\n\
                 # HELP krakenwaf_module_blocks_total Requests blocked grouped by engine and module.\n",
            );
            let mut entries: Vec<(String, u64)> = self
                .blocks_by_label
                .iter()
                .map(|e| (e.key().clone(), e.value().load(Ordering::Relaxed)))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (label, count) in entries {
                // label is "engine:module" — split for Prometheus label syntax
                let (engine, module) = label.split_once(':').unwrap_or(("unknown", &label));
                out.push_str(&format!(
                    "krakenwaf_module_blocks_total{{engine=\"{engine}\",module=\"{module}\"}} {count}\n"
                ));
            }
        }

        out
    }
}
