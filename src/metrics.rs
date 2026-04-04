
use std::sync::atomic::{AtomicU64, Ordering};

/// Lightweight runtime counters exported via the internal metrics endpoint.
#[derive(Debug, Default)]
pub struct WafMetrics {
    pub requests_inspected: AtomicU64,
    pub requests_blocked: AtomicU64,
    pub rate_limit_hits: AtomicU64,
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

    pub fn render_prometheus(&self) -> String {
        format!(
            concat!(
                "# TYPE krakenwaf_requests_inspected_total counter\n",
                "krakenwaf_requests_inspected_total {}\n",
                "# TYPE krakenwaf_requests_blocked_total counter\n",
                "krakenwaf_requests_blocked_total {}\n",
                "# TYPE krakenwaf_rate_limit_hits_total counter\n",
                "krakenwaf_rate_limit_hits_total {}\n"
            ),
            self.requests_inspected.load(Ordering::Relaxed),
            self.requests_blocked.load(Ordering::Relaxed),
            self.rate_limit_hits.load(Ordering::Relaxed)
        )
    }
}
