
use dashmap::DashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

// ── Latency histogram ─────────────────────────────────────────────────────────

/// Prometheus-compatible cumulative histogram with 11 configurable upper bounds
/// plus an implicit `+Inf` bucket. All operations are lock-free.
///
/// Bucket upper bounds (milliseconds): 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500
const LATENCY_UPPER_MS: &[u64] = &[1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500];

#[derive(Debug, Default)]
pub struct LatencyHistogram {
    /// One cumulative counter per upper bound + one for +Inf.
    buckets: [AtomicU64; 12],
    count: AtomicU64,
    sum_ms: AtomicU64,
}

impl LatencyHistogram {
    /// Record one observation of `ms` milliseconds.
    pub fn observe(&self, ms: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ms.fetch_add(ms, Ordering::Relaxed);
        // Increment every bucket whose upper bound is ≥ ms (Prometheus cumulative).
        for (i, &upper) in LATENCY_UPPER_MS.iter().enumerate() {
            if ms <= upper {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // +Inf always counts.
        self.buckets[LATENCY_UPPER_MS.len()].fetch_add(1, Ordering::Relaxed);
    }

    fn render_prometheus(&self, name: &str, out: &mut String) {
        let count = self.count.load(Ordering::Relaxed);
        let sum = self.sum_ms.load(Ordering::Relaxed);
        let _ = writeln!(out, "# TYPE {name} histogram");
        for (i, &upper) in LATENCY_UPPER_MS.iter().enumerate() {
            let v = self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(out, "{name}_bucket{{le=\"{upper}\"}} {v}");
        }
        let inf = self.buckets[LATENCY_UPPER_MS.len()].load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {inf}");
        let _ = writeln!(out, "{name}_count {count}");
        let _ = writeln!(out, "{name}_sum {sum}");
    }
}

// ── WafMetrics ────────────────────────────────────────────────────────────────

/// Lightweight runtime counters and histograms exported via the `/metrics` endpoint.
///
/// Global counters are `AtomicU64`; per-module block counters are lazily
/// inserted into a `DashMap` keyed by `"engine:module"` (e.g.
/// `"cmc:sqli_comments_detect"`).
#[derive(Debug, Default)]
pub struct WafMetrics {
    pub requests_inspected: AtomicU64,
    pub requests_blocked: AtomicU64,
    pub rate_limit_hits: AtomicU64,

    /// Requests allowed without a rate-limit decision because the Redis
    /// limiter was unreachable/slow and the configured policy is fail-open.
    /// A climbing value means rate limiting is currently NOT enforced — alert
    /// on `rate(...[5m]) > 0`.
    pub redis_rate_limit_failopen: AtomicU64,
    /// Requests denied (HTTP 429) because the Redis limiter was unreachable/slow
    /// and the operator selected fail-closed.
    pub redis_rate_limit_failclosed: AtomicU64,

    /// W3C traceparent counters.
    pub traceparent_forwarded: AtomicU64,
    pub traceparent_generated: AtomicU64,

    /// End-to-end request latency histogram (milliseconds, wall clock).
    pub request_latency_ms: LatencyHistogram,

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

    /// Record a Redis rate-limiter unavailability that was resolved by the
    /// configured fail mode. `allowed == true` ⇒ fail-open (request let through);
    /// `allowed == false` ⇒ fail-closed (request denied with 429).
    pub fn inc_redis_rate_limit_fail(&self, allowed: bool) {
        if allowed {
            self.redis_rate_limit_failopen.fetch_add(1, Ordering::Relaxed);
        } else {
            self.redis_rate_limit_failclosed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment the counter for a specific engine+module label.
    /// `label` should be `"<engine>:<module>"`, e.g. `"cmc:overflow_detect"`.
    pub fn inc_blocked_by_label(&self, label: &str) {
        self.blocks_by_label
            .entry(label.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a completed request latency in milliseconds.
    pub fn observe_latency_ms(&self, ms: u64) {
        self.request_latency_ms.observe(ms);
    }

    /// Increment the counter for a forwarded W3C traceparent.
    pub fn inc_traceparent_forwarded(&self) {
        self.traceparent_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the counter for a generated (new) W3C traceparent.
    pub fn inc_traceparent_generated(&self) {
        self.traceparent_generated.fetch_add(1, Ordering::Relaxed);
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
                "# TYPE krakenwaf_redis_rate_limit_failopen_total counter\n",
                "# HELP krakenwaf_redis_rate_limit_failopen_total Requests allowed without a rate-limit decision because Redis was unavailable (fail-open).\n",
                "krakenwaf_redis_rate_limit_failopen_total {}\n",
                "# TYPE krakenwaf_redis_rate_limit_failclosed_total counter\n",
                "# HELP krakenwaf_redis_rate_limit_failclosed_total Requests denied because Redis was unavailable and the fail mode is fail-closed.\n",
                "krakenwaf_redis_rate_limit_failclosed_total {}\n",
                "# TYPE krakenwaf_traceparent_forwarded_total counter\n",
                "krakenwaf_traceparent_forwarded_total {}\n",
                "# TYPE krakenwaf_traceparent_generated_total counter\n",
                "krakenwaf_traceparent_generated_total {}\n",
            ),
            self.requests_inspected.load(Ordering::Relaxed),
            self.requests_blocked.load(Ordering::Relaxed),
            self.rate_limit_hits.load(Ordering::Relaxed),
            self.redis_rate_limit_failopen.load(Ordering::Relaxed),
            self.redis_rate_limit_failclosed.load(Ordering::Relaxed),
            self.traceparent_forwarded.load(Ordering::Relaxed),
            self.traceparent_generated.load(Ordering::Relaxed),
        );

        self.request_latency_ms.render_prometheus(
            "krakenwaf_request_duration_milliseconds",
            &mut out,
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
                let _ = writeln!(
                    out,
                    "krakenwaf_module_blocks_total{{engine=\"{engine}\",module=\"{module}\"}} {count}"
                );
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::WafMetrics;

    /// The enriched regex-rule label ("<title>, ID <id>:Regex rule") must be
    /// rendered with the rule identity as the engine and "Regex rule" as the
    /// module — not the old blind `engine="unknown",module="regex"`.
    #[test]
    fn regex_rule_label_renders_title_and_id() {
        let metrics = WafMetrics::default();
        metrics.inc_blocked_by_label("Shell downloader body, ID 00003:Regex rule");

        let out = metrics.render_prometheus();
        assert!(
            out.contains(
                "krakenwaf_module_blocks_total{engine=\"Shell downloader body, ID 00003\",module=\"Regex rule\"} 1"
            ),
            "unexpected exposition output:\n{out}"
        );
        assert!(
            !out.contains("engine=\"unknown\""),
            "regex rule blocks must no longer be attributed to unknown:\n{out}"
        );
    }

    #[test]
    fn cmc_label_renders_engine_and_module() {
        let metrics = WafMetrics::default();
        metrics.inc_blocked_by_label("cmc:sqli_comments_detect");

        let out = metrics.render_prometheus();
        assert!(out.contains(
            "krakenwaf_module_blocks_total{engine=\"cmc\",module=\"sqli_comments_detect\"} 1"
        ));
    }
}
