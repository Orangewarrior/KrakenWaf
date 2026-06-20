//! TTL cache for Spamhaus DQS DNS-over-TLS reputation lookups.
//!
//! ## Threat model addressed
//!
//! Each Spamhaus DQS check is a DNS-over-TLS query with a multi-second timeout,
//! and it runs on the **request hot path** inside the WAF engine's early
//! inspection (`inspect_early`). Without caching, every request from a
//! not-yet-known IP forces a fresh DNS-over-TLS round-trip before the request can
//! proceed — an attacker rotating source addresses (trivial across an IPv6 /64)
//! turns each request into an outbound DNS-over-TLS lookup, both amplifying load and
//! adding seconds of tail latency. This is a denial-of-service vector against
//! the WAF itself.
//!
//! ## Design
//!
//! A lock-free [`DashMap`] keyed by `(IpAddr, zone)`. Each entry stores an
//! absolute expiry [`Instant`] and the resolved outcome:
//!
//! * `Some(match)` — the IP is listed in that zone (a *positive* result).
//! * `None` — the IP is not listed (a *negative* result).
//!
//! Positive and negative results carry independent TTLs: the negative TTL is
//! kept shorter so a freshly-listed IP starts being blocked sooner, while the
//! positive TTL can be long because a listed IP rarely de-lists within an hour.
//!
//! Lookup errors are **never cached** — a transient DNS-over-TLS failure must not pin a
//! "not listed" verdict; the next request retries.
//!
//! Memory is bounded by [`MAX_ENTRIES`]: an insert that would exceed the cap
//! first sweeps expired entries, and only inserts if that frees room. Combined
//! with TTL expiry this keeps the map from growing without bound under IP
//! rotation.

use crate::update::SpamhausDqsMatch;
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Hard ceiling on distinct cached `(ip, zone)` entries. At ~100 bytes/entry
/// this bounds the cache to a few MiB even when full.
const MAX_ENTRIES: usize = 131_072;

#[derive(Clone)]
struct CacheEntry {
    expires_at: Instant,
    /// `Some` = listed (positive), `None` = not listed (negative).
    result: Option<SpamhausDqsMatch>,
}

/// Outcome of a cache [`SpamhausDqsCache::get`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    /// No fresh entry — the caller must perform a live DQS lookup.
    Miss,
    /// Cached *negative*: the IP is known not to be listed in this zone.
    NotListed,
    /// Cached *positive*: the IP is listed; carries the recorded match.
    Listed(SpamhausDqsMatch),
}

/// Bounded, TTL-expiring cache of Spamhaus DQS lookup outcomes.
pub struct SpamhausDqsCache {
    entries: DashMap<(IpAddr, String), CacheEntry>,
    positive_ttl: Duration,
    negative_ttl: Duration,
    max_entries: usize,
}

impl SpamhausDqsCache {
    /// Construct a cache with the given positive/negative TTLs.
    #[must_use]
    pub fn new(positive_ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            positive_ttl,
            negative_ttl,
            max_entries: MAX_ENTRIES,
        }
    }

    /// Look up a cached outcome for `(ip, zone)` as of `now`. See [`CacheLookup`].
    #[must_use]
    pub fn get(&self, ip: &IpAddr, zone: &str, now: Instant) -> CacheLookup {
        let Some(entry) = self.entries.get(&(*ip, zone.to_string())) else {
            return CacheLookup::Miss;
        };
        if entry.expires_at <= now {
            return CacheLookup::Miss;
        }
        match &entry.result {
            Some(hit) => CacheLookup::Listed(hit.clone()),
            None => CacheLookup::NotListed,
        }
    }

    /// Record a lookup outcome for `(ip, zone)`, expiring at `now + ttl` where
    /// the TTL is chosen by whether the result is positive or negative.
    pub fn insert(
        &self,
        ip: IpAddr,
        zone: &str,
        result: Option<SpamhausDqsMatch>,
        now: Instant,
    ) {
        // Bound memory: when at capacity, reclaim expired slots first and only
        // insert if that actually frees room, so a flood of distinct IPs cannot
        // grow the map past the cap.
        if self.entries.len() >= self.max_entries {
            self.sweep(now);
            if self.entries.len() >= self.max_entries {
                return;
            }
        }
        let ttl = if result.is_some() {
            self.positive_ttl
        } else {
            self.negative_ttl
        };
        // If `now + ttl` overflows `Instant` (astronomically unlikely — it needs
        // an `Instant` near the monotonic-clock ceiling) fall back to `now`,
        // which makes the entry expire immediately. That fails safe: a fresh
        // lookup runs next time rather than the entry living effectively forever.
        let expires_at = now.checked_add(ttl).unwrap_or(now);
        self.entries
            .insert((ip, zone.to_string()), CacheEntry { expires_at, result });
    }

    /// Drop every entry whose TTL has elapsed as of `now`.
    pub fn sweep(&self, now: Instant) {
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    /// Number of currently-held entries (including not-yet-swept expired ones).
    #[must_use]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache currently holds no entries.
    #[must_use]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn match_for(zone: &str) -> SpamhausDqsMatch {
        SpamhausDqsMatch {
            zone: zone.to_string(),
            query: "example.query".to_string(),
            response: "127.0.0.2".parse().expect("ip"),
        }
    }

    fn ip() -> IpAddr {
        "203.0.113.7".parse().expect("ip")
    }

    #[test]
    fn miss_when_empty() {
        let cache = SpamhausDqsCache::new(Duration::from_mins(1), Duration::from_mins(1));
        assert_eq!(cache.get(&ip(), "sbl", Instant::now()), CacheLookup::Miss);
    }

    #[test]
    fn positive_hit_is_returned_within_ttl() {
        let cache = SpamhausDqsCache::new(Duration::from_hours(1), Duration::from_mins(5));
        let now = Instant::now();
        cache.insert(ip(), "sbl", Some(match_for("sbl")), now);
        match cache.get(&ip(), "sbl", now) {
            CacheLookup::Listed(hit) => assert_eq!(hit.zone, "sbl"),
            other => panic!("expected Listed, got {other:?}"),
        }
    }

    #[test]
    fn negative_hit_is_distinguished_from_miss() {
        let cache = SpamhausDqsCache::new(Duration::from_hours(1), Duration::from_mins(5));
        let now = Instant::now();
        cache.insert(ip(), "sbl", None, now);
        // NotListed means "known not listed" — distinct from Miss.
        assert_eq!(cache.get(&ip(), "sbl", now), CacheLookup::NotListed);
    }

    #[test]
    fn positive_entry_expires_after_its_ttl() {
        let positive = Duration::from_hours(1);
        let cache = SpamhausDqsCache::new(positive, Duration::from_mins(5));
        let now = Instant::now();
        cache.insert(ip(), "sbl", Some(match_for("sbl")), now);
        let after = now + positive + Duration::from_secs(1);
        assert_eq!(cache.get(&ip(), "sbl", after), CacheLookup::Miss, "must expire");
    }

    #[test]
    fn negative_ttl_is_shorter_than_positive() {
        let positive = Duration::from_hours(1);
        let negative = Duration::from_mins(5);
        let cache = SpamhausDqsCache::new(positive, negative);
        let now = Instant::now();
        cache.insert(ip(), "sbl", None, now);
        // Past the negative TTL the negative entry is gone …
        let after_negative = now + negative + Duration::from_secs(1);
        assert_eq!(cache.get(&ip(), "sbl", after_negative), CacheLookup::Miss);
        // … whereas a positive entry inserted at the same time would still live.
        cache.insert(ip(), "xbl", Some(match_for("xbl")), now);
        assert!(matches!(
            cache.get(&ip(), "xbl", after_negative),
            CacheLookup::Listed(_)
        ));
    }

    #[test]
    fn zones_are_cached_independently() {
        let cache = SpamhausDqsCache::new(Duration::from_hours(1), Duration::from_mins(5));
        let now = Instant::now();
        cache.insert(ip(), "sbl", Some(match_for("sbl")), now);
        cache.insert(ip(), "xbl", None, now);
        assert!(matches!(
            cache.get(&ip(), "sbl", now),
            CacheLookup::Listed(_)
        ));
        assert_eq!(cache.get(&ip(), "xbl", now), CacheLookup::NotListed);
    }

    #[test]
    fn sweep_drops_expired_entries() {
        let ttl = Duration::from_mins(1);
        let cache = SpamhausDqsCache::new(ttl, ttl);
        let now = Instant::now();
        cache.insert(ip(), "sbl", None, now);
        assert_eq!(cache.len(), 1);
        cache.sweep(now + ttl + Duration::from_secs(1));
        assert_eq!(cache.len(), 0);
    }
}
