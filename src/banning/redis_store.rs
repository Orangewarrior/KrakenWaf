//! Redis/Valkey-backed BAN list. Reuses the `fred::clients::Pool` produced
//! for the distributed rate-limiter so a single TLS pool serves both
//! subsystems. The per-IP state lives in a Redis Hash:
//!
//! ```text
//! HSET <key_prefix>:<ip>
//!     banned_until    <unix_seconds>
//!     ban_count       <int>
//!     occurrences     <int>
//!     last_event_at   <unix_seconds>
//! EXPIRE <key_prefix>:<ip> <30d>
//! ```
//!
//! Each record_block call is wrapped in a Lua script so the read-decide-write
//! sequence is atomic from a Redis client perspective. All operations are
//! guarded by an `op_timeout` — a hung Redis must never stall the WAF
//! request path; the implementation fails open in that situation.

use anyhow::Result;
use fred::clients::Pool as FredPool;
use fred::prelude::*;
use std::time::Duration;
use tracing::warn;

use super::{BanRecord, RecordOutcome};

/// 30 days, matching the SQLite store's documented retention.
const RETENTION_SECS: i64 = 30 * 24 * 3_600;

/// Tiny lookup script. Returns banned_until (0 when not currently banned
/// or no record exists) so the call-site can decide via a single EVAL.
const LOOKUP_LUA: &str = r"
local now = tonumber(ARGV[1])
local v = tonumber(redis.call('HGET', KEYS[1], 'banned_until')) or 0
if v > now then return v end
return 0
";

/// Atomic record-block script.
///
/// KEYS[1] — full Redis key for this IP.
/// ARGV[1] — now (unix seconds)
/// ARGV[2] — tolerance_block_count
/// ARGV[3] — ban_wait_secs
/// ARGV[4] — force_ban_now ("1"/"0")
/// ARGV[5] — retention TTL (seconds)
///
/// Returns: { already_banned (0/1), occurrences, banned_until (0 when not banned), ban_count }
const RECORD_BLOCK_LUA: &str = r#"
local key            = KEYS[1]
local now            = tonumber(ARGV[1])
local tolerance      = tonumber(ARGV[2])
local ban_wait       = tonumber(ARGV[3])
local force          = ARGV[4] == "1"
local retention      = tonumber(ARGV[5])

local banned_until   = tonumber(redis.call("HGET", key, "banned_until")) or 0
local ban_count      = tonumber(redis.call("HGET", key, "ban_count"))    or 0
local occurrences    = tonumber(redis.call("HGET", key, "occurrences"))  or 0
local last_event_at  = tonumber(redis.call("HGET", key, "last_event_at")) or 0

if (now - last_event_at) > retention then
    banned_until  = 0
    ban_count     = 0
    occurrences   = 0
end

local already_banned = 0
if banned_until > now then
    already_banned = 1
end

if already_banned == 0 then
    occurrences = occurrences + 1
    local should_ban = force or (occurrences >= tolerance)
    if should_ban then
        ban_count = ban_count + 1
        local multiplier = ban_count
        if multiplier < 1 then multiplier = 1 end
        banned_until = now + ban_wait * multiplier
        occurrences = 0
    end
end

redis.call("HSET", key,
    "banned_until", banned_until,
    "ban_count", ban_count,
    "occurrences", occurrences,
    "last_event_at", now)
redis.call("EXPIRE", key, retention)

return { already_banned, occurrences, banned_until, ban_count }
"#;

pub struct RedisBanStore {
    pool: FredPool,
    key_prefix: String,
    op_timeout: Duration,
}

impl RedisBanStore {
    /// Build a Redis-backed store reusing an existing `fred` pool.
    #[must_use]
    pub fn new(pool: FredPool, key_prefix: impl Into<String>) -> Self {
        Self {
            pool,
            key_prefix: key_prefix.into(),
            // Same budget as the rate-limiter EVAL. A degraded Redis must
            // not dominate WAF tail latency.
            op_timeout: Duration::from_millis(150),
        }
    }

    fn key(&self, ip: &str) -> String {
        format!("{}:{}", self.key_prefix, ip)
    }

    /// Returns `Some(banned_until)` when `ip` is currently banned, else
    /// `None`. Fails open (returns `None`) on Redis errors or timeouts.
    pub async fn lookup(&self, ip: &str, now: i64) -> Option<i64> {
        let key = self.key(ip);
        let fut = self
            .pool
            .eval::<i64, _, _, _>(LOOKUP_LUA, vec![key], vec![now.to_string()]);
        match tokio::time::timeout(self.op_timeout, fut).await {
            Ok(Ok(0)) => None,
            Ok(Ok(until)) => Some(until),
            Ok(Err(err)) => {
                warn!(target: "krakenwaf", error = %err, ip, "Redis ban lookup failed; failing open");
                None
            }
            Err(_) => {
                warn!(target: "krakenwaf", ip, "Redis ban lookup timed out; failing open");
                None
            }
        }
    }

    /// Atomic increment + (optional) ban. See [`RECORD_BLOCK_LUA`].
    /// Returns a default-allowed [`RecordOutcome`] on Redis failure so the
    /// WAF cannot brick itself if Redis becomes unhealthy mid-flight.
    pub async fn record_block(
        &self,
        ip: &str,
        now: i64,
        tolerance: u32,
        ban_wait_secs: i64,
        force_ban_now: bool,
    ) -> Result<RecordOutcome> {
        let key = self.key(ip);
        let args: Vec<String> = vec![
            now.to_string(),
            tolerance.to_string(),
            ban_wait_secs.to_string(),
            (if force_ban_now { "1" } else { "0" }).to_string(),
            RETENTION_SECS.to_string(),
        ];
        let fut = self
            .pool
            .eval::<Vec<i64>, _, _, _>(RECORD_BLOCK_LUA, vec![key], args);

        match tokio::time::timeout(self.op_timeout, fut).await {
            Ok(Ok(values)) => Ok(parse_outcome(&values)),
            Ok(Err(err)) => {
                warn!(target: "krakenwaf", error = %err, ip, "Redis ban EVAL failed; failing open");
                Ok(RecordOutcome::default())
            }
            Err(_) => {
                warn!(target: "krakenwaf", ip, "Redis ban EVAL timed out; failing open");
                Ok(RecordOutcome::default())
            }
        }
    }
}

fn parse_outcome(values: &[i64]) -> RecordOutcome {
    let already_banned = values.first().copied().unwrap_or(0) == 1;
    let occurrences = u32::try_from(values.get(1).copied().unwrap_or(0)).unwrap_or(0);
    let banned_until = values.get(2).copied().unwrap_or(0);
    let ban_count = values.get(3).copied().unwrap_or(0);

    let triggered_ban = if !already_banned && banned_until > 0 {
        Some(BanRecord {
            banned_until,
            ban_count,
        })
    } else {
        None
    };

    RecordOutcome {
        already_banned,
        triggered_ban,
        occurrences,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_outcome_when_not_banned() {
        // already_banned=0, occurrences=2, banned_until=0, ban_count=0
        let r = parse_outcome(&[0, 2, 0, 0]);
        assert!(!r.already_banned);
        assert_eq!(r.occurrences, 2);
        assert!(r.triggered_ban.is_none());
    }

    #[test]
    fn parse_outcome_when_just_banned() {
        let r = parse_outcome(&[0, 0, 2000, 1]);
        assert!(r.triggered_ban.is_some());
        let rec = r.triggered_ban.unwrap();
        assert_eq!(rec.banned_until, 2000);
        assert_eq!(rec.ban_count, 1);
    }

    #[test]
    fn parse_outcome_when_already_banned() {
        let r = parse_outcome(&[1, 0, 2000, 1]);
        assert!(r.already_banned);
        assert!(r.triggered_ban.is_none());
    }
}
