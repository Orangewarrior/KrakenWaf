//! SQLite-backed BAN list. Always-available fallback when no distributed
//! Redis backend is configured for the WAF.
//!
//! Schema (single table):
//! ```text
//! banned_ips(
//!     ip            TEXT PRIMARY KEY,
//!     banned_until  INTEGER,           -- unix epoch seconds, NULL when not banned
//!     ban_count     INTEGER NOT NULL DEFAULT 0,
//!     occurrences   INTEGER NOT NULL DEFAULT 0,
//!     last_event_at INTEGER NOT NULL   -- unix epoch seconds, drives the 30-day purge
//! );
//! ```
//!
//! Concurrency: every read-modify-write goes through `IMMEDIATE` `SQLite`
//! transactions on a `parking_lot::Mutex<Connection>` so updates from
//! concurrent request threads are serialised and atomic.

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use std::{path::Path, sync::Arc, time::Duration};

use super::{BanRecord, RecordOutcome};

/// Counter reset window: occurrence + `ban_count` are purged after this much
/// inactivity. Matches the documented "1 month" promise.
const OCCURRENCE_RETENTION: Duration = Duration::from_hours(720);

pub struct SqliteBanStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteBanStore {
    /// Open or create the database at `path`. The file's parent directory
    /// is created if necessary.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be created or the
    /// database cannot be opened / migrated.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create banning store directory '{}'", parent.display())
            })?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open '{}'", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous  = NORMAL;
             PRAGMA busy_timeout = 5000;
             CREATE TABLE IF NOT EXISTS banned_ips (
                 ip            TEXT PRIMARY KEY,
                 banned_until  INTEGER,
                 ban_count     INTEGER NOT NULL DEFAULT 0,
                 occurrences   INTEGER NOT NULL DEFAULT 0,
                 last_event_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_banned_until ON banned_ips(banned_until);",
        )?;

        // Restrict file perms — like SqliteStore, the file is not encrypted
        // at rest and lists every IP banned by the WAF.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// In-memory store. Useful for the disabled manager (which never
    /// queries it) and for unit tests that want hermetic isolation.
    ///
    /// # Errors
    /// Returns an error if the in-memory `SQLite` connection or schema
    /// initialisation fails.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE banned_ips (
                ip TEXT PRIMARY KEY,
                banned_until INTEGER,
                ban_count INTEGER NOT NULL DEFAULT 0,
                occurrences INTEGER NOT NULL DEFAULT 0,
                last_event_at INTEGER NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Return the unix-epoch `banned_until` if `ip` is currently in the
    /// BAN list (and the ban has not yet expired), otherwise `None`.
    #[must_use] 
    pub fn lookup(&self, ip: &str, now: i64) -> Option<i64> {
        let conn = self.conn.lock();
        let row: Option<i64> = conn
            .query_row(
                "SELECT banned_until FROM banned_ips WHERE ip = ?1 AND banned_until IS NOT NULL AND banned_until > ?2",
                params![ip, now],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        row
    }

    /// Record one block occurrence and (when applicable) extend or open
    /// the ban window.
    ///
    /// When `force_ban_now` is true (the security-scanner shortcut), the
    /// `tolerance_block_count` threshold is bypassed and the IP is banned
    /// immediately. The occurrence counter is still incremented so audit
    /// queries see the event.
    ///
    /// # Errors
    /// Returns an error if the `SQLite` transaction fails.
    pub fn record_block(
        &self,
        ip: &str,
        now: i64,
        tolerance: u32,
        ban_wait_secs: i64,
        force_ban_now: bool,
    ) -> Result<RecordOutcome> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let existing = tx
            .query_row(
                "SELECT banned_until, ban_count, occurrences, last_event_at FROM banned_ips WHERE ip = ?1",
                params![ip],
                |r| {
                    Ok((
                        r.get::<_, Option<i64>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;

        let retention_secs = i64::try_from(OCCURRENCE_RETENTION.as_secs()).unwrap_or(i64::MAX);

        let (mut banned_until, mut ban_count, mut occurrences) = match existing {
            Some((bu, bc, oc, last)) => {
                if now.saturating_sub(last) > retention_secs {
                    // Counter expired — start fresh.
                    (None, 0_i64, 0_i64)
                } else {
                    (bu, bc, oc)
                }
            }
            None => (None, 0_i64, 0_i64),
        };

        // If the IP is currently banned, leave the window alone — the
        // server-layer check already short-circuits these requests, so
        // reaching this code path is exceptional. We still refresh
        // last_event_at to keep the row from being purged.
        let already_banned = matches!(banned_until, Some(until) if until > now);

        let mut triggered = None;

        if !already_banned {
            occurrences += 1;

            let should_ban = force_ban_now || occurrences >= i64::from(tolerance);

            if should_ban {
                ban_count += 1;
                let multiplier = ban_count.max(1);
                let extension = ban_wait_secs.saturating_mul(multiplier);
                let until = now.saturating_add(extension);
                banned_until = Some(until);
                occurrences = 0;
                triggered = Some(BanRecord {
                    banned_until: until,
                    ban_count,
                });
            }
        }

        tx.execute(
            "INSERT INTO banned_ips (ip, banned_until, ban_count, occurrences, last_event_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(ip) DO UPDATE SET
                 banned_until = excluded.banned_until,
                 ban_count = excluded.ban_count,
                 occurrences = excluded.occurrences,
                 last_event_at = excluded.last_event_at",
            params![ip, banned_until, ban_count, occurrences, now],
        )?;

        tx.commit()?;

        Ok(RecordOutcome {
            already_banned,
            triggered_ban: triggered,
            occurrences: occurrences.try_into().unwrap_or(u32::MAX),
        })
    }

    /// Delete rows whose `last_event_at` is older than the retention window.
    /// Invoked periodically by the housekeeping task.
    ///
    /// # Errors
    /// Returns an error when the DELETE statement fails.
    pub fn purge_stale(&self, now: i64) -> Result<usize> {
        let conn = self.conn.lock();
        let retention = i64::try_from(OCCURRENCE_RETENTION.as_secs()).unwrap_or(i64::MAX);
        let cutoff = now.saturating_sub(retention);
        let removed = conn.execute(
            "DELETE FROM banned_ips WHERE last_event_at < ?1 AND (banned_until IS NULL OR banned_until <= ?2)",
            params![cutoff, now],
        )?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_block_does_not_ban_below_threshold() {
        let s = SqliteBanStore::in_memory().expect("store");
        let r = s.record_block("1.1.1.1", 1000, 3, 60, false).expect("ok");
        assert!(r.triggered_ban.is_none());
        assert_eq!(r.occurrences, 1);
    }

    #[test]
    fn reaches_threshold_triggers_ban() {
        let s = SqliteBanStore::in_memory().expect("store");
        s.record_block("1.1.1.1", 1000, 3, 60, false).expect("ok");
        s.record_block("1.1.1.1", 1010, 3, 60, false).expect("ok");
        let r = s.record_block("1.1.1.1", 1020, 3, 60, false).expect("ok");
        let rec = r.triggered_ban.expect("ban triggered");
        assert_eq!(rec.ban_count, 1);
        assert_eq!(rec.banned_until, 1020 + 60);
        assert_eq!(s.lookup("1.1.1.1", 1025), Some(1020 + 60));
    }

    #[test]
    fn asymptotic_extension_on_repeat_bans() {
        let s = SqliteBanStore::in_memory().expect("store");
        // First ban — threshold 1 for brevity.
        let r1 = s.record_block("9.9.9.9", 1000, 1, 60, false).expect("ok");
        assert_eq!(r1.triggered_ban.expect("ban").banned_until, 1060);
        // Wait until the ban expires.
        let r2 = s.record_block("9.9.9.9", 2000, 1, 60, false).expect("ok");
        let rec2 = r2.triggered_ban.expect("ban");
        assert_eq!(rec2.ban_count, 2);
        assert_eq!(rec2.banned_until, 2000 + 60 * 2);
        let r3 = s.record_block("9.9.9.9", 3000, 1, 60, false).expect("ok");
        let rec3 = r3.triggered_ban.expect("ban");
        assert_eq!(rec3.ban_count, 3);
        assert_eq!(rec3.banned_until, 3000 + 60 * 3);
    }

    #[test]
    fn security_scanner_force_bans_on_first_hit() {
        let s = SqliteBanStore::in_memory().expect("store");
        let r = s.record_block("8.8.8.8", 1000, 10, 60, true).expect("ok");
        assert!(r.triggered_ban.is_some());
    }

    #[test]
    fn lookup_returns_none_after_expiry() {
        let s = SqliteBanStore::in_memory().expect("store");
        s.record_block("4.4.4.4", 1000, 1, 60, false).expect("ok");
        assert!(s.lookup("4.4.4.4", 1059).is_some());
        assert!(s.lookup("4.4.4.4", 1061).is_none());
    }

    #[test]
    fn counter_resets_after_retention_window() {
        let s = SqliteBanStore::in_memory().expect("store");
        s.record_block("7.7.7.7", 1000, 5, 60, false).expect("ok");
        let later = 1000 + i64::try_from(OCCURRENCE_RETENTION.as_secs()).expect("retention fits i64") + 10;
        let r = s.record_block("7.7.7.7", later, 5, 60, false).expect("ok");
        // Counter should have reset before incrementing; so occurrences == 1.
        assert_eq!(r.occurrences, 1);
    }

    #[test]
    fn already_banned_does_not_re_increment() {
        let s = SqliteBanStore::in_memory().expect("store");
        let r1 = s.record_block("2.2.2.2", 1000, 1, 60, false).expect("ok");
        assert!(r1.triggered_ban.is_some());
        let r2 = s.record_block("2.2.2.2", 1010, 1, 60, false).expect("ok");
        assert!(r2.already_banned);
        assert!(r2.triggered_ban.is_none());
    }

    #[test]
    fn purge_removes_expired_rows() {
        let s = SqliteBanStore::in_memory().expect("store");
        s.record_block("5.5.5.5", 1000, 5, 60, false).expect("ok");
        let later = 1000 + i64::try_from(OCCURRENCE_RETENTION.as_secs()).expect("retention fits i64") + 10;
        let removed = s.purge_stale(later).expect("ok");
        assert_eq!(removed, 1);
    }
}
