use crate::logging::SecurityEvent;
use anyhow::{Context, Result};
use sea_orm::{
    entity::prelude::*,
    ActiveValue, ActiveValue::Set, ConnectOptions, Database, DatabaseBackend,
    DatabaseConnection, EntityTrait, Statement,
};
use std::{fs, path::Path, time::Duration};
use tokio::{sync::mpsc, time::interval};
use tracing::{error, warn};

/// Attack-payload rows older than this are purged to bound DB size.
const PAYLOAD_RETENTION_DAYS: i64 = 90;
const PURGE_INTERVAL: Duration = Duration::from_hours(24);

/// Schema version stamped into `PRAGMA user_version` by `create_latest_schema`.
/// This is the single source of truth for "newest schema this binary knows".
/// `create_latest_schema` already emits every column up to this version, so a
/// freshly created database must be tagged with it — otherwise the matching
/// `migrate_to_vN` step re-runs on the next start and an `ADD COLUMN` fails on
/// a column that already exists. Bump this in lockstep with each new migration.
const LATEST_SCHEMA_VERSION: i64 = 4;

#[derive(Clone)]
pub struct SqliteStore {
    tx: mpsc::Sender<SecurityEvent>,
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "vulnerabilities")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub title: String,
    pub severity: String,
    pub cwe: String,
    pub description: String,
    pub reference_url: String,
    pub occurred_at: String,
    pub rule_match: String,
    pub rule_line_match: String,
    pub client_ip: String,
    pub country: String,
    pub continent_name: String,
    pub http_method: String,
    pub request_uri: String,
    pub fullpath_evidence: String,
    pub engine: String,
    pub request_payload: String,
    pub request_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        panic!("no relations")
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl SqliteStore {
    /// # Errors
    /// Returns an error if the database directory cannot be created or the `SQLite` connection fails.
    pub async fn new(root: &Path) -> Result<Self> {
        let db_dir = root.join("logs").join("db");
        fs::create_dir_all(&db_dir)?;
        let db_path = db_dir.join("vulns_alert.db");
        let url = format!("sqlite://{}?mode=rwc", db_path.display());

        let mut opts = ConnectOptions::new(url);
        opts.max_connections(16)
            .min_connections(2)
            .connect_timeout(Duration::from_secs(5))
            .sqlx_logging(false);

        let db = Database::connect(opts).await?;
        init_schema(&db).await?;

        // Restrict the DB file to owner-only so other OS users cannot read
        // stored attack payloads (SQLite files are not encrypted at rest).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&db_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = fs::set_permissions(&db_path, perms);
            }
        }

        // Background purge: delete rows older than PAYLOAD_RETENTION_DAYS so the
        // DB does not grow unboundedly from long-running attack campaigns.
        let db_purge = db.clone();
        tokio::spawn(async move {
            let mut ticker = interval(PURGE_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(err) = purge_old_events(&db_purge).await {
                    warn!(target: "krakenwaf", "sqlite purge failed: {err:#}");
                }
            }
        });

        let (tx, mut rx) = mpsc::channel::<SecurityEvent>(1024);
        let db_clone = db.clone();

        tokio::spawn(async move {
            let mut buffer = Vec::with_capacity(128);
            while let Some(first) = rx.recv().await {
                buffer.push(first);
                while buffer.len() < 128 {
                    match rx.try_recv() {
                        Ok(item) => buffer.push(item),
                        Err(_) => break,
                    }
                }

                if let Err(err) = batch_insert(&db_clone, &buffer).await {
                    warn!(target: "krakenwaf", "sqlite batch insert failed: {err:#}");
                }
                buffer.clear();
            }
        });

        Ok(Self { tx })
    }

    pub fn enqueue(&self, event: SecurityEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(target: "krakenwaf", "security event queue full — dropping event (backpressure)");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!(target: "krakenwaf", "security event queue closed — event dropped");
            }
        }
    }
}

async fn init_schema(db: &DatabaseConnection) -> Result<()> {
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA journal_mode=WAL;".to_owned())).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA foreign_keys=ON;".to_owned())).await?;

    let current_version = query_user_version(db).await?;

    if !table_exists(db, "vulnerabilities").await? {
        create_latest_schema(db).await?;
        set_user_version(db, LATEST_SCHEMA_VERSION).await?;
        return Ok(());
    }

    // v1 → v2: adds client_ip, http_method, request_uri, fullpath_evidence, engine columns.
    if current_version < 2 || !column_exists(db, "vulnerabilities", "engine").await? {
        migrate_to_v2(db).await?;
        set_user_version(db, 2).await?;
    }

    // v2 → v3: adds request_id VARCHAR(32) for per-request correlation ID support.
    if current_version < 3 || !column_exists(db, "vulnerabilities", "request_id").await? {
        migrate_to_v3(db).await?;
        set_user_version(db, 3).await?;
    }

    // v3 → v4: adds country and continent_name for GeoIP enrichment.
    if current_version < 4 || !column_exists(db, "vulnerabilities", "country").await? {
        migrate_to_v4(db).await?;
        set_user_version(db, 4).await?;
    }

    Ok(())
}

async fn query_user_version(db: &DatabaseConnection) -> Result<i64> {
    let stmt = Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA user_version;".to_owned());
    let row = db.query_one(stmt).await?;
    Ok(row
        .and_then(|r| r.try_get_by_index::<i64>(0).ok())
        .unwrap_or(0))
}

async fn set_user_version(db: &DatabaseConnection, version: i64) -> Result<()> {
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, format!("PRAGMA user_version={version};"))).await?;
    Ok(())
}

async fn table_exists(db: &DatabaseConnection, name: &str) -> Result<bool> {
    let row = db.query_one(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
        [name.to_owned().into()],
    )).await?;
    Ok(row.is_some())
}

async fn column_exists(db: &DatabaseConnection, table: &str, column: &str) -> Result<bool> {
    let rows = db
        .query_all(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!("PRAGMA table_info({table});"),
        ))
        .await?;
    for row in rows {
        if let Ok(name) = row.try_get::<String>("", "name") {
            if name == column {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Add a column to `table` only if it is not already present.
///
/// `SQLite` has no `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, and a bare
/// `ADD COLUMN` errors when the column already exists. Guarding on
/// `column_exists` makes the column migrations **idempotent**: re-running one
/// against an already-upgraded table is a safe no-op instead of a hard failure.
/// That keeps startup robust across restarts in the same working directory, a
/// legacy database whose `user_version` was never stamped, or a migration that
/// was interrupted partway through.
///
/// `ddl` must be a compile-time-constant `ALTER TABLE ... ADD COLUMN …`
/// statement — never request data (see the SQL-safety note below).
async fn add_column_if_missing(
    db: &DatabaseConnection,
    table: &str,
    column: &str,
    ddl: &str,
) -> Result<()> {
    if column_exists(db, table, column).await? {
        return Ok(());
    }
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, ddl.to_owned()))
        .await?;
    Ok(())
}

async fn create_latest_schema(db: &DatabaseConnection) -> Result<()> {
    db.execute(Statement::from_string(
        DatabaseBackend::Sqlite,
        r"
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title VARCHAR(256) NOT NULL,
            severity VARCHAR(32) NOT NULL,
            cwe VARCHAR(128) NOT NULL,
            description TEXT NOT NULL,
            reference_url TEXT NOT NULL,
            occurred_at TIMESTAMP NOT NULL,
            rule_match TEXT NOT NULL,
            rule_line_match VARCHAR(256) NOT NULL,
            client_ip VARCHAR(64) NOT NULL,
            country VARCHAR(128) NOT NULL DEFAULT '',
            continent_name VARCHAR(64) NOT NULL DEFAULT '',
            http_method VARCHAR(16) NOT NULL,
            request_uri TEXT NOT NULL,
            fullpath_evidence TEXT NOT NULL,
            engine VARCHAR(32) NOT NULL,
            request_payload TEXT NOT NULL,
            request_id VARCHAR(32) NOT NULL DEFAULT ''
        );
        ".to_owned(),
    )).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_occurred_at ON vulnerabilities(occurred_at DESC);".to_owned())).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);".to_owned())).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_engine ON vulnerabilities(engine);".to_owned())).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_title ON vulnerabilities(title);".to_owned())).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_request_id ON vulnerabilities(request_id);".to_owned())).await?;
    Ok(())
}

async fn migrate_to_v2(db: &DatabaseConnection) -> Result<()> {
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "BEGIN IMMEDIATE;".to_owned())).await?;
    let result: Result<()> = async {
        db.execute(Statement::from_string(DatabaseBackend::Sqlite, "ALTER TABLE vulnerabilities RENAME TO vulnerabilities_legacy;".to_owned())).await?;
        create_latest_schema(db).await?;
        db.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            r"
            INSERT INTO vulnerabilities (
                id, title, severity, cwe, description, reference_url, occurred_at,
                rule_match, rule_line_match, client_ip, country, continent_name,
                http_method, request_uri, fullpath_evidence, engine, request_payload, request_id
            )
            SELECT
                id, title, severity, cwe, description, reference_url, occurred_at,
                rule_match, rule_line_match,
                '' AS client_ip,
                '' AS country,
                '' AS continent_name,
                '' AS http_method,
                '' AS request_uri,
                '' AS fullpath_evidence,
                CASE
                    WHEN rule_line_match LIKE 'Vectorscan/%' THEN 'vectorscan'
                    WHEN rule_line_match LIKE 'regex/%' THEN 'regex'
                    WHEN rule_match LIKE 'libinjection::%' THEN 'libinjection'
                    ELSE 'keyword'
                END AS engine,
                request_payload,
                '' AS request_id
            FROM vulnerabilities_legacy;
            ".to_owned(),
        )).await?;
        db.execute(Statement::from_string(DatabaseBackend::Sqlite, "DROP TABLE vulnerabilities_legacy;".to_owned())).await?;
        Ok(())
    }.await;

    match result {
        Ok(()) => {
            db.execute(Statement::from_string(DatabaseBackend::Sqlite, "COMMIT;".to_owned())).await?;
            Ok(())
        }
        Err(err) => {
            let _ = db.execute(Statement::from_string(DatabaseBackend::Sqlite, "ROLLBACK;".to_owned())).await;
            Err(err).context("failed to migrate vulnerabilities table to schema v2")
        }
    }
}

async fn migrate_to_v3(db: &DatabaseConnection) -> Result<()> {
    add_column_if_missing(
        db,
        "vulnerabilities",
        "request_id",
        "ALTER TABLE vulnerabilities ADD COLUMN request_id VARCHAR(32) NOT NULL DEFAULT '';",
    )
    .await
    .context("failed to add request_id column (schema v3)")?;

    db.execute(Statement::from_string(
        DatabaseBackend::Sqlite,
        "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_request_id ON vulnerabilities(request_id);".to_owned(),
    ))
    .await
    .context("failed to create request_id index (schema v3)")?;

    Ok(())
}

async fn migrate_to_v4(db: &DatabaseConnection) -> Result<()> {
    add_column_if_missing(
        db,
        "vulnerabilities",
        "country",
        "ALTER TABLE vulnerabilities ADD COLUMN country VARCHAR(128) NOT NULL DEFAULT '';",
    )
    .await
    .context("failed to add country column (schema v4)")?;

    add_column_if_missing(
        db,
        "vulnerabilities",
        "continent_name",
        "ALTER TABLE vulnerabilities ADD COLUMN continent_name VARCHAR(64) NOT NULL DEFAULT '';",
    )
    .await
    .context("failed to add continent_name column (schema v4)")?;

    Ok(())
}

// SAFETY (SQL): every dynamic value reaching SQLite goes through SeaORM's `ActiveModel`
// (see `batch_insert` below) or `Statement::from_sql_and_values` with a positional `?`
// placeholder (see `table_exists` and `purge_old_events`). No untrusted string is ever
// concatenated into a raw SQL string. The `format!()` calls in this file (PRAGMAs,
// ALTER TABLE, table-name introspection) operate exclusively on compile-time constants
// or values controlled by the operator running the binary — never on request data.

/// Normalises the RFC 3339 timestamp emitted by the engine
/// (e.g. `2026-06-08T15:42:14.282795004+00:00`) into the human-friendly
/// `YYYY-MM-DD HH:MM:SS` UTC form (e.g. `2026-06-08 15:42:14`) stored in the
/// `occurred_at` column. This format also matches `SQLite`'s `datetime('now')`
/// output, keeping `purge_old_events` comparisons correct. If the input cannot
/// be parsed, the original string is preserved so no forensic data is lost.
fn format_occurred_at(raw: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(raw).map_or_else(
        |_| raw.to_string(),
        |dt| dt.naive_utc().format("%Y-%m-%d %H:%M:%S").to_string(),
    )
}

async fn batch_insert(db: &DatabaseConnection, events: &[SecurityEvent]) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }

    let models = events.iter().map(|event| ActiveModel {
        id: ActiveValue::default(),
        title: Set(event.title.clone()),
        severity: Set(event.severity.to_string()),
        cwe: Set(event.cwe.clone()),
        description: Set(event.description.clone()),
        reference_url: Set(event.reference_url.clone()),
        occurred_at: Set(format_occurred_at(&event.timestamp)),
        rule_match: Set(event.rule_match.clone()),
        rule_line_match: Set(event.rule_line_match.clone()),
        client_ip: Set(event.client_ip.clone()),
        country: Set(event.country.clone()),
        continent_name: Set(event.continent_name.clone()),
        http_method: Set(event.method.clone()),
        request_uri: Set(event.uri.clone()),
        fullpath_evidence: Set(event.fullpath_evidence.clone()),
        engine: Set(event.engine.clone()),
        request_payload: Set(event.request_payload.clone()),
        request_id: Set(event.request_id.clone()),
    }).collect::<Vec<_>>();

    Entity::insert_many(models).exec(db).await?;
    Ok(())
}

async fn purge_old_events(db: &DatabaseConnection) -> Result<()> {
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "DELETE FROM vulnerabilities WHERE occurred_at < datetime('now', ?);",
        [format!("-{PAYLOAD_RETENTION_DAYS} days").into()],
    )).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `occurred_at` must be stored in the human-friendly `YYYY-MM-DD HH:MM:SS`
    /// UTC form, regardless of the sub-second precision or offset in the source
    /// RFC 3339 timestamp.
    #[test]
    fn occurred_at_is_human_readable() {
        assert_eq!(
            format_occurred_at("2026-06-08T15:42:14.282795004+00:00"),
            "2026-06-08 15:42:14"
        );
        // A non-UTC offset is normalised to UTC.
        assert_eq!(
            format_occurred_at("2026-06-08T17:42:14+02:00"),
            "2026-06-08 15:42:14"
        );
    }

    /// An unparseable timestamp must be preserved verbatim so forensic data is
    /// never silently dropped.
    #[test]
    fn occurred_at_preserves_unparseable_input() {
        assert_eq!(format_occurred_at("not-a-timestamp"), "not-a-timestamp");
    }

    /// Open a fresh connection to a `SQLite` file, mirroring `SqliteStore::new`.
    /// A new connection per call faithfully simulates a process restart against
    /// the same on-disk database.
    async fn connect(path: &Path) -> DatabaseConnection {
        let url = format!("sqlite://{}?mode=rwc", path.display());
        Database::connect(url).await.expect("connect sqlite")
    }

    /// A freshly created database must be stamped with the newest schema version
    /// and carry every column `create_latest_schema` emits. If the stamp lags the
    /// real schema, the matching migration re-runs on the next boot.
    #[tokio::test]
    async fn fresh_schema_is_stamped_at_latest_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("vulns.db");
        let db = connect(&db_path).await;

        init_schema(&db).await.expect("init fresh schema");

        assert_eq!(
            query_user_version(&db).await.expect("user_version"),
            LATEST_SCHEMA_VERSION,
            "fresh schema must be stamped at the latest version"
        );
        for col in ["request_id", "country", "continent_name"] {
            assert!(
                column_exists(&db, "vulnerabilities", col).await.expect("introspect"),
                "fresh schema is missing column `{col}`"
            );
        }
    }

    /// Regression: running the WAF twice from the same working directory used to
    /// panic on the second start with `duplicate column name: country` — the
    /// fresh schema was stamped v3 while already carrying the v4 columns, so the
    /// v4 migration re-ran an `ADD COLUMN` against an existing column. A second
    /// `init_schema` (here via a brand-new connection, as a real restart would)
    /// must now be a clean no-op.
    #[tokio::test]
    async fn init_schema_is_idempotent_across_restarts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("vulns.db");

        {
            let first = connect(&db_path).await;
            init_schema(&first).await.expect("first boot");
        }
        {
            let second = connect(&db_path).await;
            init_schema(&second)
                .await
                .expect("second boot must not fail (regression: duplicate column)");
            assert_eq!(
                query_user_version(&second).await.expect("user_version"),
                LATEST_SCHEMA_VERSION
            );
        }
        // A third boot on the same file is still a no-op.
        let third = connect(&db_path).await;
        init_schema(&third).await.expect("third boot");
    }

    /// A legacy database that already has the latest columns but whose
    /// `user_version` was never stamped (reads back as 0) must upgrade cleanly:
    /// the idempotent `ADD COLUMN` guards turn the forced migrations into no-ops
    /// and the version is brought up to date.
    #[tokio::test]
    async fn legacy_unstamped_db_with_columns_upgrades_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("vulns.db");
        let db = connect(&db_path).await;

        // Build the full current schema, then forcibly reset the version stamp
        // to 0 to mimic a database created before `user_version` tracking.
        create_latest_schema(&db).await.expect("create schema");
        set_user_version(&db, 0).await.expect("reset version");

        init_schema(&db).await.expect("legacy upgrade must not fail");

        assert_eq!(
            query_user_version(&db).await.expect("user_version"),
            LATEST_SCHEMA_VERSION
        );
    }
}
