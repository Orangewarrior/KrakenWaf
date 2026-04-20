use crate::logging::SecurityEvent;
use anyhow::{Context, Result};
use sea_orm::{
    entity::prelude::*,
    ActiveValue::Set, ConnectOptions, Database, DatabaseBackend,
    DatabaseConnection, EntityTrait, Statement,
};
use std::{fs, path::Path, time::Duration};
use tokio::{sync::mpsc, time::interval};
use tracing::{error, warn};

/// Attack-payload rows older than this are purged to bound DB size.
const PAYLOAD_RETENTION_DAYS: i64 = 90;
const PURGE_INTERVAL: Duration = Duration::from_secs(24 * 3600);

#[derive(Clone)]
pub struct SqliteStore {
    tx: mpsc::UnboundedSender<SecurityEvent>,
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
    pub http_method: String,
    pub request_uri: String,
    pub fullpath_evidence: String,
    pub engine: String,
    pub request_payload: String,
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
    pub async fn new(root: &Path) -> Result<Self> {
        let db_dir = root.join("logs").join("db");
        fs::create_dir_all(&db_dir)?;
        let db_path = db_dir.join("vulns_alert.db");
        let url = format!("sqlite://{}?mode=rwc", db_path.display());

        let mut opts = ConnectOptions::new(url);
        opts.max_connections(8)
            .min_connections(1)
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

        let (tx, mut rx) = mpsc::unbounded_channel::<SecurityEvent>();
        let db_clone = db.clone();

        tokio::spawn(async move {
            let mut buffer = Vec::with_capacity(128);
            loop {
                match rx.recv().await {
                    Some(first) => {
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
                    None => break,
                }
            }
        });

        Ok(Self { tx })
    }

    pub fn enqueue(&self, event: SecurityEvent) {
        if let Err(err) = self.tx.send(event) {
            error!(target: "krakenwaf", "failed to enqueue security event: {err}");
        }
    }
}

async fn init_schema(db: &DatabaseConnection) -> Result<()> {
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA journal_mode=WAL;".to_owned())).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA foreign_keys=ON;".to_owned())).await?;

    let current_version = query_user_version(db).await?;
    if !table_exists(db, "vulnerabilities").await? {
        create_latest_schema(db).await?;
        set_user_version(db, 2).await?;
        return Ok(());
    }

    if current_version < 2 || !schema_is_latest(db).await? {
        migrate_to_v2(db).await?;
        set_user_version(db, 2).await?;
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

async fn schema_is_latest(db: &DatabaseConnection) -> Result<bool> {
    let required = [
        "id", "title", "severity", "cwe", "description", "reference_url", "occurred_at",
        "rule_match", "rule_line_match", "client_ip", "http_method", "request_uri",
        "fullpath_evidence", "engine", "request_payload",
    ];
    let rows = db
        .query_all(Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA table_info(vulnerabilities);".to_owned()))
        .await?;
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        if let Ok(name) = row.try_get::<String>("", "name") {
            seen.insert(name);
        }
    }
    Ok(required.iter().all(|name| seen.contains(*name)))
}

async fn create_latest_schema(db: &DatabaseConnection) -> Result<()> {
    db.execute(Statement::from_string(
        DatabaseBackend::Sqlite,
        r#"
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
            http_method VARCHAR(16) NOT NULL,
            request_uri TEXT NOT NULL,
            fullpath_evidence TEXT NOT NULL,
            engine VARCHAR(32) NOT NULL,
            request_payload TEXT NOT NULL
        );
        "#.to_owned(),
    )).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_occurred_at ON vulnerabilities(occurred_at DESC);".to_owned())).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);".to_owned())).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_engine ON vulnerabilities(engine);".to_owned())).await?;
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_title ON vulnerabilities(title);".to_owned())).await?;
    Ok(())
}


async fn migrate_to_v2(db: &DatabaseConnection) -> Result<()> {
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "BEGIN IMMEDIATE;".to_owned())).await?;
    let result: Result<()> = async {
        db.execute(Statement::from_string(DatabaseBackend::Sqlite, "ALTER TABLE vulnerabilities RENAME TO vulnerabilities_legacy;".to_owned())).await?;
        create_latest_schema(db).await?;
        db.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            r#"
            INSERT INTO vulnerabilities (
                id, title, severity, cwe, description, reference_url, occurred_at,
                rule_match, rule_line_match, client_ip, http_method, request_uri,
                fullpath_evidence, engine, request_payload
            )
            SELECT
                id,
                title,
                severity,
                cwe,
                description,
                reference_url,
                occurred_at,
                rule_match,
                rule_line_match,
                '' AS client_ip,
                '' AS http_method,
                '' AS request_uri,
                '' AS fullpath_evidence,
                CASE
                    WHEN rule_line_match LIKE 'Vectorscan/%' THEN 'vectorscan'
                    WHEN rule_line_match LIKE 'regex/%' THEN 'regex'
                    WHEN rule_match LIKE 'libinjection::%' THEN 'libinjection'
                    ELSE 'keyword'
                END AS engine,
                request_payload
            FROM vulnerabilities_legacy;
            "#.to_owned(),
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

async fn batch_insert(db: &DatabaseConnection, events: &[SecurityEvent]) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }

    let models = events.iter().map(|event| ActiveModel {
        id: Default::default(),
        title: Set(event.title.clone()),
        severity: Set(event.severity.to_string()),
        cwe: Set(event.cwe.clone()),
        description: Set(event.description.clone()),
        reference_url: Set(event.reference_url.clone()),
        occurred_at: Set(event.timestamp.clone()),
        rule_match: Set(event.rule_match.clone()),
        rule_line_match: Set(event.rule_line_match.clone()),
        client_ip: Set(event.client_ip.clone()),
        http_method: Set(event.method.clone()),
        request_uri: Set(event.uri.clone()),
        fullpath_evidence: Set(event.fullpath_evidence.clone()),
        engine: Set(event.engine.clone()),
        request_payload: Set(event.request_payload.clone()),
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
