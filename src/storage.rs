
use crate::logging::{sanitize_payload, SecurityEvent};
use anyhow::Result;
use sea_orm::{
    entity::prelude::*,
    ActiveValue::Set, ConnectOptions, Database, DatabaseBackend,
    DatabaseConnection, EntityTrait, Statement,
};
use std::{fs, path::Path, time::Duration};
use tokio::sync::mpsc;
use tracing::{error, warn};

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
    db.execute(Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA user_version=1;".to_owned())).await?;
    db.execute(Statement::from_string(
        DatabaseBackend::Sqlite,
        r#"
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            cwe TEXT NOT NULL,
            description TEXT NOT NULL,
            reference_url TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            rule_match TEXT NOT NULL,
            rule_line_match TEXT NOT NULL,
            request_payload TEXT NOT NULL
        );
        "#.to_owned(),
    )).await?;
    Ok(())
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
        request_payload: Set(sanitize_payload(&event.request_payload)),
    }).collect::<Vec<_>>();

    Entity::insert_many(models).exec(db).await?;
    Ok(())
}
