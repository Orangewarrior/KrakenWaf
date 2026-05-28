//! Integration test: verifies that GeoIP country/continent fields are correctly
//! saved in the SQLite vulnerability log when an attack arrives with an external
//! IP via X-Forwarded-For.
//!
//! Topology:
//!   reqwest → KrakenWaf (--no-tls, --real-ip-header x-forwarded-for) → Axum backend
//!
//! The WAF binary runs in a temp directory that has db/geo/GeoLite2-City.mmdb
//! symlinked in from the project root.  After sending a SQLi payload the test
//! queries the SQLite DB and asserts country/continent_name are populated.
//!
//! # Prerequisites
//! - `db/geo/GeoLite2-City.mmdb` must exist (run `soldier_update --geo-update`).
//! - `Banning_mode: false` should be set in `conf/banning.yaml` before running
//!   any test loop to avoid banning 127.0.0.1.

use rusqlite::Connection;
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    time::Duration,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    l.local_addr().expect("local_addr").port()
}

fn waf_base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .expect("test")
}

struct WafGuard {
    child: Child,
    _tmpdir: tempfile::TempDir,
}

impl Drop for WafGuard {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Spin up a backend that echoes the query param `q` unsanitised.
fn spawn_backend() -> (u16, std::thread::JoinHandle<()>) {
    use axum::{extract::Query, response::Html, routing::get, Router};
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Q {
        #[serde(default)]
        q: String,
    }
    async fn handler(Query(p): Query<Q>) -> Html<String> {
        Html(format!("<h1>{}</h1>", p.q))
    }
    let port = pick_free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let handle = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let app = Router::new().route("/search", get(handler));
                let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                axum::serve(listener, app).await.unwrap();
            });
    });
    std::thread::sleep(Duration::from_millis(200));
    (port, handle)
}

/// Spawn the KrakenWaf binary.
///
/// `geo_active` controls whether `conf/update.yaml` in the tmpdir marks
/// `maxmind-geo.active` as true or false.  When false the WAF must not load
/// the GeoIP database even if the `.mmdb` file is present.
fn spawn_geo_waf(waf_port: u16, backend_port: u16) -> Option<WafGuard> {
    spawn_geo_waf_with_active(waf_port, backend_port, true)
}

fn spawn_geo_waf_with_active(waf_port: u16, backend_port: u16, geo_active: bool) -> Option<WafGuard> {
    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let db_src = project_root.join("db/geo/GeoLite2-City.mmdb");
    if !db_src.exists() {
        eprintln!(
            "[geoip_waf_test] SKIP: {} not found — run soldier_update --geo-update",
            db_src.display()
        );
        return None;
    }

    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let geo_dir = tmpdir.path().join("db/geo");
    std::fs::create_dir_all(&geo_dir).expect("create db/geo");

    // Symlink the mmdb so the test doesn't copy 63 MB on every run.
    let db_dst = geo_dir.join("GeoLite2-City.mmdb");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&db_src, &db_dst).expect("symlink mmdb");
    #[cfg(not(unix))]
    std::fs::copy(&db_src, &db_dst).expect("copy mmdb");

    // Write conf/update.yaml so the WAF respects the active flag.
    let conf_dir = tmpdir.path().join("conf");
    std::fs::create_dir_all(&conf_dir).expect("create conf");
    std::fs::write(
        conf_dir.join("update.yaml"),
        format!(
            "maxmind-geo:\n  active: {geo_active}\n  account_id: \"\"\n  key: \"\"\n  cron: \"0 18 1 * *\"\n"
        ),
    )
    .expect("write update.yaml");

    let rules_dir = project_root.join("rules");
    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://127.0.0.1:{backend_port}");

    let child = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .args([
            "--no-tls",
            "--allow-private-upstream",
            "--listen",
            &listen,
            "--upstream",
            &upstream,
            "--rules-dir",
            rules_dir.to_str().unwrap(),
            "--real-ip-header",
            "x-forwarded-for",
            "--trusted-proxy-cidrs",
            "127.0.0.0/8",
        ])
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn krakenwaf");

    Some(WafGuard {
        child,
        _tmpdir: tmpdir,
    })
}

async fn wait_for_waf(client: &reqwest::Client, port: u16) {
    let url = format!("{}/__krakenwaf/health", waf_base(port));
    for _ in 0..150 {
        if client
            .get(&url)
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("KrakenWaf on port {port} did not become ready");
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// Sends a SQL injection attack via the WAF using X-Forwarded-For: 8.8.8.8,
/// then reads the SQLite DB to verify country and continent_name are populated.
#[tokio::test]
async fn geo_country_saved_in_sqlite_for_external_ip() {
    let (backend_port, _backend) = spawn_backend();
    let waf_port = pick_free_port();

    let Some(waf) = spawn_geo_waf(waf_port, backend_port) else {
        return; // DB absent — skip
    };

    let client = http_client();
    wait_for_waf(&client, waf_port).await;

    // Send a classic SQL injection payload. The WAF (libinjection) will block it.
    // X-Forwarded-For: 8.8.8.8 → Google DNS → United States / North America
    let resp = client
        .get(format!(
            "{}/search?q=' OR 1=1--",
            waf_base(waf_port)
        ))
        .header("x-forwarded-for", "8.8.8.8")
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status().as_u16(),
        403,
        "WAF must block the SQLi payload"
    );

    // Give the async SQLite writer a moment to flush the event.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Read the SQLite DB from the WAF's temp workdir.
    let db_path = waf
        ._tmpdir
        .path()
        .join("logs/db/vulns_alert.db");
    assert!(db_path.exists(), "SQLite DB must exist after a blocked request");

    let conn = Connection::open(&db_path).expect("open vulns_alert.db");
    let (country, continent): (String, String) = conn
        .query_row(
            "SELECT country, continent_name FROM vulnerabilities ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query vulnerabilities");

    assert_eq!(
        country, "United States",
        "country must be 'United States' for 8.8.8.8 (Google DNS)"
    );
    assert_eq!(
        continent, "North America",
        "continent_name must be 'North America' for 8.8.8.8"
    );

    drop(waf);
}

/// Same attack with a European IP (185.220.101.34 — Tor exit range, Germany).
#[tokio::test]
async fn geo_country_saved_for_european_ip() {
    let (backend_port, _backend) = spawn_backend();
    let waf_port = pick_free_port();

    let Some(waf) = spawn_geo_waf(waf_port, backend_port) else {
        return;
    };

    let client = http_client();
    wait_for_waf(&client, waf_port).await;

    let resp = client
        .get(format!("{}/search?q=1 UNION SELECT 1,2,3--", waf_base(waf_port)))
        .header("x-forwarded-for", "185.220.101.34")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status().as_u16(), 403, "WAF must block UNION SELECT");

    tokio::time::sleep(Duration::from_millis(800)).await;

    let db_path = waf._tmpdir.path().join("logs/db/vulns_alert.db");
    let conn = Connection::open(&db_path).expect("open db");
    let (country, continent): (String, String) = conn
        .query_row(
            "SELECT country, continent_name FROM vulnerabilities ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query");

    assert!(
        !country.is_empty(),
        "European IP should resolve to a country (got empty)"
    );
    assert_eq!(continent, "Europe", "185.220.101.34 should be in Europe");

    drop(waf);
}

/// Verify that a private/loopback IP yields empty geo fields (not an error).
#[tokio::test]
async fn geo_fields_empty_for_private_ip() {
    let (backend_port, _backend) = spawn_backend();
    let waf_port = pick_free_port();

    let Some(waf) = spawn_geo_waf(waf_port, backend_port) else {
        return;
    };

    let client = http_client();
    wait_for_waf(&client, waf_port).await;

    // No X-Forwarded-For — effective IP is 127.0.0.1 (loopback → empty geo).
    let resp = client
        .get(format!("{}/search?q=' OR '1'='1", waf_base(waf_port)))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status().as_u16(), 403, "WAF must block the SQLi");

    tokio::time::sleep(Duration::from_millis(800)).await;

    let db_path = waf._tmpdir.path().join("logs/db/vulns_alert.db");
    let conn = Connection::open(&db_path).expect("open db");
    let (country, continent): (String, String) = conn
        .query_row(
            "SELECT country, continent_name FROM vulnerabilities ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query");

    assert!(
        country.is_empty(),
        "loopback IP must yield empty country, got: {country}"
    );
    assert!(
        continent.is_empty(),
        "loopback IP must yield empty continent, got: {continent}"
    );

    drop(waf);
}

/// When `maxmind-geo.active: false` in conf/update.yaml, the WAF must NOT
/// load the GeoIP database and must save empty country/continent_name even
/// for public IPs — the .mmdb file is present but should be ignored.
#[tokio::test]
async fn geo_disabled_via_active_false_saves_empty_fields() {
    let (backend_port, _backend) = spawn_backend();
    let waf_port = pick_free_port();

    let Some(waf) = spawn_geo_waf_with_active(waf_port, backend_port, false) else {
        return;
    };

    let client = http_client();
    wait_for_waf(&client, waf_port).await;

    // 8.8.8.8 would normally resolve to United States, but geo is disabled.
    let resp = client
        .get(format!("{}/search?q=' OR 1=1--", waf_base(waf_port)))
        .header("x-forwarded-for", "8.8.8.8")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status().as_u16(), 403, "WAF must still block the SQLi");

    tokio::time::sleep(Duration::from_millis(800)).await;

    let db_path = waf._tmpdir.path().join("logs/db/vulns_alert.db");
    let conn = Connection::open(&db_path).expect("open db");
    let (country, continent): (String, String) = conn
        .query_row(
            "SELECT country, continent_name FROM vulnerabilities ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query");

    assert!(
        country.is_empty(),
        "active: false must yield empty country even for public IP 8.8.8.8, got: {country}"
    );
    assert!(
        continent.is_empty(),
        "active: false must yield empty continent even for public IP 8.8.8.8, got: {continent}"
    );

    drop(waf);
}
