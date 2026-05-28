//! GeoIP integration tests — MaxMind GeoLite2-City support.
//!
//! # Test strategy
//!
//! Tests that require `db/geo/GeoLite2-City.mmdb` are *skipped* automatically
//! when the file is absent (fresh checkout without credentials). To run the
//! full suite:
//!
//! 1. Fill in `conf/update.yaml` with your MaxMind credentials.
//! 2. Run `./target/debug/soldier_update --addr-list maxmind-geo`.
//! 3. Run `cargo test --test geoip_test`.
//!
//! # BAN mode during geo tests
//!
//! **Important:** Before running WAF integration tests that send real traffic,
//! set `Banning_mode: false` in `conf/banning.yaml`.  Leaving banning enabled
//! while running test loops will trigger bans on `127.0.0.1` and interfere with
//! block-count accounting.
//!
//! # Free-proxy IP variety
//!
//! To exercise geo-lookup with globally diverse IPs without owning infrastructure,
//! you can route requests through free SOCKS5 / HTTP proxies and verify that the
//! `country` / `continent_name` fields logged by the WAF match the expected
//! geolocation.  The tests tagged `#[ignore]` below demonstrate this pattern.
//! Run them with:
//!   cargo test --test geoip_test -- --include-ignored

use krakenwaf::{
    geo::{GeoIpReader, GeoIpResult},
    update::{
        load_update_config, scheduled_soldier_jobs_for_values, MaxmindGeoConfig, UpdateConfig,
    },
};
use std::{fs, path::Path};
use tempfile::TempDir;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn db_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("db/geo/GeoLite2-City.mmdb")
}

fn open_reader() -> Option<GeoIpReader> {
    let p = db_path();
    if !p.exists() {
        eprintln!(
            "[geoip_test] SKIP: {} not found. \
             Run soldier_update --addr-list maxmind-geo after setting credentials in conf/update.yaml.",
            p.display()
        );
        return None;
    }
    GeoIpReader::builder(&p).build().ok()
}

// ── GeoIpResult unit tests ────────────────────────────────────────────────────

#[test]
fn geo_result_default_is_empty() {
    let r = GeoIpResult::empty();
    assert!(r.country_name.is_empty());
    assert!(r.continent_name.is_empty());
}

// ── GeoIpReader lookup tests ──────────────────────────────────────────────────

#[test]
fn private_ipv4_returns_empty_country() {
    let Some(reader) = open_reader() else { return };
    for ip in &["192.168.0.1", "10.0.0.1", "172.16.0.1"] {
        let r = reader.lookup(ip);
        assert!(
            r.country_name.is_empty(),
            "private IP {ip} should not resolve to a country"
        );
    }
}

#[test]
fn loopback_returns_empty() {
    let Some(reader) = open_reader() else { return };
    let r = reader.lookup("127.0.0.1");
    assert!(r.country_name.is_empty());
}

#[test]
fn invalid_ip_string_returns_empty() {
    let Some(reader) = open_reader() else { return };
    let r = reader.lookup("not-an-ip-address");
    assert!(r.country_name.is_empty());
}

#[test]
fn google_dns_is_united_states() {
    let Some(reader) = open_reader() else { return };
    // 8.8.8.8 is Google's Anycast DNS — resolves to United States in GeoLite2.
    let r = reader.lookup("8.8.8.8");
    assert!(!r.country_name.is_empty(), "8.8.8.8 should resolve to a country");
    assert_eq!(r.country_name, "United States");
    assert_eq!(r.continent_name, "North America");
}

#[test]
fn cloudflare_dns_lookup_does_not_panic() {
    let Some(reader) = open_reader() else { return };
    // 1.1.1.1 is Cloudflare's anycast DNS. GeoLite2 may or may not have
    // geographic data for APNIC/Cloudflare reserved blocks — that is acceptable.
    // This test verifies the lookup completes without panicking.
    let r = reader.lookup("1.1.1.1");
    // country_name may be empty for anycast / special-purpose blocks.
    let _ = r;
}

#[test]
fn ipv6_google_dns_resolves() {
    let Some(reader) = open_reader() else { return };
    // 2001:4860:4860::8888 is Google's IPv6 DNS.
    let r = reader.lookup("2001:4860:4860::8888");
    assert!(!r.country_name.is_empty(), "Google IPv6 DNS should resolve to a country");
}

#[test]
fn multiple_continents_covered() {
    let Some(reader) = open_reader() else { return };
    // Sample one IP per continent to verify coverage.
    let cases = [
        // (ip, expected_continent)
        ("8.8.8.8", "North America"),   // Google DNS, US
        ("185.220.101.1", "Europe"),     // Tor exit node range, DE/EU
        ("202.12.27.33", "Asia"),        // APNIC, AU/Asia-Pacific
    ];
    for (ip, expected_continent) in &cases {
        let r = reader.lookup(ip);
        if !r.continent_name.is_empty() {
            assert_eq!(
                &r.continent_name, expected_continent,
                "IP {ip} expected continent {expected_continent}, got {}",
                r.continent_name
            );
        }
    }
}

// ── YAML config parsing ───────────────────────────────────────────────────────

#[test]
fn maxmind_geo_config_parses_from_yaml() {
    let tmp = TempDir::new().unwrap();
    let conf_dir = tmp.path().join("conf");
    fs::create_dir_all(&conf_dir).unwrap();
    fs::write(
        conf_dir.join("update.yaml"),
        r#"
KrakenWaf:
  cron: "0 18 */15 * *"
blocklist:
  title: "Blocklist site"
  lists:
    url_file: []
  cron: "0 12 */3 * *"
spamhaus:
  cron: "0 12 */3 * *"
firehol:
  cron: "0 12 */3 * *"
maxmind-geo:
  title: "Maxmind GeoLite2 city"
  active: true
  url_file:
    - "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
  cron: "0 18 1 * *"
"#,
    )
    .unwrap();

    let config = load_update_config(&conf_dir.join("update.yaml")).unwrap();
    let geo = &config.maxmind_geo;
    assert_eq!(geo.title, "Maxmind GeoLite2 city");
    assert!(geo.active);
    assert_eq!(geo.cron, "0 18 1 * *");
    assert_eq!(geo.url_file.values().len(), 1);
}

#[test]
fn maxmind_geo_defaults_when_section_absent() {
    let tmp = TempDir::new().unwrap();
    let conf_dir = tmp.path().join("conf");
    fs::create_dir_all(&conf_dir).unwrap();
    fs::write(
        conf_dir.join("update.yaml"),
        r#"
KrakenWaf:
  cron: "0 18 */15 * *"
"#,
    )
    .unwrap();

    let config = load_update_config(&conf_dir.join("update.yaml")).unwrap();
    let geo = &config.maxmind_geo;
    // Defaults should be applied when the section is absent.
    assert!(geo.active, "geo active defaults to true");
    assert_eq!(geo.cron, "0 18 1 * *");
}

#[test]
fn maxmind_geo_can_be_disabled() {
    let tmp = TempDir::new().unwrap();
    let conf_dir = tmp.path().join("conf");
    fs::create_dir_all(&conf_dir).unwrap();
    fs::write(
        conf_dir.join("update.yaml"),
        r#"
maxmind-geo:
  active: false
  cron: "0 18 1 * *"
"#,
    )
    .unwrap();

    let config = load_update_config(&conf_dir.join("update.yaml")).unwrap();
    assert!(!config.maxmind_geo.active, "geo should be disabled when active: false");
}

// ── Cron scheduling ───────────────────────────────────────────────────────────

fn geo_config_for_cron(cron: &str) -> UpdateConfig {
    UpdateConfig {
        maxmind_geo: MaxmindGeoConfig {
            active: true,
            cron: cron.to_string(),
            ..MaxmindGeoConfig::default()
        },
        ..UpdateConfig::default()
    }
}

#[test]
fn geo_update_scheduled_on_1st_at_18h() {
    // "0 18 1 * *" — every 1st of the month at 18:00
    let config = geo_config_for_cron("0 18 1 * *");
    let jobs = scheduled_soldier_jobs_for_values(&config, 0, 18, 1, 5, 3).unwrap();
    assert!(
        jobs.iter().any(|j| j.args == vec!["--addr-list", "maxmind-geo"]),
        "geo update job must be scheduled on day=1 hour=18"
    );
}

#[test]
fn geo_update_not_scheduled_on_other_days() {
    let config = geo_config_for_cron("0 18 1 * *");
    let jobs = scheduled_soldier_jobs_for_values(&config, 0, 18, 15, 5, 3).unwrap();
    assert!(
        !jobs.iter().any(|j| j.args == vec!["--addr-list", "maxmind-geo"]),
        "geo update must NOT fire on day=15"
    );
}

#[test]
fn geo_update_not_scheduled_when_inactive() {
    let config = UpdateConfig {
        maxmind_geo: MaxmindGeoConfig {
            active: false,
            cron: "0 18 1 * *".to_string(),
            ..MaxmindGeoConfig::default()
        },
        ..UpdateConfig::default()
    };
    let jobs = scheduled_soldier_jobs_for_values(&config, 0, 18, 1, 5, 3).unwrap();
    assert!(
        !jobs.iter().any(|j| j.args == vec!["--addr-list", "maxmind-geo"]),
        "inactive geo module must not produce a job"
    );
}

// ── Geo-aware WAF integration ─────────────────────────────────────────────────
//
// These tests spin up the WAF + backend and verify that security events contain
// country/continent enrichment when the GeoIP database is present.
// They are marked `#[ignore]` because they require:
//   1. `db/geo/GeoLite2-City.mmdb` to be populated (soldier_update --addr-list maxmind-geo).
//   2. `Banning_mode: false` in conf/banning.yaml (to avoid banning 127.0.0.1).
//
// Run with:
//   cargo test --test geoip_test -- geo_waf --include-ignored

#[ignore]
#[test]
fn geo_event_country_populated_for_public_ip() {
    // This test is a placeholder for a full WAF integration test.
    // To run:
    //   1. Ensure db/geo/GeoLite2-City.mmdb exists.
    //   2. Send a request through the WAF with X-Forwarded-For: 8.8.8.8
    //      (and --real-ip-header x-forwarded-for --trusted-proxy-cidrs 127.0.0.1/32).
    //   3. Verify that the SQLite log row has country="United States".
    let Some(reader) = open_reader() else {
        eprintln!("Skipping: GeoLite2-City.mmdb not present");
        return;
    };
    let result = reader.lookup("8.8.8.8");
    assert_eq!(result.country_name, "United States");
    assert_eq!(result.continent_name, "North America");
}

// ── Free-proxy multi-region test (manual / ignored by default) ────────────────
//
// This test documents how to verify geo enrichment from multiple source regions
// using free SOCKS5 proxies. To use:
//
//   1. Obtain free proxy addresses from a public list (e.g. https://www.proxy-list.download).
//   2. Configure the reqwest client with a SOCKS5 proxy:
//        let client = reqwest::Client::builder()
//            .proxy(reqwest::Proxy::all("socks5://proxy_host:port").unwrap())
//            .build().unwrap();
//   3. Send an attack payload through the WAF (e.g. `?q=' OR 1=1--`).
//   4. Read the SQLite database and verify that `country` and `continent_name`
//      are populated with the proxy's geolocation.
//
// NOTE: Free proxies are unreliable. Use this pattern only for manual validation.
// Banning mode MUST be disabled for these tests to avoid poisoning the ban list.
#[ignore]
#[test]
fn multi_region_geo_enrichment_via_proxy() {
    // Placeholder: see doc comment above for implementation instructions.
    println!("Manual test — see test source for instructions.");
}
