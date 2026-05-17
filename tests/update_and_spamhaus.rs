use krakenwaf::{
    cmc::CmcManager,
    metrics::WafMetrics,
    rules::RuleSet,
    update::{
        build_spamhaus_dqs_query, download_addr_list_url_files, load_update_config,
        normalized_dqs_zones, output_file_name_for_url, scheduled_soldier_jobs_for_values,
        update_addr_list, update_addr_list_from_config, update_spamhaus, CronSchedule,
        UpdateConfig,
    },
    waf::{rate_limit::PersistenceMode, Decision, InspectionContext, WafEngine},
};
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn write_minimal_rule_tree(root: &std::path::Path) {
    fs::create_dir_all(root.join("addr/spamhaus")).expect("test");
    fs::create_dir_all(root.join("addr/blocklist")).expect("test");
    fs::create_dir_all(root.join("addr/firehol")).expect("test");
    fs::create_dir_all(root.join("addr")).expect("test");
    fs::create_dir_all(root.join("regex")).expect("test");
    fs::create_dir_all(root.join("Vectorscan")).expect("test");
    fs::create_dir_all(root.join("user_agents")).expect("test");
    fs::write(root.join("addr/blocklist.txt"), "").expect("test");
    fs::write(root.join("addr/allowlist.txt"), "").expect("test");
    fs::write(root.join("user_agents/scanners.txt"), "").expect("test");
    fs::write(root.join("rules.json"), r#"{"blocked_ip_prefixes":[]}"#).expect("test");
    fs::write(root.join("regex/path_regex.json"), r#"{"rules":[]}"#).expect("test");
    fs::write(root.join("regex/body_regex.json"), r#"{"rules":[]}"#).expect("test");
    fs::write(root.join("regex/header_regex.json"), r#"{"rules":[]}"#).expect("test");
    fs::write(
        root.join("Vectorscan/strings2block.json"),
        r#"{"rules":[]}"#,
    )
    .expect("test");
}

#[test]
fn loads_update_yaml_and_cron_matches_examples() {
    let tmp = tempfile::tempdir().expect("test");
    fs::create_dir_all(tmp.path().join("conf")).expect("test");
    fs::write(
        tmp.path().join("conf/update.yaml"),
        r#"
KrakenWaf:
  cron: "0 18 */15 * *"
blocklist:
  title: "Blocklist site"
  lists:
    url_file:
      - "https://lists.blocklist.de/lists/bruteforcelogin.txt"
      - "https://lists.blocklist.de/lists/bots.txt"
  cron: "0 12 */3 * *"
spamhaus:
  title: "Spamhaus site"
  lists:
    url_file: "https://www.spamhaus.org/drop/drop.lasso"
  DQS-key: false
  zones: ["sbl", "xbl", "authbl"]
  cron: "0 12 */3 * *"
firehol:
  title: "Firehol"
  lists:
    url_file:
      - "https://iplists.firehol.org/files/firehol_proxies.netset"
      - "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/c2_tracker.ipset"
  cron: "0 12 */3 * *"
"#,
    )
    .expect("test");

    let config = load_update_config(&tmp.path().join("conf/update.yaml")).expect("test");
    assert_eq!(config.blocklist.title, "Blocklist site");
    assert_eq!(config.blocklist.lists.url_file.values().len(), 2);
    assert!(!config.spamhaus.dqs_key);
    assert_eq!(config.spamhaus.title, "Spamhaus site");
    assert_eq!(
        config.spamhaus.lists.url_file.values(),
        ["https://www.spamhaus.org/drop/drop.lasso"]
    );
    assert_eq!(config.spamhaus.zones, ["sbl", "xbl", "authbl"]);
    assert_eq!(config.kraken_waf.cron, "0 18 */15 * *");
    assert_eq!(config.firehol.title, "Firehol");
    assert_eq!(
        config.firehol.lists.url_file.values(),
        [
            "https://iplists.firehol.org/files/firehol_proxies.netset",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/c2_tracker.ipset"
        ]
    );

    let kraken = CronSchedule::parse(&config.kraken_waf.cron).expect("test");
    assert!(kraken.matches_values(0, 18, 16, 5, 0));
    assert!(!kraken.matches_values(0, 18, 15, 5, 0));

    let spamhaus = CronSchedule::parse(&config.spamhaus.cron).expect("test");
    assert!(spamhaus.matches_values(0, 12, 4, 5, 0));
    assert!(!spamhaus.matches_values(0, 13, 4, 5, 0));

    let firehol = CronSchedule::parse(&config.firehol.cron).expect("test");
    assert!(firehol.matches_values(0, 12, 4, 5, 0));
}

#[test]
fn scheduler_includes_firehol_addr_list_job() {
    let config = UpdateConfig {
        kraken_waf: krakenwaf::update::KrakenWafUpdateConfig {
            cron: "59 23 31 12 6".to_string(),
        },
        blocklist: krakenwaf::update::AddrListUpdateConfig {
            cron: "59 23 31 12 6".to_string(),
            ..Default::default()
        },
        firehol: krakenwaf::update::AddrListUpdateConfig {
            cron: "0 12 */3 * *".to_string(),
            ..Default::default()
        },
        spamhaus: krakenwaf::update::SpamhausUpdateConfig {
            cron: "59 23 31 12 6".to_string(),
            ..Default::default()
        },
    };

    let jobs = scheduled_soldier_jobs_for_values(&config, 0, 12, 4, 5, 0).expect("test");
    assert_eq!(jobs.len(), 1);
    assert_eq!(
        jobs[0].args,
        vec!["--addr-list".to_string(), "firehol".to_string()]
    );
}

#[tokio::test]
async fn spamhaus_disabled_writes_error_log() {
    let tmp = tempfile::tempdir().expect("test");
    let config = UpdateConfig::default();
    let err = update_spamhaus(tmp.path(), &config)
        .await
        .expect_err("test");
    assert!(err.to_string().contains("DQS-key is disabled"));
    let errors =
        fs::read_to_string(tmp.path().join("logs/console_local/errors.txt")).expect("test");
    assert!(errors.contains("DQS-key is disabled"));
}

#[tokio::test]
async fn downloads_configured_url_file_to_spamhaus_dir() {
    let tmp = tempfile::tempdir().expect("test");
    let addr = start_feed_server().await;
    let urls = vec![format!("http://{addr}/drop.lasso")];

    download_addr_list_url_files(tmp.path(), "spamhaus", "Spamhaus site", &urls)
        .await
        .expect("test");

    let content =
        fs::read_to_string(tmp.path().join("rules/addr/spamhaus/DROP.txt")).expect("test");
    assert!(content.starts_with("# krakenwaf-title: Spamhaus site\n"));
    assert!(content.contains("198.51.100.0/24 ; DROP example\n"));
}

#[tokio::test]
async fn downloads_blocklist_url_files_to_blocklist_dir() {
    let tmp = tempfile::tempdir().expect("test");
    let addr = start_feed_server().await;
    let urls = vec![format!("http://{addr}/bots.txt")];

    download_addr_list_url_files(tmp.path(), "blocklist", "Blocklist site", &urls)
        .await
        .expect("test");

    let content =
        fs::read_to_string(tmp.path().join("rules/addr/blocklist/bots.txt")).expect("test");
    assert!(content.starts_with("# krakenwaf-title: Blocklist site\n"));
    assert!(content.contains("198.51.100.0/24 ; DROP example\n"));
}

#[tokio::test]
async fn downloads_firehol_url_files_to_firehol_dir() {
    let tmp = tempfile::tempdir().expect("test");
    let addr = start_feed_server().await;
    let urls = vec![format!("http://{addr}/c2_tracker.ipset")];

    download_addr_list_url_files(tmp.path(), "firehol", "Firehol", &urls)
        .await
        .expect("test");

    let content =
        fs::read_to_string(tmp.path().join("rules/addr/firehol/c2_tracker.ipset")).expect("test");
    assert!(content.starts_with("# krakenwaf-title: Firehol\n"));
    assert!(content.contains(&format!(
        "# krakenwaf-source-url: http://{addr}/c2_tracker.ipset\n"
    )));
    assert!(content.contains("203.0.113.25\n"));
}

#[tokio::test]
async fn update_addr_list_from_config_downloads_firehol_lists() {
    let tmp = tempfile::tempdir().expect("test");
    let addr = start_feed_server().await;
    fs::create_dir_all(tmp.path().join("conf")).expect("test");
    fs::write(
        tmp.path().join("conf/update.yaml"),
        format!(
            r#"
firehol:
  title: "Firehol"
  lists:
    url_file:
      - "http://{addr}/firehol_proxies.netset"
      - "http://{addr}/c2_tracker.ipset"
  cron: "0 12 */3 * *"
"#
        ),
    )
    .expect("test");

    update_addr_list_from_config(tmp.path(), &tmp.path().join("conf/update.yaml"), "firehol")
        .await
        .expect("test");

    let proxies = fs::read_to_string(tmp.path().join("rules/addr/firehol/firehol_proxies.netset"))
        .expect("test");
    let c2_tracker =
        fs::read_to_string(tmp.path().join("rules/addr/firehol/c2_tracker.ipset")).expect("test");
    assert!(proxies.starts_with("# krakenwaf-title: Firehol\n"));
    assert!(proxies.contains("198.51.100.0/24\n"));
    assert!(c2_tracker.contains("203.0.113.25\n"));
}

#[tokio::test]
async fn firehol_update_requires_configured_url_files() {
    let tmp = tempfile::tempdir().expect("test");
    let config = UpdateConfig::default();

    let err = update_addr_list(tmp.path(), &config, "firehol")
        .await
        .expect_err("test");

    assert!(
        err.to_string()
            .contains("firehol.lists.url_file has no URLs configured")
    );
}

#[test]
fn builds_spamhaus_dqs_queries_for_supported_zones() {
    let query = build_spamhaus_dqs_query(
        "127.0.0.2".parse::<IpAddr>().expect("test"),
        "test-key",
        "authbl",
    )
    .expect("test");
    assert_eq!(query, "2.0.0.127.test-key.authbl.dq.spamhaus.net");

    let zones = normalized_dqs_zones(&[
        "xbl".to_string(),
        "authbl".to_string(),
        "ignored".to_string(),
        "sbl".to_string(),
    ]);
    assert_eq!(zones, ["authbl", "sbl", "xbl"]);

    let file_name = output_file_name_for_url(
        "spamhaus",
        &"https://www.spamhaus.org/drop/drop.lasso"
            .parse()
            .expect("test"),
    )
    .expect("test");
    assert_eq!(file_name, "DROP.txt");

    let blocklist_name = output_file_name_for_url(
        "blocklist",
        &"https://example.test/bots.txt".parse().expect("test"),
    )
    .expect("test");
    assert_eq!(blocklist_name, "bots.txt");

    let firehol_name = output_file_name_for_url(
        "firehol",
        &"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/c2_tracker.ipset"
            .parse()
            .expect("test"),
    )
    .expect("test");
    assert_eq!(firehol_name, "c2_tracker.ipset");
}

#[tokio::test]
async fn waf_blocks_spamhaus_ip_and_reports_source_list() {
    let tmp = tempfile::tempdir().expect("test");
    write_minimal_rule_tree(tmp.path());
    fs::write(
        tmp.path().join("addr/spamhaus/DROP.txt"),
        "# krakenwaf-title: Spamhaus site\n198.51.100.0/24 ; DROP example\n",
    )
    .expect("test");

    let rules = Arc::new(RuleSet::from_dir(tmp.path()).expect("test"));
    assert_eq!(rules.addr_list_entries.len(), 1);

    let engine = WafEngine::new(
        rules,
        10_000,
        true,
        false,
        false,
        false,
        &tmp.path().join("rate.bin"),
        PersistenceMode::Bincode,
        Arc::new(WafMetrics::default()),
        Arc::new(CmcManager::default()),
    )
    .expect("test");

    let decision = engine
        .inspect_early(&InspectionContext {
            client_ip: "198.51.100.25".to_string(),
            method: "GET".to_string(),
            uri: "/".to_string(),
            path: "/".to_string(),
            headers: String::new(),
            body_limit: 1024,
            request_id: "test".to_string(),
        })
        .await;

    match decision {
        Decision::Block(finding) => {
            assert_eq!(finding.title, "Spamhaus site");
            assert!(finding.rule_match.contains("DROP.txt"));
            assert!(finding.rule_line_match.contains("addr/spamhaus/DROP.txt"));
        }
        Decision::Allow => panic!("expected Spamhaus IP to be blocked"),
    }
}

#[tokio::test]
async fn waf_blocks_firehol_dir_ip_and_reports_source_list() {
    let tmp = tempfile::tempdir().expect("test");
    write_minimal_rule_tree(tmp.path());
    fs::write(
        tmp.path().join("addr/firehol/firehol_proxies.netset"),
        "# krakenwaf-title: Firehol\n198.51.100.0/24\n",
    )
    .expect("test");

    let rules = Arc::new(RuleSet::from_dir(tmp.path()).expect("test"));
    assert_eq!(rules.addr_list_entries.len(), 1);

    let engine = WafEngine::new(
        rules,
        10_000,
        true,
        false,
        false,
        false,
        &tmp.path().join("rate.bin"),
        PersistenceMode::Bincode,
        Arc::new(WafMetrics::default()),
        Arc::new(CmcManager::default()),
    )
    .expect("test");

    let decision = engine
        .inspect_early(&InspectionContext {
            client_ip: "198.51.100.25".to_string(),
            method: "GET".to_string(),
            uri: "/".to_string(),
            path: "/".to_string(),
            headers: String::new(),
            body_limit: 1024,
            request_id: "test".to_string(),
        })
        .await;

    match decision {
        Decision::Block(finding) => {
            assert_eq!(finding.title, "Firehol");
            assert!(finding.rule_match.contains("firehol_proxies.netset"));
            assert!(finding
                .rule_line_match
                .contains("addr/firehol/firehol_proxies.netset"));
        }
        Decision::Allow => panic!("expected Firehol IP to be blocked"),
    }
}

async fn start_feed_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("test");
    let addr = listener.local_addr().expect("test");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                let req = String::from_utf8_lossy(&buf[..n]);
                let body =
                    if req.starts_with("GET /drop.lasso ") || req.starts_with("GET /bots.txt ") {
                        "198.51.100.0/24 ; DROP example\n"
                    } else if req.starts_with("GET /firehol_proxies.netset ") {
                        "198.51.100.0/24\n"
                    } else if req.starts_with("GET /c2_tracker.ipset ") {
                        "203.0.113.25\n"
                    } else {
                        ""
                    };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    addr
}

#[cfg(unix)]
#[test]
fn addr_list_symlink_outside_rules_root_is_rejected() {
    let tmp = tempfile::tempdir().expect("test");
    let outside = tempfile::tempdir().expect("test");
    write_minimal_rule_tree(tmp.path());
    fs::write(outside.path().join("evil.txt"), "198.51.100.1\n").expect("test");
    std::os::unix::fs::symlink(
        outside.path().join("evil.txt"),
        tmp.path().join("addr/firehol/evil.txt"),
    )
    .expect("test");

    let err = RuleSet::from_dir(tmp.path()).expect_err("symlink outside root must fail");
    assert!(err.to_string().contains("possible symlink attack"));
}

#[tokio::test]
async fn waf_blocks_blocklist_dir_ip_and_reports_yaml_title() {
    let tmp = tempfile::tempdir().expect("test");
    write_minimal_rule_tree(tmp.path());
    fs::write(
        tmp.path().join("addr/blocklist/bots.txt"),
        "# krakenwaf-title: Blocklist site\n203.0.113.0/24\n",
    )
    .expect("test");

    let rules = Arc::new(RuleSet::from_dir(tmp.path()).expect("test"));
    assert_eq!(rules.addr_list_entries.len(), 1);

    let engine = WafEngine::new(
        rules,
        10_000,
        true,
        false,
        false,
        false,
        &tmp.path().join("rate.bin"),
        PersistenceMode::Bincode,
        Arc::new(WafMetrics::default()),
        Arc::new(CmcManager::default()),
    )
    .expect("test");

    let decision = engine
        .inspect_early(&InspectionContext {
            client_ip: "203.0.113.8".to_string(),
            method: "GET".to_string(),
            uri: "/".to_string(),
            path: "/".to_string(),
            headers: String::new(),
            body_limit: 1024,
            request_id: "test".to_string(),
        })
        .await;

    match decision {
        Decision::Block(finding) => {
            assert_eq!(finding.title, "Blocklist site");
            assert!(finding.rule_match.contains("bots.txt"));
            assert!(finding.rule_line_match.contains("addr/blocklist/bots.txt"));
        }
        Decision::Allow => panic!("expected blocklist IP to be blocked"),
    }
}
