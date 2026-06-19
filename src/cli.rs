use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;

/// Administrative sub-commands. When present the WAF runs the command and exits
/// instead of starting the proxy listener.
#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Inspect and validate `KrakenWaf` configuration files.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Validate the WAF rule set.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum ConfigAction {
    /// Load every configuration file (proxy, rate-limit, websocket, banning,
    /// update, CMC) and fail fast on the first error. Exit code 0 = all valid.
    Validate,
    /// Print the effective configuration. Pass `--redact` to mask secret-bearing
    /// fields (passwords, credentialed URLs) for safe sharing in tickets / logs.
    Dump {
        /// Mask secrets in the output (recommended for production / support).
        #[arg(long)]
        redact: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum RulesAction {
    /// Load the rule set from `--rules-dir` and report its contents. Exit code
    /// 0 = the rule set parsed successfully.
    Validate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WafMode {
    /// Block detected threats (default behaviour).
    Block,
    /// Log detections but never block (observation mode).
    Silent,
    /// Detect-only / shadow mode: run all inspection engines, emit findings and
    /// increment metrics, but always return Allow. Useful for validating new rule
    /// sets against live traffic before enabling blocking.
    DetectOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WalMode {
    /// Persist rate-limiter state in `SQLite` (WAL journal). Slower writes
    /// but supports inspection via `sqlite3 cli` and partial updates.
    Sqlite,
    /// Persist as a flat `postcard` file (atomic rename). Much faster snapshots
    /// and re-hydration; entire state is rewritten on each persist tick.
    Postcard,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "krakenwaf")]
#[command(author, version, about = "KrakenWaf - TLS-aware Rust WAF inspired by OctopusWAF")]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    /// Optional administrative sub-command (`config`, `rules`). When supplied
    /// the WAF runs the command and exits instead of starting the listener.
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(long, default_value = "0.0.0.0:8443")]
    pub listen: SocketAddr,

    /// TCP port for the dedicated observability listener (`/metrics` plus the
    /// `/livez`, `/readyz`, and `/__krakenwaf/health` probes). It binds the same
    /// IP as `--listen` but on this separate port and reuses the `--listen` TLS
    /// certificates (it serves plain HTTP only when the whole WAF runs with
    /// `--no-tls`), so operators can firewall, route, and scrape observability
    /// in isolation from proxied traffic. When omitted, the WAF reads
    /// `metrics-port` from `conf/proxy.yaml` (shipped default: 4343).
    #[arg(long = "metrics-port")]
    pub metrics_port: Option<u16>,

    /// TCP port for the dedicated **rule-management** control-plane listener
    /// (`/rule/control/cmc/list`, `/rule/control/cmc/update`). Like the metrics
    /// listener it binds the same IP as `--listen` on this separate port and
    /// reuses the `--listen` TLS certificates (plain HTTP only under `--no-tls`).
    /// When omitted, the WAF reads `rule_management_port` from
    /// `conf/proxy.yaml` (shipped default: 4342). The control plane only opens
    /// when the Rorschach secrets are provisioned.
    #[arg(long = "rule-management-port")]
    pub rule_management_port: Option<u16>,

    /// Path to the rule-management IP allowlist (one CIDR or bare IP per line;
    /// `#` comments allowed). Defaults to
    /// `<rules-dir>/addr/allowlist/allow_rule_management.txt`. A request whose
    /// effective client IP is outside every entry receives HTTP 403. An empty or
    /// invalid allowlist is a fatal startup error when the control plane is
    /// enabled (fail-closed).
    #[arg(long = "rule-management-allowlist")]
    pub rule_management_allowlist: Option<String>,

    #[arg(long, default_value = "http://127.0.0.1:8080")]
    pub upstream: String,

    #[arg(long, default_value = "./rules", global = true)]
    pub rules_dir: String,

    #[arg(long, default_value = "./rules/tls/sni_map.csv")]
    pub sni_map: String,

    #[arg(long, action = ArgAction::SetTrue, hide = true)]
    pub enable_libinjection: bool,

    #[arg(long = "enable-libinjection-sqli", action = ArgAction::SetTrue)]
    pub enable_libinjection_sqli: bool,

    #[arg(long = "enable-libinjection-xss", action = ArgAction::SetTrue)]
    pub enable_libinjection_xss: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    pub enable_vectorscan: bool,

    #[arg(long, default_value_t = false)]
    pub blocklist_ip: bool,

    #[arg(long)]
    pub blockmsg: Option<String>,

    /// Per-IP request rate limit (requests per minute). Overrides the value in
    /// `--ratelimit-by-file-conf` or `conf/ratelimit.yaml`. When absent the
    /// effective limit is taken from the config file or defaults to 240.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub rate_limit_per_minute: Option<u32>,

    /// Path to a WebSocket control-policy YAML file. `KrakenWaf` auto-discovers
    /// `conf/websocket.yaml` in the working directory; use this flag to supply
    /// an alternative path. The file governs `ws://` / `wss://` upgrade limits
    /// (allowed paths, per-IP session cap, idle / session timeouts, handshake
    /// inspection). When `enable_ws_control` is false no limit applies.
    #[arg(long = "websocket-conf", global = true)]
    pub websocket_conf: Option<String>,

    /// Path to a rate-limit YAML configuration file. `KrakenWaf` auto-discovers
    /// `conf/ratelimit.yaml` in the working directory; use this flag to supply
    /// an alternative path. The file controls the Redis backend, per-IP
    /// concurrency cap, and the default rate limit.
    #[arg(long = "ratelimit-by-file-conf", global = true)]
    pub ratelimit_by_file_conf: Option<String>,

    /// Load proxy-related settings from a YAML file. Passing the flag bare
    /// (`--external-proxy-conf`) auto-loads `conf/proxy.yaml`; pass a path to use
    /// a different file. The settings (`--listen`, `--upstream`,
    /// `--upstream-timeout-secs`, `--allow-private-upstream`,
    /// `--internal-header-name`, `--real-ip-header`, `--trusted-proxy-cidrs`,
    /// `--sni-map`, `--no-tls`, `--header-protection-injection`, `--blockmsg`)
    /// and `--debug-proxy-dev` are loaded from the file. An explicitly-passed
    /// CLI flag still wins; an empty field in the file leaves the WAF's
    /// built-in default in place.
    #[arg(
        long = "external-proxy-conf",
        num_args = 0..=1,
        default_missing_value = "conf/proxy.yaml",
        global = true
    )]
    pub external_proxy_conf: Option<String>,

    #[arg(long, default_value_t = 15)]
    pub upstream_timeout_secs: u64,

    #[arg(long, action = ArgAction::SetTrue)]
    pub verbose: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    pub allow_private_upstream: bool,

    /// Persist developer-grade proxy diagnostic events under
    /// `logs/proxy_errors_dev/proxy_errors.jsonl`. Critical proxy failures are
    /// still persisted when this is false; this switch controls noisier events
    /// such as malformed forwarding headers from trusted proxies. Also settable
    /// via `debug-proxy-dev` in `conf/proxy.yaml`.
    #[arg(long = "debug-proxy-dev", action = ArgAction::SetTrue, default_value_t = false)]
    pub debug_proxy_dev: bool,

    /// Path to a PEM certificate (or bundle) to trust as an additional root CA
    /// when connecting to a TLS upstream. The certificate is *added* to the
    /// built-in public roots — full chain verification is still enforced — so a
    /// backend presenting a private-PKI / internal-CA certificate can be fronted
    /// without disabling validation. Also settable via `upstream-ca` in
    /// `conf/proxy.yaml`.
    #[arg(long = "upstream-ca")]
    pub upstream_ca: Option<String>,

    #[arg(long, default_value = "")]
    pub internal_header_name: String,

    /// Maximum simultaneous TCP connections the WAF accepts.
    /// 2.24.0: when 0 (the default) `KrakenWaf` derives a conservative value
    /// from total RAM at startup (≈ 1 connection per 2 MiB, clamped to
    /// [64, 4096]). YAML key: `memory-limits.max_connections`.
    #[arg(long, default_value_t = 0)]
    pub max_connections: usize,

    /// Maximum upstream response body to buffer (bytes).
    /// 2.24.0: default dropped from 100 MiB → 8 MiB. 0 = use the YAML
    /// value `memory-limits.max_response_body_buffered_bytes`.
    #[arg(long, default_value_t = 0)]
    pub max_upstream_response_bytes: usize,

    /// Hard ceiling on the request body size the WAF will inspect (bytes).
    /// 2.24.0: default dropped from 100 MiB → 8 MiB. 0 = use the YAML
    /// value `memory-limits.max_request_body_buffered_bytes`. Per-route
    /// rule limits remain bounded by this value.
    #[arg(long, default_value_t = 0)]
    pub max_body_bytes: usize,

    /// Timeout (seconds) for a single client connection accepted by the WAF.
    /// Overrides the value in `--ratelimit-by-file-conf` or
    /// `conf/ratelimit.yaml`. When absent the effective value is taken from the
    /// config file or defaults to 30 s.
    #[arg(long = "connection-timeout-secs")]
    pub connection_timeout_secs: Option<u64>,

    /// Anti-Slowloris: maximum wall-clock time the WAF waits for a client to
    /// complete the TLS handshake before dropping the connection. A client that
    /// opens a socket but never finishes the handshake would otherwise hold a
    /// connection slot (and a `--max-connections` permit) indefinitely. Only
    /// applies to TLS mode. 0 disables the bound (not recommended).
    /// Overrides the value in `--ratelimit-by-file-conf` or
    /// `conf/ratelimit.yaml`. When absent the effective value is taken from
    /// the config file or defaults to 10 s.
    #[arg(long = "tls-handshake-timeout-secs")]
    pub tls_handshake_timeout_secs: Option<u64>,

    /// Anti-Slowloris: maximum time to receive a complete HTTP/1 request
    /// header block after the connection (and TLS handshake, when enabled) is
    /// established. 0 disables the bound (not recommended). HTTP/2 is
    /// unaffected because its framing and timeout model are different.
    /// Overrides `http_header_read_timeout_secs` in the rate-limit config.
    #[arg(long = "http-header-read-timeout-secs")]
    pub http_header_read_timeout_secs: Option<u64>,

    #[arg(long = "header-protection-injection")]
    pub header_protection_injection: Option<String>,

    #[arg(long = "cmc-load", global = true)]
    pub cmc_load: Option<String>,

    #[arg(long = "real-ip-header")]
    pub real_ip_header: Option<String>,

    #[arg(long = "trusted-proxy-cidrs", value_delimiter = ',')]
    pub trusted_proxy_cidrs: Vec<String>,

    /// WAF enforcement mode.
    /// `block` (default) — block matching requests.
    /// `silent` — log detections but never block.
    /// `detect-only` — run all engines, emit findings and metrics, always allow.
    #[arg(long, value_enum, default_value = "block")]
    pub mode: WafMode,

    /// Path to an allow-paths YAML file (e.g. rules/allowpaths/lists.yaml). URIs
    /// matching any entry are passed through without blocking even when a rule fires.
    #[arg(long = "allow-paths")]
    pub allow_paths_file: Option<String>,

    /// Disable TLS and listen on plain HTTP. Useful when TLS termination is handled
    /// by an upstream load balancer, or for integration testing. When set, --sni-map
    /// is ignored.
    #[arg(long = "no-tls", default_value_t = false)]
    pub no_tls: bool,

    /// Persistence backend for the rate-limiter snapshot.
    /// `sqlite` uses WAL journaling (queryable, slower); `postcard` uses a
    /// flat binary file with atomic rename (much faster, opaque format).
    #[arg(long = "wal-mode", value_enum, default_value = "sqlite")]
    pub wal_mode: WalMode,

    /// Anomaly-score block threshold. Rule scores accumulate across all
    /// matches in a single request; when the sum reaches this value the
    /// Detection-engine block threshold (score). Overrides the
    /// `Anomaly_threshold` field under `global-options` in the CMC config
    /// file (`--cmc-load`). When absent the effective value is taken from
    /// the CMC file or defaults to 600.
    #[arg(long = "anomaly-threshold")]
    pub anomaly_threshold: Option<u32>,

    /// Per-request wall-clock cap on WAF inspection (milliseconds).
    /// 0 = unlimited (default). When exceeded the inspection stops and the
    /// request is blocked fail-closed with a deadline finding and JSONL event.
    /// Overrides the `Max_inspection_ms` field under `global-options` in the
    /// CMC config file (`--cmc-load`). When absent the effective value is
    /// taken from the CMC file or defaults to 0 (disabled).
    #[arg(long = "max-inspection-ms")]
    pub max_inspection_ms: Option<u64>,

    /// Slowloris protection: maximum wall-clock time the WAF waits for a
    /// single body frame before timing out. Overrides the value in
    /// `--ratelimit-by-file-conf` or `conf/ratelimit.yaml`. When absent the
    /// effective value is taken from the config file or defaults to 30 s.
    #[arg(long = "body-frame-timeout-secs")]
    pub body_frame_timeout_secs: Option<u64>,

    /// Global memory-backpressure cap on in-flight request body bytes.
    /// When exceeded the WAF returns HTTP 503 immediately. 0 = disabled.
    /// Overrides the value in `--ratelimit-by-file-conf` or
    /// `conf/ratelimit.yaml`. When absent the effective value is taken from
    /// the config file or defaults to 1 GiB (1073741824).
    #[arg(long = "max-inflight-body-bytes")]
    pub max_inflight_body_bytes: Option<usize>,

    /// Per-IP memory-backpressure cap on in-flight request body bytes.
    /// When exceeded the WAF returns HTTP 503 for that IP. 0 = disabled.
    /// Overrides the value in `--ratelimit-by-file-conf` or
    /// `conf/ratelimit.yaml`. When absent the effective value is taken from
    /// the config file or defaults to 200 MiB (209715200).
    #[arg(long = "max-per-ip-body-bytes")]
    pub max_per_ip_body_bytes: Option<usize>,
}

impl Cli {
    #[must_use] 
    pub fn libinjection_sqli_enabled(&self) -> bool {
        self.enable_libinjection || self.enable_libinjection_sqli
    }

    #[must_use] 
    pub fn libinjection_xss_enabled(&self) -> bool {
        self.enable_libinjection || self.enable_libinjection_xss
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, WalMode};

    #[test]
    fn wal_mode_accepts_postcard() {
        let cli = Cli::try_parse_from(["krakenwaf", "--wal-mode", "postcard"])
            .expect("postcard must be a valid persistence mode");
        assert_eq!(cli.wal_mode, WalMode::Postcard);
    }

    #[test]
    fn wal_mode_rejects_unknown_encoders() {
        assert!(Cli::try_parse_from(["krakenwaf", "--wal-mode", "legacy"]).is_err());
    }

    #[test]
    fn parses_http_header_read_timeout() {
        let cli = Cli::try_parse_from([
            "krakenwaf",
            "--http-header-read-timeout-secs",
            "7",
        ])
        .expect("header timeout must parse");
        assert_eq!(cli.http_header_read_timeout_secs, Some(7));
    }

    #[test]
    fn rejects_zero_rate_limit() {
        assert!(Cli::try_parse_from([
            "krakenwaf",
            "--rate-limit-per-minute",
            "0",
        ])
        .is_err());
    }
}
