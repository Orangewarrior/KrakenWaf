# Banning subsystem

KrakenWaf 2.30.0 introduces a first-class **BAN list** that keeps repeat
offenders (and confirmed scanners) away from the protected origin
without ever reaching the WAF inspection pipeline.

The subsystem is **opt-in** and configured via `conf/banning.yaml`.

```yaml
# conf/banning.yaml
Banning_mode: true

Ban_context:
  security_scanners: true
  tolerance_block_count: 3
  Ban_wait_time: 30m
```

When the file is absent or `Banning_mode: false`, KrakenWaf behaves
exactly like 2.29.0 — no BAN list, no extra log entries, no extra
storage.

---

## Configuration reference

| Field | Type | Required when enabled | Meaning |
|-------|------|------------------------|---------|
| `Banning_mode` | bool | always | Master switch. `true` enables the BAN list. `false` disables the entire subsystem. |
| `Ban_context.security_scanners` | bool | no (defaults to `false`) | When `true`, **a single block** by the `Detect_bots_n_scanners` CMC module immediately bans the source IP. The `tolerance_block_count` threshold is bypassed. |
| `Ban_context.tolerance_block_count` | u32 | yes (must be ≥ 1) | Number of WAF blocks (any engine) an IP may rack up before being added to the BAN list. |
| `Ban_context.Ban_wait_time` | duration | yes (must be > 0) | Initial ban duration. Format: any `humantime` expression — `30s`, `30m`, `2h`, `1h30m`, `1d`. |

Aliased / alternate keys (also accepted for tooling that prefers
snake_case YAML):

* `banning_mode` ↔ `Banning_mode`
* `ban_context` ↔ `Ban_context`
* `tolerance block count` (with spaces) ↔ `tolerance_block_count`
* `ban_wait_time` ↔ `Ban_wait_time`

---

## Lifecycle of a ban

```text
            ┌──────────────────────────────────────────────────┐
            │  request from <IP> arrives at KrakenWaf          │
            └──────────────┬───────────────────────────────────┘
                           │
                ┌──────────▼──────────┐
                │ ban_manager.check() │  ← server.rs, before any inspection
                └─────────┬───────────┘
                          │ banned?
                 ┌────────┴────────┐
                yes               no
                 │                 │
                 ▼                 ▼
   ┌──────────────────────┐  ┌──────────────────────────────────────┐
   │ 403 "Banned by       │  │ normal WAF pipeline                  │
   │ KrakenWaf" + Low     │  │   • per-IP concurrency gate          │
   │ severity log         │  │   • memory backpressure              │
   │   (engine="banning") │  │   • WAF inspection                   │
   └──────────────────────┘  │   • upstream forward                 │
                             └──────────────────┬───────────────────┘
                                                │ block?
                                                ▼
                                ┌────────────────────────────────┐
                                │ ban_manager.record_block(IP)   │
                                │   • SecurityScanner → maybe    │
                                │     fast-track ban now         │
                                │   • else: occurrences++; ban   │
                                │     when occurrences ≥ N       │
                                └────────────────────────────────┘
```

### Asymptotic ban duration

Repeat offenders are punished progressively. Let `T = Ban_wait_time`:

| Offense | Ban duration |
|---------|--------------|
| 1st     | `T`          |
| 2nd     | `2 × T`      |
| 3rd     | `3 × T`      |
| Nth     | `N × T`      |

`ban_count` resets to zero after **30 days** of no recorded blocks — an
attacker who fell silent does not stay flagged forever.

### What counts as a block

By default, **every WAF block** counts toward `tolerance_block_count`,
including:

* Regex / Aho-Corasick / Vectorscan / libinjection / CMC detections
* IP-reputation blocks (Spamhaus, Firehol, `addr/blocklist.txt`)
* Rate-limit and per-IP concurrency exhaustion (HTTP 429)

Blocks that occur **while the IP is already banned** are *not* counted
— the BAN-list short-circuit fires before `log_and_enforce`. This
prevents an attacker from inflating their own ban duration via retries.

Blocks in `Silent` or `DetectOnly` mode (`--mode=silent`, `--detect-only`)
are also not counted, because in those modes the WAF observes but does
not actually block; banning would be inconsistent with the operator's
explicit "do not enforce" intent.

### `security_scanners` fast-track

When `security_scanners: true`, the `Detect_bots_n_scanners` CMC module
becomes the most aggressive trigger in the WAF:

* A single request with a scanner User-Agent (`Nikto`, `sqlmap`, `nmap`,
  `masscan`, `nessus`, `OpenVAS`, `gobuster`, `dirbuster`, `Arachni`,
  `Nuclei`, `wfuzz`, `commix`, `Acunetix`, ...) **immediately** adds the
  source IP to the BAN list.
* The `tolerance_block_count` threshold is bypassed for this specific
  reason. Other block reasons still follow the normal threshold.

This is the recommended setting for production deployments — confirmed
scanner tools have no legitimate use case against a public site.

---

## Storage backend

The BAN list is **hybrid**:

| Condition | Backend | Why |
|-----------|---------|-----|
| `conf/ratelimit.yaml` defines a `redis:` section | Redis / Valkey (the same `fred::Pool` is reused) | Distributed: every WAF instance behind a load-balancer sees the same BAN list. TTL is managed by `EXPIRE`. |
| No Redis configured | SQLite at `logs/db/banning.db` | Always-available fallback. ACID transactions via `parking_lot::Mutex<Connection>`. WAL + busy_timeout = 5 s. |

### Redis schema

```text
HSET <key_prefix>:<ip>
     banned_until    <unix seconds>
     ban_count       <int>
     occurrences     <int>
     last_event_at   <unix seconds>
EXPIRE <key_prefix>:<ip> 30d
```

* `<key_prefix>` defaults to `krakenwaf:ban`.
* The increment-and-decide sequence is an atomic Lua script — `INCR`,
  threshold check, conditional ban, EXPIRE.
* All operations use a **150 ms per-call timeout**. If Redis is hung,
  the WAF fails open (request proceeds) — denying availability is worse
  than missing one ban.

### SQLite schema

```sql
CREATE TABLE banned_ips (
    ip            TEXT PRIMARY KEY,
    banned_until  INTEGER,
    ban_count     INTEGER NOT NULL DEFAULT 0,
    occurrences   INTEGER NOT NULL DEFAULT 0,
    last_event_at INTEGER NOT NULL
);
CREATE INDEX idx_banned_until ON banned_ips(banned_until);
```

The file is `chmod 0600` on Unix (matches `logs/db/vulns_alert.db`).

A background task purges rows where `last_event_at < now - 30d` and
`banned_until <= now` once per hour.

---

## Log format

A ban-list rejection produces a `SecurityEvent` identical in shape to
every other WAF block — same JSON schema, same SQLite columns — so
dashboards work without modification.

Distinguishing fields:

| Field | Value |
|-------|-------|
| `engine` | `"banning"` |
| `title` | `"Banned IP — request rejected"` |
| `severity` | `"low"` |
| `rule_match` | `"banning::active_ban"` |
| `rule_line_match` | `"banned_until=<unix epoch>"` |
| `cwe` | `"CWE-693"` (Protection Mechanism Failure) |

The severity is intentionally `Low`: the request has already been
denied without inspection, so no actual threat material reached the
WAF. The log entry exists for **auditability**, not alerting.

A ban-list rejection is also reflected in the Prometheus metric:

```text
krakenwaf_blocked_total{engine="banning:active_ban"} 1
```

---

## How to test it manually

```bash
# 1. Enable banning + the scanner fast-track
cat > conf/banning.yaml <<'EOF'
Banning_mode: true
Ban_context:
  security_scanners: true
  tolerance_block_count: 3
  Ban_wait_time: 5m
EOF

# 2. Start KrakenWaf (the YAML is auto-discovered at startup)
./krakenwaf --no-tls --listen 127.0.0.1:8080 --upstream http://127.0.0.1:9000

# 3. Send a scanner request — blocked + banned
curl -i -H "User-Agent: nikto/2.1.6" http://127.0.0.1:8080/

# 4. Send a clean request from the same source IP — rejected from the
#    BAN list, with the engine="banning" log entry.
curl -i http://127.0.0.1:8080/
```

To exercise the cumulative threshold instead, set
`security_scanners: false`, send three SQLi-style requests, then a
clean one — the fourth is rejected by the BAN list.

For an end-to-end automated regression see
`tests/banning_real_test.rs` (SQLite backend, no TLS),
`tests/banning_redis_test.rs` (plain Redis backend), and
`tests/banning_redis_tls_test.rs` (production `rediss://` path).

---

## Running the Redis-backed tests locally

The two Redis integration suites skip cleanly when a backing
`redis-server` is unreachable. To run them:

```bash
# Plain Redis on 127.0.0.1:6379 — tests/banning_redis_test.rs
redis-server --daemonize yes --port 6379 --save "" --appendonly no

# TLS Redis on 127.0.0.1:6380 — tests/banning_redis_tls_test.rs.
# Tests load the CA from $KRAKENWAF_TEST_TLS_CA or
# /tmp/krakenwaf-tls/ca.pem by default. Generate a CA + server-cert
# chain (self-signed CA, server cert signed by it, SAN=IP:127.0.0.1):

mkdir -p /tmp/krakenwaf-tls && cd /tmp/krakenwaf-tls

openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj "/CN=KrakenWaf test CA" -keyout ca.key -out ca.pem

openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=127.0.0.1" -keyout server.key -out server.csr

cat > server.ext <<'EOF'
subjectAltName = IP:127.0.0.1,DNS:localhost
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out server.pem -days 30 -extfile server.ext

redis-server --daemonize yes --port 0 --tls-port 6380 \
    --tls-cert-file /tmp/krakenwaf-tls/server.pem \
    --tls-key-file /tmp/krakenwaf-tls/server.key \
    --tls-ca-cert-file /tmp/krakenwaf-tls/ca.pem \
    --tls-auth-clients no --save "" --appendonly no

cargo test --test banning_redis_test --test banning_redis_tls_test
```

The TLS suite exercises the same `RateLimiter::new_redis()`
constructor the binary uses in production, including the
`rediss://`-only guard (it has a regression test that proves plain
`redis://` is rejected).

---

## When to leave it off

* You front KrakenWaf with a CDN that already does IP reputation
  (Cloudflare, Fastly, Akamai). Adding a second BAN layer is rarely
  useful and complicates incident response.
* You operate in a closed-network setting where every source IP is
  trusted — there is no untrusted population to ban.
* You expect a large set of NAT-shared IPs (corporate proxies, mobile
  carriers) where a single bad request would unfairly punish hundreds
  of innocent clients.

In those cases keep `Banning_mode: false` (or omit `conf/banning.yaml`
entirely).
