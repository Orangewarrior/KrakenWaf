# Admin sub-commands — `config` & `rules`

KrakenWaf ships three administrative sub-commands that run a single task and
exit **without** starting the proxy listener. They give operators a fail-fast
pre-flight check over the configuration files and rule set the WAF would load,
and a redacted dump of the effective configuration for safe sharing.

```
krakenwaf config validate
krakenwaf config dump --redact
krakenwaf rules  validate
```

All three honour the same path flags the server uses, and those flags are
`global` — they may appear **before or after** the sub-command:

| Flag | Selects |
|------|---------|
| `--external-proxy-conf <path>` | `conf/proxy.yaml` (or the given path) |
| `--ratelimit-by-file-conf <path>` | `conf/ratelimit.yaml` |
| `--websocket-conf <path>` | `conf/websocket.yaml` |
| `--rules-dir <path>` | rule-set directory (default `./rules`) |
| `--cmc-load <path>` | optional CMC config |

When a flag is omitted the command falls back to the conventional
`conf/<name>.yaml` under the working directory (and the default `./rules`).

---

## `config validate`

Loads every configuration file and **fails fast on the first invalid one**.
Intended for CI pipelines, systemd `ExecStartPre`, and Kubernetes init
containers so a bad config is caught **before** any port is bound.

```bash
krakenwaf config validate
```

What it checks:

| Section | Source | Behaviour when absent |
|---------|--------|-----------------------|
| `proxy` | `conf/proxy.yaml` | skipped (built-in defaults) unless `--external-proxy-conf` is explicit |
| `ratelimit` | `conf/ratelimit.yaml` | lenient load + `validate()` (defaults) |
| `websocket` | `conf/websocket.yaml` | lenient load + `validate()` (defaults) |
| `banning` | `conf/banning.yaml` | validated relative to the working dir |
| `update` | `conf/update.yaml` | skipped when absent |
| `cmc` | `--cmc-load <path>` | only when the flag is supplied |

Output (`✓` valid, `✗` invalid, `-` absent → defaults):

```
  ✓ proxy      /srv/krakenwaf/conf/proxy.yaml
  ✓ ratelimit  /srv/krakenwaf/conf/ratelimit.yaml
  ✓ websocket  /srv/krakenwaf/conf/websocket.yaml
  ✓ banning    /srv/krakenwaf/conf/banning.yaml
  - update     /srv/krakenwaf/conf/update.yaml (absent — using built-in defaults)

config validate: OK — all configuration files are valid
```

**Exit code:** `0` when every file is valid; `1` otherwise, with a concise error
chain (no Rust backtrace) naming the offending file and the reason, e.g.:

```
  ✗ ratelimit  conf/ratelimit.yaml
      invalid rate-limit config 'conf/ratelimit.yaml': `connection_timeout_secs`
      must be >= 1 (got 0); 0 would time out every client connection immediately
config validate: 1 configuration file(s) failed validation
```

---

## `config dump [--redact]`

Prints the **effective configuration** as a single YAML document: the parsed
`proxy`, `ratelimit`, and `websocket` sections, a small `effective:` block with
CLI-precedence-resolved values, and a `secrets:` block reporting secret
*presence* (never the value).

```bash
krakenwaf config dump --redact
```

`--redact` (recommended in production / support) masks secret-bearing fields:

* **Credentialed URLs** — the `user:pass@` userinfo of `upstream` and `redis.url`
  becomes `***REDACTED***@host…`. The host / path stay legible so the topology is
  still readable.
* **Secrets** — `REDIS_PASSWORD`, `REDIS_USERNAME`, `MAXMIND_LICENSE_KEY` are
  reported as `***REDACTED***` (present) or `<unset>` — the value is **never**
  printed. Presence is resolved through the file-first secret chain (see
  [secrets.md](secrets.md)).

Example (truncated):

```yaml
# KrakenWaf effective configuration (secrets redacted)
proxy:
  listen: 0.0.0.0:443
  upstream: https://app.internal:8080
  ...
ratelimit:
  rate_limit_per_minute: 240
  redis:
    url: rediss://***REDACTED***@redis.internal:6380/0
    ...
websocket:
  enable_ws_control: true
  allowed_paths: [/ws, /wss]
  ...
effective:
  rate_limit_per_minute: 240
  ws_control_enabled: true
secrets:
  REDIS_PASSWORD: ***REDACTED***
  REDIS_USERNAME: <unset>
  MAXMIND_LICENSE_KEY: <unset>
```

Without `--redact` the credentialed-URL userinfo is still printed, and secret
presence shows as `<set via file/env>` / `<unset>` (the value is never emitted in
either mode). Prefer `--redact` whenever the output may be pasted into a ticket,
chat, or log.

---

## `rules validate`

Loads the rule set from `--rules-dir` (default `./rules`) and reports
per-category counts. Use it after editing or hot-loading rules to confirm they
parse before a `SIGHUP` reload or a restart.

```bash
krakenwaf rules validate --rules-dir ./rules
```

```
rules validate: loading from ./rules
  ✓ rule set parsed successfully
      uri_keywords          8
      header_keywords       2
      body_keywords         11
      path_regex            35
      blocked_ips           2
      blocked_ip_prefixes   2
      allowed_ips           2

rules validate: OK
```

When `--cmc-load <path>` is supplied the CMC config is validated too. If the
rule set parses but contains **no request-matching rules**, the command prints a
warning (the WAF would start but report `NOT READY` on `/readyz`).

**Exit code:** `0` on a clean parse; `1` (with the failing path + reason) when
the rule set or CMC config cannot be loaded.

---

## Wiring into deployments

All three commands are pre-wired into the hardened deploy artifacts (see
[production_hardening.md](production_hardening.md)):

* **systemd** — `ExecStartPre=/usr/local/bin/krakenwaf config validate …` aborts
  the unit before it binds a port if any config is invalid.
* **Kubernetes** — an init container runs `config validate`, failing the rollout
  fast on a bad config.
* **Docker** — the image `HEALTHCHECK` runs `config validate`.
