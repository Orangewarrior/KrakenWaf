# Allow-Paths

The allow-paths feature lets operators declare URI prefixes that bypass WAF
inspection entirely. This is useful for:

- **CMS admin panels** (WordPress `/wp-admin`, Drupal `/admin`) where the WAF
  would otherwise flag legitimate rich-text editor payloads.
- **Monitoring dashboards** (Grafana, Prometheus) accessed over a trusted
  internal network.
- **Health-check endpoints** called by load balancers (e.g. `/healthz`).

> **Security note**: requests matching an allow-path are forwarded to upstream
> without any WAF inspection. You are responsible for protecting these paths at
> the network or application level (IP allowlists, authentication middleware,
> mTLS, etc.).

## Configuration

The shipped `conf/filter.yaml` sets:

```yaml
allowpaths: ./rules/allowpaths/lists.yaml
```

The policy is therefore loaded automatically. Use the CLI flag only to select
an alternative file; it has higher precedence:

```
krakenwaf --allow-paths rules/allowpaths/lists.yaml
```

KrakenWaf validates the YAML file on startup and exits with an error if it
cannot be parsed or if any entry is missing required fields.

## YAML format

```yaml
allow:
  - order: 1
    title: "Short descriptive label"
    description: "Optional longer explanation"
    log: true          # emit an info log line when this entry matches (default: false)
    paths:
      - /path/prefix
      - /another/prefix

  - order: 2
    title: "IP-restricted health probes"
    description: "Only loopback may reach these paths"
    log: false
    only_addrs: rules/addr/allowlist/allow_addrs.txt   # optional IP allowlist
    paths:
      - /healthz
      - /metrics
```

| Field         | Type    | Required | Default | Description |
|---------------|---------|----------|---------|-------------|
| `order`       | integer | yes      | —       | Determines sort order when multiple entries could match; lower wins. |
| `title`       | string  | yes      | —       | Human-readable label shown in log output. |
| `description` | string  | no       | `""`    | Free-form notes for operators. |
| `log`         | boolean | no       | `false` | When `true`, an `info`-level log line is emitted each time a request matches this entry. |
| `port`        | integer | no       | —       | TCP listener port this entry is scoped to. When set, the entry is consulted **only** for requests arriving on that exact port (e.g. `4343` for the dedicated observability port). When omitted the entry applies on every listener. See [Port scoping](#port-scoping) below. |
| `only_addrs`  | string  | no       | —       | Path to a file listing allowed client IPs. When set, only those IPs may access the listed paths; all others receive HTTP 403. See [IP restriction](#ip-restriction-only_addrs) below. |
| `paths`       | list    | yes      | —       | URI prefixes. Matching is prefix-based after URL normalisation (percent-decode + path traversal collapse). |

### Matching rules

- Comparison is done against the **normalised** URI path (percent-decoded,
  `..` collapsed, backslashes replaced with `/`). All path operations use
  `fs::canonicalize` to prevent path-traversal bypasses.
- A path `/wp-admin` matches `/wp-admin`, `/wp-admin/`, and
  `/wp-admin/edit.php` but **not** `/wp-admin-setup`.
- Matching is **case-sensitive** (standard for URI paths per RFC 3986).

### Port scoping

The optional `port` field binds an entry to a single TCP listener:

- `port` **omitted** → the entry applies on every listener (the historic,
  port-agnostic behaviour; nothing changes for existing files).
- `port: <n>` → the entry is **invisible** on every listener except port `n`.
  On any other port the WAF treats it as if it were not present (`NoMatch`),
  so the path is inspected normally there.

This is how the shipped configuration scopes the health/metrics/UI entry to the
dedicated observability port (default `4343`) without affecting the data-plane
port:

```yaml
allow:
  - order: 2
    title: "Health check and UI endpoint"
    log: false
    port: 4343                                            # observability port only
    only_addrs: rules/addr/allowlist/allow_addrs_metrics_n_ui.txt
    paths:
      - /metrics
      - /healthz
      - /readyz
      - /livez
```

On the observability port this port additionally enforces an
`Authorization: Bearer <token>` credential — see
**[docs/observability.md](observability.md)** for the full bearer-token gate.

---

## IP restriction (`only_addrs`)

When an allow-path entry has the `only_addrs` field set, every incoming
request is checked against an IP address file **before** the WAF-bypass
decision is made:

| Client IP status | Result |
|---|---|
| IP **is** in the file | Allow (WAF inspection bypassed) |
| IP **is not** in the file | **HTTP 403** — blocked immediately |
| Path does not match | Normal WAF inspection applies |

Additionally, if the full request URI (including query string) contains the
restricted path — even if it is embedded in a query parameter — and the
client IP is not allowed, the request is blocked. This prevents redirect-based
bypasses such as `GET /api?next=/healthz`.

### IP allowlist file format

One entry per line. Supports three notation styles:

| Style | Example | Meaning |
|---|---|---|
| Exact IP | `127.0.0.1` | Single address |
| CIDR | `10.0.0.0/8` | Network range (standard CIDR) |
| Start–end range | `192.168.1.1-192.168.1.50` | Inclusive range |

Lines starting with `#` and blank lines are ignored.

### Default allowlist file

The default provided file is `rules/addr/allowlist/allow_addrs.txt`:

```
# Only loopback may access observability endpoints.
127.0.0.1
::1
```

You can point `only_addrs` to any path, absolute or relative to the WAF
working directory:

```yaml
only_addrs: rules/addr/allowlist/allow_addrs.txt      # relative to WAF root
only_addrs: /etc/krakenwaf/ops_allowlist.txt           # absolute path
```

### Interaction with `--real-ip-header` / `--trusted-proxy-cidrs`

The `only_addrs` check uses the **effective** client IP — the same IP that
the rate limiter and blocklist use. If the WAF is behind a trusted load
balancer and `--real-ip-header X-Forwarded-For --trusted-proxy-cidrs
10.0.0.0/8` is configured, the real client IP (extracted from the header) is
used for the IP restriction, not the TCP peer address.

This applies both to proxied paths (dispatched through the WAF proxy engine)
and to the WAF's own built-in endpoints (`/metrics`, `/readyz`, etc.).

---

## Examples

### CMS (WordPress/Drupal)

```yaml
allow:
  - order: 1
    title: "WordPress admin"
    description: "Bypass WAF for authenticated admin users; restrict to VPN IPs at network level"
    log: true
    paths:
      - /wp-admin
      - /wp-json/wp/v2
```

### Observability stack (Grafana, Prometheus) — localhost only

```yaml
allow:
  - order: 1
    title: "Grafana"
    log: false
    only_addrs: rules/addr/allowlist/allow_addrs.txt
    paths:
      - /grafana
      - /grafana/login
      - /grafana/api

  - order: 2
    title: "Prometheus metrics"
    log: false
    only_addrs: rules/addr/allowlist/allow_addrs.txt
    paths:
      - /metrics
```

### Load-balancer health checks — internal subnet only

```yaml
allow:
  - order: 1
    title: "Health probes"
    log: false
    only_addrs: /etc/krakenwaf/lb_ips.txt   # 10.0.0.0/8 range
    paths:
      - /healthz
      - /readyz
      - /livez
```

---

## Interaction with `--mode`

Allow-paths bypass takes precedence over `--mode`. A URI that matches an
allow-path entry (and whose source IP passes any configured `only_addrs`
check) is always forwarded without inspection regardless of whether the WAF
is running in `block` or `silent` mode.

If the source IP fails the `only_addrs` check, the request is blocked with
HTTP 403 regardless of `--mode`.

---

## Path canonicalization and security

Every file path involved in the allow-paths feature is canonicalized with
`fs::canonicalize` before being opened, preventing:

- **Path traversal**: `../../etc/passwd` style attacks in `only_addrs` paths.
- **Symlink attacks**: symlinks that escape the configured rules directory.

URI paths in the YAML and in incoming requests are normalised (percent-decode,
`..` collapse, backslash → `/` conversion) so that encoded or obfuscated
traversal attempts match the same canonical form.
