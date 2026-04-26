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

## CLI flag

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
```

| Field         | Type    | Required | Default | Description |
|---------------|---------|----------|---------|-------------|
| `order`       | integer | yes      | —       | Determines sort order when multiple entries could match; lower wins. |
| `title`       | string  | yes      | —       | Human-readable label shown in log output. |
| `description` | string  | no       | `""`    | Free-form notes for operators. |
| `log`         | boolean | no       | `false` | When `true`, an `info`-level log line is emitted each time a request matches this entry. |
| `paths`       | list    | yes      | —       | URI prefixes. Matching is prefix-based after URL normalization (percent-decode + path traversal collapse). |

### Matching rules

- Comparison is done against the **normalized** URI path (percent-decoded,
  `..` collapsed, backslashes replaced with `/`).
- A path `/wp-admin` matches `/wp-admin`, `/wp-admin/`, and
  `/wp-admin/edit.php` but **not** `/wp-admin-setup`.
- Matching is **case-sensitive** (standard for URI paths per RFC 3986).

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

### SIEM / observability stack

```yaml
allow:
  - order: 1
    title: "Grafana"
    log: false
    paths:
      - /grafana

  - order: 2
    title: "Prometheus metrics"
    log: false
    paths:
      - /metrics
```

### Load-balancer health checks

```yaml
allow:
  - order: 1
    title: "Health probes"
    log: false
    paths:
      - /healthz
      - /readyz
      - /livez
```

## Interaction with `--mode`

Allow-paths bypass takes precedence over `--mode`. A URI that matches an
allow-path is always forwarded without inspection regardless of whether the WAF
is running in `block` or `silent` mode.
