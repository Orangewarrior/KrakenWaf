# Deployment notes

> **Hardened, CIS-aligned deploy artifacts** (systemd, Kubernetes, Docker) are
> documented in [production_hardening.md](production_hardening.md) and shipped
> under [`deploy/`](../deploy). The admin pre-flight commands
> (`config validate`, `config dump --redact`, `rules validate`) are documented in
> [admin_commands.md](admin_commands.md). WebSocket (`ws://`/`wss://`) controls
> are in [websocket.md](websocket.md).

## Rate limiting at the edge
KrakenWAF rate limits by the observed client IP. When deployed directly on the TCP edge this is the socket peer address and requires no header trust chain.

## Behind a load balancer / reverse proxy
If KrakenWAF is deployed behind a trusted proxy, configure:

- `--trusted-proxy-cidrs 10.0.0.0/8,192.168.0.0/16`
- `--real-ip-header x-forwarded-for`

Only requests whose TCP peer IP belongs to a configured trusted CIDR will be allowed to override the effective client IP from the configured header. This avoids trusting spoofed client-supplied forwarding headers on untrusted links.

## Proxy configuration file (`conf/proxy.yaml`)

The proxy-level flags can be loaded as a group from a YAML file via
`--external-proxy-conf` (passed bare it auto-loads `conf/proxy.yaml`), keeping
the command line terse and the topology version-controlled:

```yaml
listen : 0.0.0.0:443
upstream : https://app.internal:8080
upstream-timeout-secs:                 # empty -> WAF default (15 s)
upstream-ca: /etc/krakenwaf/internal-ca.pem  # trust the backend's private CA
allow-private-upstream: true           # internal upstream
debug-proxy-dev: false                 # persist noisy proxy diagnostics only when needed
real-ip-header: X-Forwarded-For
trusted-proxy-cidrs: 10.0.0.0/8, 192.168.0.0/16
no-tls: false
header-protection-injection: ./rules/headers_http/relax.headers
blockmsg: ./alert/blockalert.html
```

When the upstream presents a certificate from a **private / internal CA** (common
for internal services), set `upstream-ca` (or `--upstream-ca`) to that CA's PEM.
KrakenWaf trusts the public webpki roots by default; the supplied CA is *added*
to them with full chain verification still enforced — so the backend is verified
rather than rejected with a 502. This is **not** an "accept any certificate"
switch.

Resolution order is: an explicitly-passed CLI flag → the value in
`conf/proxy.yaml` → the built-in default. An empty field never overrides the
default. Comments (`#`, full-line or inline) are ignored, and the file is
validated at startup — a bad `listen`, `upstream`, CIDR, or header name aborts
boot with a descriptive error. The connection / body-size caps
(`--max-connections`, `--connection-timeout-secs`, `--max-body-bytes`,
`--max-upstream-response-bytes`) live in `conf/ratelimit.yaml` instead — see
[rate_limit.md](rate_limit.md).

`debug-proxy-dev` is a development/incident-debug switch for proxy diagnostics.
Leave it `false` in normal production so malformed forwarding headers do not
create noisy JSONL. Turn it on temporarily to persist diagnostic proxy events to
`logs/proxy_errors_dev/proxy_errors.jsonl`; critical proxy failures remain
persisted even when the switch is off. See [proxy_diagnostics.md](proxy_diagnostics.md).

## Request inspection scope

CMC, regex, vectorscan, and libinjection inspection run against a synthesized full-request payload made from the HTTP method, URI, flattened headers, and body bytes. Streaming body inspection also evaluates a rolling full-request window so POST and REST payload detections are not limited to query-string inspection alone.
