# Spamhaus DQS updates

KrakenWaf can validate and use Spamhaus DQS DNS zones with
`soldier_update --addr-list spamhaus`. SBL, XBL, and AuthBL are DNS query zones, not full
download files in the SIA download API. The updater writes local marker files
under `rules/addr/spamhaus/` for auditability, and the WAF queries the selected
DQS zones at runtime when `--blocklist-ip` is enabled.

`soldier_update` resolves Spamhaus download and DQS hostnames through Quad9
DNS-over-TLS. The resolver enables DNSSEC validation, uses encrypted TLS
transport for DNS, and disables `/etc/hosts` fallback for this updater path so
the lookup policy is explicit.

## Why use Spamhaus IP lists

Spamhaus datasets add external reputation to the WAF before request parsing.
This is useful for blocking clients that are already associated with botnet
control, authentication abuse, hijacked networks, or other hostile
infrastructure. For blue team and CSIRT work, the alert records the exact list
file and path, so analysts can explain why an IP was blocked and which
intelligence source contributed.

Relevant Spamhaus references:

- DQS overview: https://docs.spamhaus.com/70-access-methods/data-query-service/000-intro.html
- DQS access and authentication: https://docs.spamhaus.com/70-access-methods/data-query-service/020-dqs-auth.html
- Dataset descriptions for SBL, XBL, and AuthBL: https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/030-datasets.html
- SIA dataset download endpoint, which currently lists bcl, xbl, and css for full export: https://docs.spamhaus.com/sia/docs/source/10-API-Interface/500-Downloads.html

## Get a DQS token

1. Create or request a Spamhaus account from Spamhaus Technology.
2. Enable the Data Query Service or the dataset subscription that includes the
   feeds you want to use.
3. Copy the issued token/key. Spamhaus documents DQS keys as customer-specific
   values used for authenticated access.
4. Provide it to the updater as a file secret (preferred) or env var. See
   [docs/secrets.md](secrets.md) for the full resolution order.

```bash
# File secret (preferred): /run/secrets/krakenwaf/SPAMHAUS_DQS_KEY (or *_FILE)
printf '%s' 'your-token-here' > /run/secrets/krakenwaf/SPAMHAUS_DQS_KEY

# Environment variable (fallback):
export SPAMHAUS_DQS_KEY="your-token-here"
```

## Configure KrakenWaf

Edit `conf/update.yaml`:

```yaml
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
  zones:
    - sbl
    - xbl
    - authbl
  cron: "0 12 */3 * *"
firehol:
  title: "Firehol"
  lists:
    url_file:
      - "https://iplists.firehol.org/files/firehol_proxies.netset"
      - "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/c2_tracker.ipset"
  cron: "0 12 */3 * *"
```

`lists.url_file` can be a single URL or a YAML array of URLs. Every downloaded
file is saved under the matching list directory:

- `blocklist.lists.url_file` -> `rules/addr/blocklist/`
- `spamhaus.lists.url_file` -> `rules/addr/spamhaus/`
- `firehol.lists.url_file` -> `rules/addr/firehol/`

Use a YAML array for multiple URLs; do not repeat the same `url_file` key.
`drop.lasso` and other URLs under Spamhaus `/drop/` are saved as `DROP.txt`.
The `title` field is written into downloaded files and later appears in raw,
JSON, and SQLite findings.

`DQS-key: false` is the repository default. With this setting, the updater only
downloads files from `lists.url_file` and does not require `SPAMHAUS_DQS_KEY`.
Set `DQS-key: true` to enable DQS validation and runtime lookups. Supported
runtime zones are `sbl`, `xbl`, and `authbl`.

## Run manually

Build the updater:

```bash
cargo build --release --bin soldier_update
```

Run the Spamhaus update:

```bash
target/release/soldier_update --addr-list blocklist
target/release/soldier_update --addr-list firehol
target/release/soldier_update --addr-list spamhaus
```

The updater downloads configured `lists.url_file` entries first. With the
example above, it saves:

- `rules/addr/spamhaus/DROP.txt`

If `DQS-key: true`, set `SPAMHAUS_DQS_KEY` before running the updater. It also
validates the three zones by querying Spamhaus' documented test IP
`127.0.0.2`, then writes marker files:

- `rules/addr/spamhaus/SBL.txt`
- `rules/addr/spamhaus/XBL.txt`
- `rules/addr/spamhaus/AUTHBL.txt`

The `SBL.txt`, `XBL.txt`, and `AUTHBL.txt` marker files are not full IP list
exports. They record which DQS zones were validated and are used by the WAF for
log source paths. Full SIA download exports require a SIA/JWT bearer token and
enterprise access to a specific dataset; a DQS DNS key is not accepted by that
endpoint.

DNS failures in the DQS validation path are handled strictly: NXDOMAIN or
no-record answers mean "not listed", while DNSSEC validation failures, TLS/DoT
transport failures, and resolver errors make the update fail instead of
silently continuing with a different resolver.

## Run automatic updates

Build both robots:

```bash
cargo build --release --bin soldier_update --bin watch_tower
```

Start the scheduler:

```bash
target/release/watch_tower
```

`watch_tower` reads `conf/update.yaml` once per minute. With the example above:

- KrakenWaf source code update runs at 18:00 every 15 days according to the cron expression.
- blocklist file downloads run at 12:00 every 3 days according to the cron expression.
- Firehol file downloads run at 12:00 every 3 days according to the cron expression.
- Spamhaus DQS validation runs at 12:00 every 3 days according to the cron expression only when `DQS-key: true`.

## WAF blocking behavior

Start KrakenWaf with IP blocklist support:

```bash
target/release/krakenwaf --blocklist-ip
```

During startup and rule reload, KrakenWaf reads address lists from
`rules/addr/blocklist/` and `rules/addr/spamhaus/`. When `--blocklist-ip` is
`rules/addr/firehol/` is loaded the same way. When `--blocklist-ip` is
enabled and `DQS-key: true`, every client IP is also checked against the
configured Spamhaus DQS zones. The local marker files under
`rules/addr/spamhaus/` provide an audit path for DQS logs.

When a client IP matches a downloaded file, the finding uses:

- title: YAML `title`, such as `Blocklist site` or `Spamhaus site`
- rule match: `<list file> <matched CIDR>`
- rule source: `<local path>:<line>`

When a client IP matches a DQS zone, the finding uses:

- title: `Spamhaus DQS match: <ZONE>`
- rule match: `Spamhaus DQS zone=<zone> response=<127.x.x.x>`
- rule source: `rules/addr/spamhaus/<ZONE>.txt:dqs`

## DQS lookup caching (per-request DoS hardening)

The DQS check runs **per request** on the WAF hot path: each lookup is a
DNS-over-TLS query with a multi-second timeout. Without caching, a client that
rotates source addresses (trivial across an IPv6 `/64`) would force one outbound
DoT lookup per request — both an amplification vector and a tail-latency hit
against the WAF itself.

KrakenWaf therefore caches every DQS outcome in a bounded, TTL-expiring,
lock-free cache keyed by `(client IP, zone)`:

- **Positive** (listed) results are cached for `DQS-cache-ttl-secs`
  (default **3600s**) — a listed IP rarely de-lists within the hour.
- **Negative** (not-listed) results are cached for
  `DQS-cache-negative-ttl-secs` (default **300s**) — kept short so a
  *newly*-listed IP starts being blocked promptly.
- **Errors are never cached.** A transient DoT failure must not pin a
  "not listed" verdict; the next request retries.

The cache is bounded to a fixed maximum number of `(ip, zone)` entries; when
full it first reclaims expired slots and only then admits a new entry, so IP
rotation cannot grow it without bound.

### Configuration (`conf/update.yaml`)

```yaml
spamhaus:
  DQS-key: true
  zones:
    - sbl
    - xbl
    - authbl
  # Optional cache tuning (defaults shown):
  DQS-cache-ttl-secs: 3600           # positive (listed) TTL
  DQS-cache-negative-ttl-secs: 300   # negative (not-listed) TTL
```

Both keys are optional; omit them to use the defaults. Lowering the negative TTL
trades more DoT lookups for faster reaction to freshly-listed IPs.
