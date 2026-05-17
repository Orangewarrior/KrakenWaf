# Address Blocklist and Allowlist

KrakenWAF v2.10.0 replaces the legacy `rules/blocklist_ip.txt` with a pair of
structured address-control files under `rules/addr/`.

---

## Blocklist — `rules/addr/blocklist.txt`

Requests from IPs or CIDRs listed here are rejected with **HTTP 403** before
any other inspection takes place. A finding is logged to JSON, raw critical,
and SQLite.

### Format

```
# Lines starting with # are comments.
# One IPv4 address, IPv6 address, or CIDR block per line.
10.10.10.1
192.0.2.0/24
2001:db8::1
```

### Enabling

Pass `--blocklist-ip` to activate blocklist enforcement:

```sh
krakenwaf --blocklist-ip --upstream http://127.0.0.1:8080 ...
```

Without `--blocklist-ip` the file is loaded but not enforced (useful for
staging the list before rolling it out to production).

---

## Downloaded list directories

KrakenWAF also loads every text file under these directories:

- `rules/addr/blocklist/`
- `rules/addr/spamhaus/`
- `rules/addr/firehol/`

The updater writes downloaded files there from `conf/update.yaml`:

```yaml
blocklist:
  title: "Blocklist site"
  lists:
    url_file:
      - "https://lists.blocklist.de/lists/bruteforcelogin.txt"
      - "https://lists.blocklist.de/lists/bots.txt"
  cron: "0 12 */3 * *"
firehol:
  title: "Firehol"
  lists:
    url_file:
      - "https://iplists.firehol.org/files/firehol_proxies.netset"
      - "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/c2_tracker.ipset"
  cron: "0 12 */3 * *"
```

Run manually:

```sh
target/release/soldier_update --addr-list blocklist
target/release/soldier_update --addr-list firehol
```

Each downloaded file receives a metadata header with the YAML `title`. When a
client IP matches one of these files, JSON, raw, and SQLite logs include that
title and the local source path, for example:

- title: `Blocklist site`
- rule source: `rules/addr/blocklist/bots.txt:42`

The loader canonicalizes files before opening them. A symlink inside one of
these directories is accepted only if it resolves inside the configured rules
root; symlinks to external paths are rejected.

---

## Allowlist — `rules/addr/allowlist.txt`

Only IPs or CIDRs listed here may access the internal management endpoints:

- `/__krakenwaf/health`
- `/metrics`

Any request to those paths from an IP **not** in the allowlist receives
**HTTP 403**.

If the file is **absent or empty**, the allowlist is disabled and all IPs may
reach the management endpoints (original behaviour).

### Format

Same as the blocklist — one IPv4, IPv6, or CIDR per line, `#` comments
supported.

```
# Allow only loopback and monitoring subnet.
127.0.0.1
::1
10.0.1.0/24
```

---

## Real-IP header integration

Both files work with the `--real-ip-header` / `--trusted-proxy-cidrs` feature.
When a trusted proxy forwards the real client IP, the WAF uses that IP for
blocklist and allowlist lookups instead of the TCP peer address.

```sh
krakenwaf \
  --blocklist-ip \
  --real-ip-header X-Real-IP \
  --trusted-proxy-cidrs 10.0.0.0/8 \
  --upstream http://127.0.0.1:8080
```

---

## Hot-reload

Send `SIGHUP` to the WAF process to reload both files without downtime:

```sh
kill -HUP $(pidof krakenwaf)
```

---

## Migration from `rules/blocklist_ip.txt`

If you were using the legacy file, copy its contents into
`rules/addr/blocklist.txt`. The old path is no longer read by the WAF.
