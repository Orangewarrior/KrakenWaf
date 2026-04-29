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
