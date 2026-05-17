# Firehol address-list updates

KrakenWaf can download Firehol-style IP feeds with:

```bash
target/release/soldier_update --addr-list firehol
```

The updater reads the `firehol` section in `conf/update.yaml`, downloads every
`lists.url_file` entry, and writes the files into `rules/addr/firehol/`.

```yaml
firehol:
  title: "Firehol"
  lists:
    url_file:
      - "https://iplists.firehol.org/files/firehol_proxies.netset"
      - "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/c2_tracker.ipset"
  cron: "0 12 */3 * *"
```

`watch_tower` evaluates this cron expression once per minute. When it matches,
it executes:

```bash
soldier_update --addr-list firehol
```

## Blocking behavior

Start KrakenWaf with IP blocking enabled:

```bash
target/release/krakenwaf --blocklist-ip
```

On startup and rule reload, KrakenWaf automatically reads every regular text
file under:

- `rules/addr/blocklist/`
- `rules/addr/spamhaus/`
- `rules/addr/firehol/`

Each line can contain an IPv4 address, IPv6 address, or CIDR range. Empty lines
and comments are ignored. If a client IP matches a Firehol entry, the finding
uses the YAML `title` and the local file path, for example:

- title: `Firehol`
- rule match: `firehol_proxies.netset 198.51.100.0/24`
- rule source: `rules/addr/firehol/firehol_proxies.netset:42`

Directory and file paths are canonicalized before use. Symlinks that resolve
outside the rules root are rejected instead of being opened.
