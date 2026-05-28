# GeoIP Enrichment — MaxMind GeoLite2-City

KrakenWaf enriches every security event with the **country** and **continent**
of the source IP address using the MaxMind GeoLite2-City database.  The lookup
is performed once per request (before WAF inspection) and the result is
propagated to:

- The SQLite vulnerability log (`country`, `continent_name` columns).
- The JSONL structured log (`country`, `continent_name` fields).
- The raw critical log (`country=…  continent=…` key-value pairs).

## Quick start

### 1. Create a free MaxMind account

Register at <https://www.maxmind.com/en/> and navigate to
**My Account → Manage License Keys** to generate a license key.

Note your **Account ID** and **License Key**.

### 2. Configure credentials

Edit `conf/update.yaml` and fill in the `maxmind-geo` section:

```yaml
maxmind-geo:
  title: "Maxmind GeoLite2 city"
  active: true
  account_id: "YOUR_ACCOUNT_ID"
  key: "YOUR_LICENSE_KEY"
  url_file:
    - "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
  cron: "0 18 1 * *"   # 1st of every month at 18:00
```

### 3. Download the database

Run the updater once manually:

```bash
./target/release/soldier_update --geo-update
```

The `.mmdb` file is saved to `db/geo/GeoLite2-City.mmdb`.

### 4. Restart KrakenWaf

The WAF loads the database at startup.  After the first download (or any update)
restart the process:

```bash
pkill krakenwaf && ./target/release/krakenwaf [flags…]
```

> **Hot-reload note:** The GeoIP database is loaded once at startup.  To apply
> an updated `.mmdb` without downtime, use a rolling restart or wait for the
> next scheduled restart window.

---

## Automatic updates

`watch_tower` picks up the `cron` field from `conf/update.yaml` and calls
`soldier_update --geo-update` on schedule.  With the default `"0 18 1 * *"` the
database is refreshed on the **1st of each month at 18:00 local time** — matching
MaxMind's own monthly release cadence.

Start the scheduler:

```bash
./target/release/watch_tower &
```

---

## Bundled database

A copy of `db/geo/GeoLite2-City.mmdb` is committed to the repository so the WAF
works out of the box without needing credentials.  This copy may be **several
months out of date** by the time you deploy; it is strongly recommended to run
`soldier_update --geo-update` after configuring your credentials to get the
latest release.

If the database file is absent or cannot be opened, GeoIP enrichment is
silently disabled (the WAF operates normally; `country` and `continent_name`
fields are empty strings in all log outputs).

---

## Log format

### SQLite (`logs/db/vulns_alert.db`)

```sql
SELECT occurred_at, client_ip, country, continent_name, title, severity
FROM   vulnerabilities
ORDER  BY occurred_at DESC
LIMIT  20;
```

### JSONL (`logs/json/krakenwaf.jsonl`)

Each event line includes:

```json
{
  "timestamp": "2026-05-28T18:00:00Z",
  "client_ip": "8.8.8.8",
  "country": "United States",
  "continent_name": "North America",
  "severity": "critical",
  ...
}
```

### Critical raw log (`logs/raw/critical.log`)

```
[2026-05-28T18:00:00Z] ... ip="8.8.8.8" country="United States" continent="North America" ...
```

---

## Privacy considerations

GeoIP resolution is performed **entirely on-host** — no data is sent to MaxMind
at request time.  The downloaded `.mmdb` file is a static binary that maps
IP prefixes to geographic metadata; it does not contain personal data and is
not subject to GDPR consent requirements.

---

## Disabling GeoIP

Set `active: false` in `conf/update.yaml`:

```yaml
maxmind-geo:
  active: false
```

Alternatively, remove or rename `db/geo/GeoLite2-City.mmdb`.  In both cases the
WAF will log an informational message at startup and continue operating normally.

---

## Testing GeoIP enrichment

Before running integration tests involving real HTTP traffic, ensure that
`Banning_mode: false` is set in `conf/banning.yaml` to prevent the WAF from
banning `127.0.0.1` (the loopback address used by the test suite).  Failing to
do so will cause block-count accounting to be skewed by auto-bans triggered
during the test run.

```yaml
# conf/banning.yaml
Banning_mode: false
```

See `tests/geoip_test.rs` for the full test suite, including the `#[ignore]`
tests that demonstrate multi-region verification via free SOCKS5 proxies.
