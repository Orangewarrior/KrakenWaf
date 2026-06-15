# Secrets & environment variables

KrakenWaf reads every credential through a single helper,
`secrets::load_secret(NAME)` (`src/secrets.rs`), which resolves a secret using a
**file-first, environment-fallback** chain. This keeps credentials out of
`/proc/<pid>/environ` (readable by any process sharing the UID), crash dumps,
and the environment inherited by child processes — while staying backward
compatible with plain environment variables.

## Resolution order

For a secret named `NAME`, the first source that yields a non-empty value wins:

1. **`<NAME>_FILE`** — if this environment variable is set, its value is treated
   as a path and the file's contents are used. This is the Docker-Compose
   `*_FILE` idiom and lets you point a secret anywhere on disk.
2. **`/run/secrets/krakenwaf/<NAME>`** — the conventional mount directory. A
   Kubernetes projected secret or a bind-mounted Docker secret placed here is
   picked up with **zero extra configuration**.
3. **`NAME`** — the plain environment variable (legacy / 12-factor).

File contents are trimmed of surrounding whitespace, so a trailing newline left
by `echo "secret" > file` does not corrupt the value. An empty or
whitespace-only file is treated as absent and resolution falls through to the
next source.

## Secrets KrakenWaf reads

| Secret | Used for | File default | Env fallback |
| --- | --- | --- | --- |
| `MAXMIND_ACCOUNT_ID` | MaxMind GeoLite2 download (`soldier_update --addr-list maxmind-geo`) | `/run/secrets/krakenwaf/MAXMIND_ACCOUNT_ID` | `MAXMIND_ACCOUNT_ID` |
| `MAXMIND_LICENSE_KEY` | MaxMind GeoLite2 download | `/run/secrets/krakenwaf/MAXMIND_LICENSE_KEY` | `MAXMIND_LICENSE_KEY` |
| `SPAMHAUS_DQS_KEY` | Spamhaus DQS zone queries | `/run/secrets/krakenwaf/SPAMHAUS_DQS_KEY` | `SPAMHAUS_DQS_KEY` |
| `REDIS_PASSWORD` | Redis AUTH (rate-limiter / ban list) | `/run/secrets/krakenwaf/REDIS_PASSWORD` | `REDIS_PASSWORD` |
| `REDIS_USERNAME` | Redis ACL username (Redis 6+) | `/run/secrets/krakenwaf/REDIS_USERNAME` | `REDIS_USERNAME` |
| `BEARER_PASSWORD` | `Authorization: Bearer` token for the dedicated observability port (`/metrics`, health probes, kraken-ui) | `/run/secrets/krakenwaf/BEARER_PASSWORD` | `BEARER_PASSWORD` |
| `RORSCHACH_SECRET_EVEN` | Even-parity secret for the Rorschach rule-management bearer token (`/rule/control/cmc/*`). base64url (no padding), ≥ 64 random bytes. See `docs/rule_management.md`. | `/run/secrets/krakenwaf/RORSCHACH_SECRET_EVEN` | `RORSCHACH_SECRET_EVEN` |
| `RORSCHACH_SECRET_ODD` | Odd-parity secret for the Rorschach rule-management bearer token. base64url (no padding), ≥ 64 random bytes. | `/run/secrets/krakenwaf/RORSCHACH_SECRET_ODD` | `RORSCHACH_SECRET_ODD` |

Every place in the docs and config that mentions one of these variables also
notes the file option.

For `soldier_update` downloads and Spamhaus DQS validation, these credentials
only authenticate the upstream service. DNS resolution for those updater paths
uses Quad9 DNS-over-TLS with DNSSEC validation enabled; DNS queries are carried
over encrypted TLS transport, and `/etc/hosts` fallback is disabled for that
resolver.

## Examples

### Docker / Docker Compose

```yaml
services:
  krakenwaf:
    image: krakenwaf:latest
    secrets:
      - source: maxmind_license
        target: /run/secrets/krakenwaf/MAXMIND_LICENSE_KEY
      - source: redis_password
        target: /run/secrets/krakenwaf/REDIS_PASSWORD
secrets:
  maxmind_license:
    file: ./secrets/maxmind_license_key.txt
  redis_password:
    file: ./secrets/redis_password.txt
```

No KrakenWaf configuration is needed — the files land on the conventional path
and are picked up automatically.

### Kubernetes

Project a `Secret` into `/run/secrets/krakenwaf/`:

```yaml
volumes:
  - name: kraken-secrets
    secret:
      secretName: krakenwaf-secrets
containers:
  - name: krakenwaf
    volumeMounts:
      - name: kraken-secrets
        mountPath: /run/secrets/krakenwaf
        readOnly: true
```

### systemd

```ini
[Service]
LoadCredential=REDIS_PASSWORD:/etc/krakenwaf/redis_password
Environment=REDIS_PASSWORD_FILE=%d/REDIS_PASSWORD
```

`%d` expands to the credentials directory; `REDIS_PASSWORD_FILE` then points at
the decrypted credential.

### Explicit path override

```sh
export MAXMIND_LICENSE_KEY_FILE=/var/run/secrets/maxmind.key
```

### Plain environment variable (still supported)

```sh
export REDIS_PASSWORD='…'
```

Prefer files in production; the environment-variable form is best reserved for
local development.
