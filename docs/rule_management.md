# Rule management API (real-time CMC control plane)

KrakenWaf exposes a dedicated, isolated control plane for **inspecting and
toggling CMC detection modules at runtime** — no restart, no config reload. It
is authenticated by the **Rorschach Token**, a rotating bearer credential, and
gated by a CIDR-aware IP allowlist.

> The control plane is **opt-in**: it only opens when the Rorschach secrets are
> provisioned. If the secrets are absent the feature stays disabled and no extra
> port is opened.

---

## Topology

The control plane runs on its own listener, exactly like the observability
(`/metrics`) port:

```
client ──► KrakenWaf rule-management :4342  (TLS, or plain HTTP under --no-tls)
              │
              ├─ Gate 1: IP allowlist (CIDR-aware)        → 403 if outside
              └─ Gate 2: Rorschach bearer token            → 401 if missing/invalid
                          │
                          └─► GET  /rule/control/cmc/list
                              POST /rule/control/cmc/update
```

* It binds the **same IP as `--listen`** on a separate port and reuses the
  listener's TLS certificates (plain HTTP only when the whole WAF runs with
  `--no-tls`).
* It is **not** a reverse proxy: it serves only the two endpoints and answers
  everything else with `404`.

### Port configuration

Resolution order (highest precedence first):

1. `--rule-management-port <port>` on the command line
2. `rule_management_port:` in `conf/proxy.yaml`
3. Built-in default `4342`

```yaml
# conf/proxy.yaml
rule_management_port: 4342
```

If the resolved port collides with the proxy `listen` port or the metrics port,
the rule-management listener is not started (a warning is logged) — choose a
distinct port.

---

## Authentication — the Rorschach Token

The token is named (a small homage) after the Watchmen character because, like
the mask, its face keeps shifting: it is recomputed every **5-minute window** so
a captured token is worthless once the window rolls over.

### Secrets

Two operator-generated secrets, selected by the parity of the time window:

| Secret | Used when | Format |
| --- | --- | --- |
| `RORSCHACH_SECRET_EVEN` | `step` is even | base64url (no padding), ≥ 64 random bytes |
| `RORSCHACH_SECRET_ODD`  | `step` is odd  | base64url (no padding), ≥ 64 random bytes |

Both are resolved through the standard **file-first, env-fallback** secret chain
(`<NAME>_FILE` → `/run/secrets/krakenwaf/<NAME>` → `<NAME>`; see
[`secrets.md`](secrets.md)), so credentials are never hard-coded. Generate them
with a CSPRNG, for example:

```sh
python3 - <<'PY'
import os, base64
for name in ("RORSCHACH_SECRET_EVEN", "RORSCHACH_SECRET_ODD"):
    print(f'{name}={base64.urlsafe_b64encode(os.urandom(64)).decode().rstrip("=")}')
PY
```

Or use the bundled helper:

```sh
cargo run --bin rorschach_keygen
cargo run --bin rorschach_keygen -- --write
cargo run --bin rorschach_keygen -- --dir /secure/dir
```

At startup the WAF decodes each secret and verifies it is **at least 64 bytes**.
If a provisioned secret is missing its pair, fails to decode, or is too short,
**the WAF refuses to start** with an informative error (fail-closed). The first
64 bytes are used as the BLAKE2b keyed-MAC key.

### Cryptography

No bespoke cryptography is used. The token is a single keyed MAC over a
canonical, newline-delimited message, built only from the audited
[`orion`](https://crates.io/crates/orion) crate:

* **Keyed MAC** — `orion::auth` (BLAKE2b-256 in keyed mode) authenticates the
  message with the parity-selected secret.
* **Body hash** — `orion::hash` (unkeyed BLAKE2b-256) of the raw request body
  bytes; the resulting `body_hash` is embedded **inside** the MAC-authenticated
  message.

### Canonical message

```
rorschach-v1\n{client_id}\n{step}\n{nonce_b64}\n{method}\n{path}\n{body_hash}
```

| Field | Meaning |
| --- | --- |
| `step` | `floor(unix_time_utc / 300)` — the 5-minute window index |
| `nonce_b64` | base64url(no-pad) of 64 random bytes, fresh per request |
| `method` | upper-case HTTP method (`GET`, `POST`) |
| `path` | the request URI **path** component (no query string) |
| `body_hash` | base64url(no-pad) of BLAKE2b-256 over the **raw** body bytes |

The token is `base64url(no-pad)` of the 32-byte keyed tag.

### Wire format

```
Authorization: Bearer rch1.<client_id>.<step>.<nonce_b64>.<token_b64>
```

`client_id` is restricted to `[A-Za-z0-9_-]` so the `.` delimiter is
unambiguous.

### Validation guarantees

* **Window + skew** — the presented `step` must be within **±60 s** of the
  server clock; a far-future or stale step is `401`.
* **Constant-time** — the tag is verified with orion's constant-time comparison.
* **Anti-replay** — each `(client_id, step, nonce)` triple is accepted **once**;
  a repeat within the window is `401` even with a valid tag.
* **Body/method/path binding** — altering the request body, method, or path
  after signing invalidates the MAC → `401`.
* **No detail leak** — the token is never logged (only the `+++++` placeholder),
  and every failure collapses to a single opaque HTTP status.

> Because the body is bound into the token, the request body must be sent
> **unmodified and uncompressed** — the bytes the client signs must be the bytes
> the server receives.

---

## IP allowlist

The control plane additionally restricts callers by **effective client IP**
(honouring trusted-proxy CIDRs / `X-Forwarded-For`). The allowlist lives at:

```
rules/addr/allowlist/allow_rule_management.txt
```

(overridable with `--rule-management-allowlist <path>`). One entry per line —
bare IP or CIDR; `#` comments and blank lines ignored:

```
127.0.0.1
10.0.0.0/8
::1
```

A caller outside every entry receives `403` **before** authentication. An empty
or invalid allowlist is a fatal startup error — the control plane refuses to
start (fail-closed). The shipped default restricts access to loopback.

---

## Endpoints

### `GET /rule/control/cmc/list`

Returns the live state of every CMC module.

```json
{
  "status": "ok",
  "modules": {
    "CMC-Rules": {
      "SQLi_comments_detect": true,
      "Overflow_detect": true,
      "SSTI_detect": true,
      "SSI_injection_detect": true,
      "ESI_injection_detect": true,
      "CRLF_injection_detect": true,
      "Request_Smuggling_detect": true,
      "NOSQL_injection_detect": true,
      "XXE_attack_detect": true,
      "Anti_exposed_backup": true,
      "Anti_passwd_leak": true,
      "Java_deserialize_detect": true,
      "Detect_db_errors": true,
      "Silent_sql_errors": true,
      "Detect_bad_artifacts": true,
      "Detect_bots_n_scanners": true,
      "HPP_detect": true,
      "Open_redirect_n_RFI_detect": true
    }
  }
}
```

### `POST /rule/control/cmc/update`

Applies a **partial patch** — only the modules present in the body change;
absent modules are left untouched. The detection table is hot-swapped atomically
in real time.

Request:

```json
{
  "modules": {
    "CMC-Rules": {
      "HPP_detect": false,
      "Silent_sql_errors": false
    }
  }
}
```

Response:

```json
{
  "status": "ok",
  "context": "cmc_update",
  "updated": {
    "disabled": ["Silent_sql_errors", "HPP_detect"],
    "enabled": []
  }
}
```

After this call, `GET /rule/control/cmc/list` reflects `HPP_detect` and
`Silent_sql_errors` as `false`, and the WAF filter engine stops applying those
modules immediately — including across hot reloads of other rules.

#### Input validation

Every JSON document is strictly typed with `deny_unknown_fields`:

* an **unknown module name** (or any unknown field) → `400`;
* **absent** modules → OK (unchanged);
* any parse/validation failure returns a generic
  `{"status":"error","error":"invalid_request","message":"JSON is not in the expected format"}`
  that leaks no internal detail.

---

## Status codes

| Condition | Status |
| --- | --- |
| Valid token + allowlisted IP + valid request | `200` |
| Missing or invalid Rorschach token | `401` |
| Replayed nonce / altered path, body, or method / future step | `401` |
| Effective client IP outside the allowlist | `403` |
| Unknown JSON field / malformed body | `400` |

---

## Reference client

`src/rorschach.rs` exposes `sign_token(...)` (and `random_nonce_b64()`), the
exact code path the server verifies against. The integration tests in
`tests/rule_management_test.rs` use it as a reference client; kraken-ui (in a
separate repository) ports the same algorithm.

A minimal `curl` example (after computing `<token>` with the algorithm above):

```sh
curl -sS https://127.0.0.1:4342/rule/control/cmc/list \
  -H "Authorization: Bearer rch1.kraken-ui.<step>.<nonce_b64>.<token_b64>"
```
