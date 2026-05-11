# Java Deserialize Detect CMC

Detects **Java deserialization attack payloads** in both request inputs and
upstream HTTP responses.  Unsafe deserialization of attacker-controlled data is
one of the most critical vulnerability classes: a single crafted gadget-chain
payload can achieve remote code execution on any JVM that deserializes it.

The detector uses a **three-signal scoring model** to distinguish genuine
deserialization payloads from incidental false positives while remaining robust
against encoding variations.

---

## How it works

### Signal categories

Each of the three independent signals contributes 1 point to the detection
score.  The final decision depends on the total score and the configured
`Untrust` level.

#### Signal A — Magic bytes / encoding prefixes

| Pattern | Meaning |
|---------|---------|
| `\xAC\xED\x00\x05` (binary) | Full Java serialization stream header + version 5 |
| `\xAC\xED` (binary) | Java serialization stream magic (partial) |
| `\x1f\x8b` (binary) | GZIP magic (used to wrap compressed Java objects) |
| `rO0AB` (text) | Base64 of `AC ED 00 05 00` — very common in gadget chains |
| `rO0A` (text) | Base64 of `AC ED 00 05` — Java stream magic + version |
| `H4sI` (text) | Base64-GZIP prefix (`1F 8B 08 00` encoded) |
| `%AC%ED` (text) | URL-encoded Java magic (uppercase hex) |
| `%ac%ed` (text) | URL-encoded Java magic (lowercase hex) |
| `aced` (text) | ASCII hex representation of `0xAC 0xED` |

Binary magic is searched in the raw request/response body bytes.  Text patterns
are searched in the UTF-8 representation of the full payload (URI + headers +
body concatenated).

#### Signal B — Java serialization content headers

Fires when either the `Content-Type` or `Accept` header contains the canonical
MIME type for Java serialized objects:

```
application/x-java-serialized-object
```

Header matching is **case-insensitive** (HTTP headers are case-insensitive by
specification).

#### Signal C — Encoded base64 prefix patterns

Fires on any of the following base64 prefixes that commonly appear in serialized
Java object bodies transmitted in base64:

| Pattern | Context |
|---------|---------|
| `rO0AB` | Longest/most specific prefix |
| `rO0A` | Very common in standard Java serialized objects |
| `rO0` | Shortest prefix, also covers partial truncation |

Prefix matching is **case-sensitive** (base64 is case-sensitive).

### Scoring and blocking thresholds

| Score | Condition | Action |
|-------|-----------|--------|
| 3 | All three signals fired | **Block** (unconditional) |
| 2 | Two signals fired, `Untrust ≥ 60` | **Block** |
| 2 | Two signals fired, `Untrust < 60` | Silent `WARN` log; **no block** |
| 1 | One signal fired, `Untrust > 80` | Informative `WARN` log; **no block** |
| 1 | One signal fired, `Untrust ≤ 80` | **No action** |
| 0 | No signals fired | **No action** |

### Inspection scope

The detector runs on **both incoming requests and upstream responses**:

- **Request side** (`inspect_java_deser`): inspects the full HTTP request
  (method line + headers + body) as text plus raw body bytes.  Invoked from
  `inspect_complete_payload_with_context()` after the CMC injection-pattern
  sweep but before the regex pass.
- **Response side**: inspects the concatenation of upstream response headers
  and body text plus raw body bytes.  Invoked from `inspect_response()` after
  all keyword/regex and passwd-leak checks.

### Why `rO0A` fires both Signal A and Signal C

This is intentional: `rO0A` is simultaneously a magic-byte encoding (Signal A —
"this looks like the Java stream header") and a known base64 prefix (Signal C —
"this is the standard opening of a base64-encoded Java object").  A single
`rO0A` string therefore contributes 2 points, triggering a block at the default
`Untrust = 60`.  This aggressive default reflects the near-total absence of
`rO0A` in legitimate non-Java-deserialization traffic.

### Engine selection

| Mode | Mechanism |
|------|-----------|
| Default | Three separate Aho-Corasick automata (one per signal); Signal B uses case-insensitive matching, A and C use case-sensitive |
| `--enable-vectorscan` | Three separate Vectorscan `BlockDatabase` instances; Signal B uses `Flag::CASELESS \| Flag::SINGLEMATCH`, A and C use `Flag::SINGLEMATCH` |

Binary magic detection always uses a simple windowed byte scan over the raw
body (`raw_bytes.windows(n).any(...)`) — no Aho-Corasick or Vectorscan.

---

## Global options — `Untrust` level

The `Untrust` parameter is a global WAF paranoia level (0–100) that applies to
all detectors that support score-based decisions.  It is configured under the
new `global-options` top-level key in the CMC config file:

```yaml
global-options:
  Untrust: 60    # default; valid range 0–100

CMC-Rules:
  Java_deserialize_detect: true
  # ... other rules
```

| `Untrust` value | Behaviour for 2-signal Java deser match |
|----------------|----------------------------------------|
| 0–59 | Silent log only; traffic allowed |
| 60–100 (default ≥ 60) | Blocked |

A 1-signal match (single weak indicator) is logged at info level only when
`Untrust > 80`; otherwise the request is allowed silently.

---

## Enabling the module

Add `Java_deserialize_detect: true` under `CMC-Rules` in your config file
(default location `rules/cmc/config.yaml`):

```yaml
global-options:
  Untrust: 60

CMC-Rules:
  SQLi_comments_detect: true
  Overflow_detect: true
  SSTI_detect: true
  SSI_injection_detect: true
  ESI_injection_detect: true
  CRLF_injection_detect: true
  Request_Smuggling_detect: true
  NOSQL_injection_detect: true
  XXE_attack_detect: true
  Anti_exposed_backup: true
  Anti_passwd_leak: true
  Java_deserialize_detect: true
```

Start the WAF:

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --cmc-load rules/cmc/config.yaml
```

To enable Vectorscan SIMD acceleration (requires the `vectorscan-engine` Cargo
feature):

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --cmc-load rules/cmc/config.yaml \
  --enable-vectorscan
```

To disable, set the value to `false` or remove the line entirely.

---

## Detection finding

When a request or response is blocked the following structured finding is emitted
(visible in logs, the Prometheus `/metrics` endpoint, and the SQLite database):

| Field | Value |
|-------|-------|
| Title | `CMC Java deserialization attack detection` |
| Severity | `Critical` |
| CWE | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) — Deserialization of Untrusted Data |
| Reference | [OWASP – Insecure Deserialization](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data) |
| `rule_match` | `cmc::java_deserialize_detect:signals=<A+B+C> evidence=<detail>` |
| `rule_line_match` | `cmc/java_deserialize_detect.rs:generated` |

---

## Examples

### Blocked requests

```
# Java serialized object in POST body (rO0A fires A+C → 2 signals → block)
POST /api/object  body=rO0AAABwdXIAEGphdmEubGFuZy5PYmplY3Q=
  → WAF blocks (403)  signals=A(magic)+C(prefix)  evidence=text:rO0A

# Java content-type + binary magic + base64 prefix (3 signals → always block)
POST /rmi/invoke
  Content-Type: application/x-java-serialized-object
  body=<binary AC ED 00 05>rO0A...
  → WAF blocks (403)  signals=A(magic)+B(header)+C(prefix)

# Commons-Collections gadget chain via Accept header + rO0AB body
GET /api
  Accept: application/x-java-serialized-object
  body=rO0ABXNyADJzdW4ucmVmbGVjd...
  → WAF blocks (403)  signals=A(magic)+B(header)+C(prefix)
```

### Allowed requests (insufficient signals)

```
# Only the Java content-type header (1 signal B) at untrust=60 → allowed
POST /api  Content-Type: application/x-java-serialized-object  body={"normal":"json"}
  → forwarded  (1 signal — threshold not reached at untrust=60)

# Clean JSON POST — no signals
POST /api/login  Content-Type: application/json  body={"user":"alice"}
  → forwarded  (0 signals)

# H4sI alone (1 signal A) at untrust=60 → allowed
GET /api?data=H4sIAAAAAAAAA...  body=<no java magic in binary>
  → forwarded  (1 signal — threshold not reached at untrust=60)
```

---

## False-positive guidance

The two-signal block threshold is deliberately calibrated to minimise false
positives while catching all realistic deserialization attacks.

Common false-positive scenarios:

| Scenario | Risk | Mitigation |
|----------|------|------------|
| Application that legitimately accepts Java serialized objects | High | Allow the specific endpoint via `rules/allowpaths/lists.yaml` |
| API serving H4sI (GZIP+base64) data unrelated to Java serialization | Low (1 signal only) | Adjust `Untrust` below 80; no block at 1 signal |
| Documentation or logging endpoint that echoes `rO0A` | Low | Allow the path or lower `Untrust` |

If your application legitimately transmits Java serialized objects:

1. **Allow-path**: add the specific endpoint to `rules/allowpaths/lists.yaml`.
2. **Lower Untrust**: set `Untrust: 40` so that 2-signal matches are logged but
   not blocked.
3. **Disable the module**: set `Java_deserialize_detect: false`.

---

## Performance notes

* The three Aho-Corasick automata each perform a single `find` (early-exit) pass
  over the payload text — no count accumulation or `find_iter`.
* Binary magic detection uses `slice.windows(n).any(...)`: O(n) over the raw
  body bytes, scanning at most 4 bytes per window.
* No heap allocation occurs in the hot path beyond the optional Vectorscan
  scanner object.
* When Vectorscan is active, the scan terminates at the first match per signal
  (`Scan::Terminate` issued in the callback), keeping SIMD scan cost near O(n).

---

## Source files

| File | Purpose |
|------|---------|
| `src/cmc/java_deserialize_detect.rs` | `SIGNAL_A_TEXT`, `SIGNAL_B_TEXT`, `SIGNAL_C_TEXT`, `JAVA_DESER_BINARY_MAGIC`, `SingleMatcher`, `JavaDeserializeDfa`, `JavaDeserDecision`, Aho-Corasick/Vectorscan backends, unit tests |
| `src/cmc/mod.rs` | Module registration, `CmcConfig` fields (`java_deserialize_detect`, `untrust_level`), `CmcManager` field, `inspect_java_deser()`, `parse_lenient_yaml()` extended with `global-options` |
| `src/waf/engine.rs` | Integration — `inspect_java_deser()` called in `inspect_complete_payload_with_context()` (request) and `inspect_response()` (response) |
| `rules/cmc/config.yaml` | Default config — `global-options.Untrust: 60`, `Java_deserialize_detect: true` |
