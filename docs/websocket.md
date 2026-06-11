# WebSocket Control Policy

KrakenWaf enforces a configurable control policy over `ws://` / `wss://`
upgrade requests it tunnels to the upstream. The policy is loaded from
`conf/websocket.yaml` every time the WAF starts (or from `--websocket-conf
<path>`), and is **enabled by default** with conservative limits that support
ordinary WebSocket traffic while resisting flooding and context abuse.

When `enable_ws_control` is `false`, no limit applies and WebSocket upgrades are
tunneled transparently (the pre-2.x behaviour).

## Configuration — `conf/websocket.yaml`

```yaml
web_socket:
  enable_ws_control: true        # master switch; false ⇒ transparent tunnel
  allowed_paths:                 # paths permitted to upgrade (empty ⇒ any path)
    - /ws
    - /wss
  idle_timeout_secs: 60          # close after this long with no frame either way (0 disables)
  max_session_secs: 3600         # hard cap on total session lifetime (0 disables)
  max_connections_per_ip: 8      # simultaneous sessions per source IP (0 disables)
  inspect_handshake: true        # run the inspection engine over the upgrade request
```

### Field reference

| Field | Type | Default | Enforced | Description |
|-------|------|---------|----------|-------------|
| `enable_ws_control` | bool | `true` | — | Master switch. `false` disables every limit below. |
| `allowed_paths` | list\<string\> | `[/ws, /wss]` | handshake | Request paths allowed to upgrade. A path not on the list is rejected with **HTTP 403**. An empty list permits any path. A configured entry matches an exact path or a sub-path on a `/` boundary (`/ws` covers `/ws/chat`, not `/wsfoo`). |
| `idle_timeout_secs` | u64 | `60` | tunnel | No frame in **either** direction for this long closes the tunnel. `0` disables. |
| `max_session_secs` | u64 | `3600` | tunnel | Hard cap on a single session's total lifetime. `0` disables. |
| `max_connections_per_ip` | usize | `8` | handshake | Maximum simultaneous sessions from one source IP. Excess is rejected with **HTTP 429 + Retry-After: 5**. `0` disables. |
| `inspect_handshake` | bool | `true` | handshake | Run the full inspection engine over the upgrade request (URI + headers). A detection blocks the handshake. |

## Enforcement points

```
client ──upgrade──▶  [ WAF ]  ──tunnel──▶  upstream

handshake (before any upstream connection):
  1. allowed_paths      → 403 if the path is not permitted
  2. inspect_handshake  → 403 if the inspection engine fires (Block mode)
  3. max_connections_per_ip → 429 if the per-IP session cap is reached

established tunnel (bidirectional pump):
  4. idle_timeout_secs  → close on inactivity
  5. max_session_secs   → close on lifetime cap
```

The per-IP session slot is reserved at the handshake and released exactly when
the tunnel ends (RAII guard moved into the tunnel task), so a closed or
timed-out session frees the slot immediately. The per-IP counter map is reaped
by the same janitor that sweeps the concurrency / body-byte maps, so a client
rotating source addresses cannot grow it without bound.

## Effective values at a glance

```bash
krakenwaf config dump --redact     # includes the resolved websocket: section
krakenwaf config validate          # validates conf/websocket.yaml among others
```
