# Proxy diagnostics

`debug-proxy-dev` controls developer-grade proxy diagnostic logging.

```yaml
# conf/proxy.yaml
debug-proxy-dev: false
```

Keep it `false` for normal production traffic. With the default, noisy events
such as malformed `Forwarded:` header values are traced at debug level but are
not persisted. Critical proxy failures are still eligible for JSONL persistence.

Set it to `true` temporarily during incident analysis or proxy-chain debugging:

```yaml
debug-proxy-dev: true
```

Diagnostic proxy events are appended to:

```text
logs/proxy_errors_dev/proxy_errors.jsonl
```

Each event includes `timestamp`, `severity`, `function`, source `file` and
`line`, a stable `code`, a human-readable `message`, and contextual fields such
as the raw forwarding header and parsed host candidate. This is intended for
local debugging of trusted-proxy parsing, not for long-term high-volume audit
storage.

The WAF also records inspection deadline events separately at:

```text
logs/filter/deadline.jsonl
```

Those events are fail-closed security decisions and are independent of
`debug-proxy-dev`.
