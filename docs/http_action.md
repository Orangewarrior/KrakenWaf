# Response Inspection (`http_action`)

KrakenWAF v2.10.0 introduces per-rule **phase routing**: every detection rule
carries an `http_action` field that controls whether the rule fires on the
**incoming request** or on the **upstream response**.

## Field values

| Value | Phase | What is inspected |
|-------|-------|-------------------|
| `"Request"` (default) | Request phase | URI, request headers, request body |
| `"Response"` | Response phase | Response status, response headers, response body |

The field is **optional**; when omitted it defaults to `"Request"` so that all
existing rules remain forward-compatible.

## How it works

```
Client ──► WAF ──► Upstream
              │          │
              │ inspect   │ buffer response body
              │ request   │ inspect response
              │           │
              ◄──────────
```

1. **Request phase** — runs before the request is forwarded. Rules with
   `"http_action": "Request"` (or no `http_action`) are checked here.
   A match returns HTTP 403 immediately; the upstream never receives the
   request.

2. **Response phase** — runs after the upstream response body is fully
   buffered. Rules with `"http_action": "Response"` are checked against the
   response status code, response headers, and response body.
   A match returns HTTP 403 to the client and logs the finding.

Both Aho-Corasick keyword matchers and regex matchers honour `http_action`.
Vectorscan databases are split into request and response pools at startup.

## Rule JSON example

```json
{
  "enable": 1,
  "http_action": "Response",
  "title": "Sensitive data leak in response",
  "severity": "high",
  "cwe": "CWE-200",
  "description": "Detects SSN-like patterns in upstream responses.",
  "url": "https://cwe.mitre.org/data/definitions/200.html",
  "rule_match": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
  "id": "00001"
}
```

Place response rules in `rules/regex/body_regex.json` (or
`rules/Vectorscan/strings2block.json` for Vectorscan) with
`"http_action": "Response"`.

## Performance considerations

The upstream response body is buffered in memory before inspection. The buffer
cap is controlled by `--max-upstream-response-bytes` (default 100 MiB). If the
upstream returns a body larger than this cap the connection is terminated with
an error log entry, regardless of whether response rules are enabled.

If no `"Response"` rules are loaded, the response body is still buffered (for
forwarding), but no pattern matching occurs, so the overhead is negligible.
