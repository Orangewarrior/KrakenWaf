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
              │ inspect   │ select response mode
              │ request   │ inspect body or prefix
              │           │
              ◄──────────
```

1. **Request phase** — runs before the request is forwarded. Rules with
   `"http_action": "Request"` (or no `http_action`) are checked here.
   A match returns HTTP 403 immediately; the upstream never receives the
   request.

2. **Response phase** — runs after the upstream response headers select a
   bounded response mode. Rules with `"http_action": "Response"` are checked
   against the status, headers, and either the complete textual body or the
   retained prefix of a generic binary body.
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

## Bounded response modes

| Mode | Content types | Memory behaviour |
|------|---------------|------------------|
| `InspectBuffered` | `text/*`, JSON, XML, JavaScript, YAML, GraphQL, form data | Buffers up to `--max-upstream-response-bytes` (8 MiB default), then performs complete-body inspection and any required rewrite. |
| `StreamOnly` | Images, video, audio, fonts, PDF, archives, WASM | Streams Hyper frames directly, counting bytes up to `max_streamed_response_bytes` (1 GiB default). |
| `TeePrefix` | `application/octet-stream`, unknown or missing content type | Retains and inspects only `response_inspect_prefix_bytes` (64 KiB default), then streams the remainder. |

The streaming limits live under `memory-limits` in
`rules/cmc/config.yaml`. A response with a declared `Content-Length` above its
selected limit is rejected before forwarding. For chunked responses, KrakenWaf
counts bytes during forwarding and terminates the response if the cap is
crossed.

Complete-body response rules are strongest on `InspectBuffered` content.
`TeePrefix` rules can only detect evidence present in the configured prefix,
which deliberately trades complete binary inspection for bounded memory use.
