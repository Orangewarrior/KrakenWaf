# Per-request inspection time cap (`--max-inspection-ms`)

`--max-inspection-ms <N>` (or `global-options.Max_inspection_ms` in the CMC
config) sets a per-request **wall-clock** ceiling on WAF inspection. When the
budget is exhausted the engine stops scanning, emits a deadline finding, records
`logs/filter/deadline.jsonl`, and blocks the request fail-closed. `0` (the
default) disables the cap.

```bash
krakenwaf --max-inspection-ms 50 [...]      # 50 ms ceiling per request
```

Resolution order: `--max-inspection-ms` → `global-options.Max_inspection_ms`
in the `--cmc-load` file → built-in default (`0`, disabled).

---

## What the deadline actually covers

The deadline is checked between major inspection stages in
`inspect_payload_inner` (`src/waf/engine/mod.rs`): after normalization, after
CMC request checks, after Java deserialization checks, after libinjection,
after Vectorscan, and inside the keyword/regex view loop. A "view" is one of
the de-duplicated forms of the payload (normalised, raw, Latin-1) and its
`&`/`;`/`?`/newline/NUL-delimited segments. The most granular checks are inside:

- the **keyword** matchers (Aho-Corasick over URI / headers / body), and
- the **custom regex rules** (`rules/regex/*.json`).

Engines that run as a single function call are not interrupted mid-call; the
deadline is observed immediately after they return. That keeps the hot detectors
simple while still bounding cumulative inspection time across stages.

In the proxy path, the deadline is created once per request in `dispatch` and
shared by early prefix inspection, optional WebSocket handshake inspection,
multipart part scans, decoded full-body inspection, HPP, and Open Redirect/RFI
checks. Standalone engine calls such as `inspect_complete_payload()` still create
their own deadline for that single call.

## Why that is safe — every engine is linear-time

This is a deliberate design point, not an oversight: **KrakenWaf contains no
backtracking regular-expression engine**, so there is no
[ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service)
amplification to defend against.

| Engine | Implementation | Worst case |
|--------|----------------|-----------|
| Keyword matchers | `aho-corasick` | `O(n)` in input length |
| Custom regex rules | the `regex` crate (RE2-style, compiled with `size_limit`/`dfa_size_limit`) | linear; **no catastrophic backtracking** |
| Vectorscan | Hyperscan/Vectorscan | linear (streaming automaton) |
| CMC modules | literal Aho-Corasick sets, byte scans, and one `regex::RegexSet` (`detect_db_errors`, response-body only) | linear |

The project pulls in **no** `fancy-regex`, `onig`, or PCRE-style engine
(verified in `Cargo.toml`), so a single crafted field cannot trigger
exponential blow-up the way it can with a PCRE-based WAF. The remaining cost is
strictly proportional to payload size, which is already bounded by
`--max-body-bytes` / `max_request_body_buffered_bytes` and the
`max_decompress_ratio` zip-bomb guard.

### Why CMC modules don't need their own deadline

Because every CMC matcher is linear, a CMC module's cost is `O(payload)` with a
small constant. The body size that reaches it is already capped, so its
worst-case time is bounded *without* a deadline. Adding per-pattern deadline
checks inside the CMC modules would buy nothing against ReDoS (there is none)
and would only add branch overhead to the hot path. The `--max-inspection-ms`
loop check exists to bound the **cumulative** cost of scanning a large payload
across many keyword/regex rules and views, which is the part that scales with
the *number of rules*.

## Practical guidance

- Leave it at `0` (disabled) unless you have a latency SLO to defend; the
  linear-time engines make pathological CPU spikes unlikely.
- If you set it, size it against your p99 inspection latency with headroom
  (e.g. 10–50 ms for typical rule sets). Too tight a value can block legitimate
  large payloads once the budget is hit.
- A request that exhausts the budget is **blocked** (fail-closed) with a
  `CWE-400` deadline finding. Deadline events are queued to a background writer
  for `logs/filter/deadline.jsonl`; use that file to inspect the stage, elapsed
  time, payload sample, and rule metadata when available.
