# Per-request inspection time cap (`--max-inspection-ms`)

`--max-inspection-ms <N>` (or `global-options.Max_inspection_ms` in the CMC
config) sets a per-request **wall-clock** ceiling on WAF inspection. When the
budget is exhausted the engine stops scanning and the request is allowed to
proceed with whatever findings were already produced. `0` (the default)
disables the cap.

```bash
krakenwaf --max-inspection-ms 50 [...]      # 50 ms ceiling per request
```

Resolution order: `--max-inspection-ms` → `global-options.Max_inspection_ms`
in the `--cmc-load` file → built-in default (`0`, disabled).

---

## What the deadline actually covers

The deadline is **checked at the top of each inspection *view*** in
`inspect_payload_inner` (`src/waf/engine/mod.rs`). A "view" is one of the
de-duplicated forms of the payload (normalised, raw, Latin-1) and its
`&`/`;`/`?`/newline/NUL-delimited segments. Concretely, the deadline bounds the
per-view loop that runs:

- the **keyword** matchers (Aho-Corasick over URI / headers / body), and
- the **custom regex rules** (`rules/regex/*.json`).

The engines that run **once, before** that loop are **not** interrupted by the
deadline:

- the **CMC** modules (`cmc_manager.inspect`, `inspect_java_deser`),
- **libinjection** (SQLi / XSS), and
- **Vectorscan** (when `--enable-vectorscan` is set).

So `--max-inspection-ms` is best understood as a cap on the **keyword + regex
view loop**, not as a hard real-time bound on the entire pipeline.

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
  (e.g. 10–50 ms for typical rule sets). Too tight a value can let a large
  legitimate payload through under-inspected once the budget is hit.
- A request that exhausts the budget is **allowed** (fail-open on the cap),
  matching the documented behaviour of the flag — the cap is a latency guard,
  not an enforcement control.
