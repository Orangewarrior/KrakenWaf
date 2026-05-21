# Score-ranked regex and Vectorscan rules

KrakenWaf regex rules under `rules/regex/*.json` and Vectorscan literal rules
under `rules/Vectorscan/strings2block.json` support a numeric `score` field.

- `score >= 600`: a matching rule blocks immediately.
- `score < 600`: the match does not block by itself. Its score is added to an
  internal `sum_score` accumulator for the current rule list.
- When `sum_score >= 600`, KrakenWaf blocks using the current matching rule.
- When a new rule list is scanned, `sum_score` starts at `0`.
- When an immediate high-score block happens, `sum_score` is reset to `0`.
- **`sum_score` is reset per inspection view** (since v2.25.0). The full
  normalized payload is inspected as one view, and each segment split on
  `\n`, `&`, `;`, `?`, `\r`, `\0` is a separate, independently-scored view.
  Cross-segment attacks (e.g. `evil-a&evil-b&evil-c` with three rules each
  scoring 250) are still caught because the full-payload view already
  accumulates all matches via `find_iter` (keywords) or per-rule iteration
  (regex). This prevents a single rule from being double-counted when it
  appears in both the full payload and a sub-segment derived from it.

The configurable threshold is controlled by `--anomaly-threshold` (default
`600`). Any rule whose `score` is `>= threshold` blocks on its own; rules
with `score < threshold` only block when their accumulated `sum_score` within
a single view reaches `threshold`.

The bundled regex and Vectorscan rules use `score: 1000` unless they are
explicit score-engine laboratory rules. This preserves the previous behavior for
production rules while allowing lower-confidence detections to be correlated.

Example:

```json
{
  "enable": 1,
  "http_action": "Request",
  "title": "Low confidence marker",
  "severity": "low",
  "score": 250,
  "cwe": "CWE-693",
  "description": "A low-confidence rule that only blocks when combined.",
  "url": "https://owasp.org/www-project-web-security-testing-guide/",
  "rule_match": "kwaf-score-post-a",
  "id": "score-body-low-001"
}
```

The demo attack tool includes score sweeps:

```bash
cargo run --bin attack -- --target http://127.0.0.1:8080 --verbose
```

Expected behavior:

- A single low-score marker such as `kwaf-score-post-a` is allowed.
- A chain such as `kwaf-score-post-a kwaf-score-post-b kwaf-score-post-c kwaf-score-post-d` blocks.
- A direct marker with `score: 600`, such as `kwaf-score-post-high`, blocks immediately.
