# Request normalization

Before the keyword, regex, and CMC engines run, KrakenWaf builds a *normalized
view* of the request. A WAF that inspects a different string than the one the
upstream finally parses risks **false negatives** (the WAF sees something
benign, the app sees an attack) or **false positives** (the reverse). The
normalization contract is therefore deliberately explicit and pinned by unit
tests in `src/waf/engine/normalize.rs`.

## What is normalized

- **UTF-16 transcoding (LE/BE)** — applied **first**, before percent-decoding.
  A leading byte-order mark (`FF FE` little-endian, `FE FF` big-endian) or the
  characteristic interleaved-NUL pattern of ASCII-range UTF-16 text (`A\0B\0…`
  for LE, `\0A\0B…` for BE) is recognised and transcoded to UTF-8. The whole
  buffer must match the pattern, so binary bodies with scattered NULs are left
  alone. This closes an evasion where separators (`=`/`&`) or any payload are
  hidden inside a UTF-16 stream that the WAF would otherwise treat as opaque
  bytes but a UTF-16-aware backend would parse. Because it runs inside
  `normalize_request_bytes` / `normalize_str`, **every** CMC module and rule
  benefits (e.g. it underpins the `HPP_detect` separator decoding).
- **Percent-decoding (`%XX`)** — decoded repeatedly, up to **4 passes**
  (`MAX_URL_DECODE_PASSES`), stopping early once a pass changes nothing. This
  peels single/double/triple-encoding (`%252e%252e` → `..`). The cap bounds CPU
  on adversarial input; a payload that only reveals an attack after **5+** decode
  layers is not matched on the fully-decoded form — but no mainstream backend
  decodes that many times, and the engine additionally inspects the raw form
  (below).
- **`+` → space** — applied everywhere (form-urlencoded semantics) so a rule
  like `union select` still matches `union+select`. A percent-encoded plus
  (`%2b`) decodes to `+` on the first pass and is then folded to a space on the
  second, so the separator cannot be hidden by encoding it.
- **Null-byte dual-form** — views are split on `\0`, so both the full string and
  the null-truncated prefix are inspected. Defeats `foo\0../etc/passwd` tricks
  where a C-layer backend truncates at the first NUL.
- **Latin-1 fallback** — when lossy UTF-8 decoding introduces `\u{FFFD}`
  replacement characters, a 1:1 byte→char Latin-1 view is also inspected so
  byte-specific patterns are not masked.
- **Multi-form inspection** — the engine never trusts a single view. Keyword and
  regex matchers inspect the normalized form, the **raw/original** form, and the
  Latin-1 form, de-duplicated. Inspecting the raw form brings these matchers to
  parity with the CMC, libinjection, and vectorscan engines (which already
  inspected the original) and means detection does not depend on the WAF and the
  upstream agreeing on decode depth or on whether `+` means space in a path.

## What is intentionally not normalized

These are documented so operators understand the limits and can encode rule
variants explicitly when needed:

- Unicode normalization (NFKC), fullwidth/homoglyph folding.
- Overlong UTF-8 sequences.
- HTML-entity decoding (`&lt;` etc.).

## Operational notes

- Because percent-decoding is **more aggressive** than a typical once-decoding
  backend, the dominant tuning risk is occasional false positives (the WAF
  resolves an encoding the app leaves literal). Use detect-only mode
  (`--mode detect-only`) and the per-rule scoring (`--anomaly-threshold`) to tune
  before enabling blocking.
- The behaviours above are covered by regression tests; changing them requires
  updating those tests, which makes any change to the contract explicit in code
  review.
