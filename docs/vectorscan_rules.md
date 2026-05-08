# Vectorscan rules

KrakenWaf has two distinct sources of patterns that go to Vectorscan, each with
different compilation semantics. Mixing them up is a common source of either
false positives or "engine fails to start" errors at boot, so the rules are
worth knowing precisely.

| Source | Compiled as | Escaping behaviour |
|--------|-------------|--------------------|
| `rules/Vectorscan/strings2block.json` (`rule_match`) | **PCRE / regex** | None — operator is responsible for escaping metacharacters. |
| `rules/user_agents/scanners.txt` (one substring per line) | **Plain string literal** | Automatic — every PCRE metacharacter is escaped by the WAF before compilation. |

The runtime path for each is, respectively, `build_vectorscan_matcher()` and
`build_vectorscan_literal_matcher()` in `src/waf/engine.rs`.

---

## `rules/Vectorscan/strings2block.json` — PCRE

Each rule's `rule_match` field is fed verbatim to Vectorscan's regex compiler.
You get the full Hyperscan / Vectorscan PCRE subset: literal characters,
character classes (`[a-z]`), alternation (`a|b`), quantifiers (`*`, `+`, `?`,
`{n,m}`), anchors (`^`, `$`), word boundaries (`\b`), case-insensitive flag
(applied globally by the WAF — patterns are compiled with `Flag::CASELESS`),
and so on. Backreferences and PCRE features like atomic groups are **not**
supported by Hyperscan; if you need them, use `rules/regex/*.json` instead.

### Common pitfall: unescaped metacharacters

If you mean to match the four-byte string `cmd.exe /c` literally:

```jsonc
// WRONG — '.' matches ANY single byte; will also fire on "cmdXexe /c"
{ "rule_match": "cmd.exe /c", ... }

// RIGHT — '.' is escaped so only a real period matches
{ "rule_match": "cmd\\.exe /c", ... }
```

The metacharacters that need escaping in `strings2block.json` are:

```
.  ^  $  *  +  ?  (  )  [  ]  {  }  |  \
```

### Common pitfall: JSON double-escaping

Inside JSON, every `\` you want Vectorscan to see has to be written as `\\`.
The `sleep\(` rule already in the bundled file is a good example:

```json
{ "rule_match": "sleep\\(", ... }
```

The on-disk file contains the eight bytes `s l e e p \ ( ` — Vectorscan
receives `sleep\(` and matches the literal four-byte sequence `sleep(`. Forget
the second backslash and you ship `sleep(`, which Vectorscan rejects with
*Missing close parenthesis for group started at index 5*.

### Quick check before deploying a new rule

```bash
$ cargo build --release --features vectorscan-engine
$ ./target/release/krakenwaf --enable-vectorscan --no-tls --listen 127.0.0.1:9999
```

The engine compiles every `strings2block.json` rule into a single Vectorscan
`BlockDatabase` at startup. A bad pattern aborts the boot with the file path,
the rule line, and the underlying compiler error — there is no silent skip.

### When the rule really is a plain literal

There is no `"literal": true` flag in the schema today; the convention is "if
you put it in `strings2block.json`, you escape it". For an everyday substring
like `union select` or `' or '1'='1`, this is a non-issue (no metacharacters)
— that is why most of the bundled rules look like plain strings.

---

## `rules/user_agents/scanners.txt` — plain literals

Each non-empty, non-comment line is treated as a **plain substring** of the
incoming `User-Agent` header. The WAF passes every line through
`regex_escape_literal()` before handing it to Vectorscan, so entries like:

```
Mozilla/5.0 (compatible; Panoptic
Mozilla/5.0 (compatible; AppScan;
Mozilla/4.0 (Hydra)
```

compile cleanly even with unbalanced or otherwise regex-meaningful characters.
Findings emitted for these still show the raw substring — the escaped form is
only used during pattern compilation.

This means **you must not write regex syntax in `scanners.txt`**. A line like
`sqlmap.*tool` will be treated as the literal eleven-byte string
`sqlmap.*tool`, not a regex. If you want regex semantics for User-Agent
matching, add a rule in `rules/regex/header_regex.json` instead.

See [`docs/scanner_agents.md`](scanner_agents.md) for the broader scanner-UA
detection pipeline.

---

## TL;DR

- `strings2block.json` → write PCRE. Escape your metacharacters. Remember JSON
  needs `\\` for one backslash.
- `scanners.txt` → write plain substrings. The WAF escapes them for you.
- For more elaborate UA or path matching, prefer `rules/regex/*.json`.
