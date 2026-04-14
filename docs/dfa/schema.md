# KrakenWAF DFA schema

KrakenWAF can load optional DFA-style anomaly detectors through `--dfa-load ./rules/dfa/config.yaml`.

Enabled modules:

- `SQLi_comments_detect`: counts SQL block comments like `/**/`. Two or more comments trigger a block.
- `Overflow_detect`: detects any repeated character run of length 10 or more.
- `SSTI_detect`: detects common SSTI delimiters and returns the matched SSTI family id.
- `SSI_injection_detect`: detects SSI directives such as `<!--#include ... -->` and `<!--#exec ... -->`.
- `ESI_injection_detect`: detects ESI tags such as `<esi:include>`, `<esi:inline>`, `<esi:debug/>` and `<!--esi ... -->`.

All DFA modules are implemented as safe Rust state scanners without `unsafe`, following a generated-DFA style layout appropriate for future re2rust migration.

When a DFA returns true, KrakenWAF emits the same structured block event pipeline used by regex, keyword, Vectorscan and libinjection:

- JSONL log
- raw critical log
- SQLite evidence row

The event engine is recorded as `dfa` and the rule source uses the form `dfa/<module>.rs:generated`.
