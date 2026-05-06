# KrakenWAF DFA schema

KrakenWAF can load optional DFA-style anomaly detectors through `--dfa-load ./rules/dfa/config.yaml`.

Enabled modules:

- `SQLi_comments_detect`: counts SQL block comments like `/**/`. Two or more comments trigger a block.
- `Overflow_detect`: detects repeated character runs, structured overflow/flooding patterns, and common shellcode opcode clusters/NOP sleds for x86-32, x86-64 and ARM/Thumb payloads.
- `SSTI_detect`: detects common SSTI delimiters and returns the matched SSTI family id.
- `SSI_injection_detect`: detects SSI directives such as `<!--#include ... -->`, `<!--#exec ... -->`, `<!--#set ... -->`, conditional directives, and spacing/case variants.
- `ESI_injection_detect`: detects ESI tags such as `<esi:include>`, `<esi:inline>`, `<esi:debug/>`, `<esi:vars>`, `<esi:remove>`, flow-control directives, and `<!--esi ... -->`.
- `CRLF_injection_detect`: detects CRLF injection and HTTP response-splitting payloads such as `%0d%0aSet-Cookie:...`, `%0d%0aHTTP/1.1 200 OK`, double-encoded CRLF, `%u000d%u000a`, `\u000d\u000a`, and UTF-8 CR/LF bypass variants.
- `Request_Smuggling_detect`: detects request smuggling indicators such as `Transfer-Encoding: chunked`, `X-Session-Hijack: true`, `Content-Length` values `<= 4`, and injected `Transfer-Encoding: chunked` patterns in URI or body content.

All DFA modules are implemented as safe Rust state scanners without `unsafe`, following a generated-DFA style layout appropriate for future re2rust migration.

When a DFA returns true, KrakenWAF emits the same structured block event pipeline used by regex, keyword, Vectorscan and libinjection:

- JSONL log
- raw critical log
- SQLite evidence row

The event engine is recorded as `dfa` and the rule source uses the form `dfa/<module>.rs:generated`.
