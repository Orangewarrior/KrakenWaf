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
- `NOSQL_injection_detect`: detects NoSQL injection when URI or body content contains at least one marker from list A and one marker from list B.
- `XXE_attack_detect`: detects XML external entity attacks when URI or body content contains at least one marker from list A and one marker from list B.

`NOSQL_injection_detect` list A markers:

`$gt`, `$nin`, `$where`, `$save`, `$exists`, `$remove`, `$in`, `$comment`, `selector`, `$or`, `$and`, `this.password.match`, `db.stores.mapReduce`, `db.injection.insert`, `&&`, `||`.

`NOSQL_injection_detect` list B markers:

`==1`, `== 1`, `]=1`, `] = 1`, `true`, `sleep(`, `logins`, `admin`, `pass`, `user`, `undefined`, `Date`, `null`, `root`, `new%`, `%00`, `{}`, `success`, `.insert`, `while(true)`, `dropDatabase(`.

The detector also treats `==[1-9]` and `== [1-9]` as list B matches. When KrakenWAF is compiled with the Vectorscan feature and started with `--enable-vectorscan`, the NoSQL DFA uses Vectorscan for the literal list checks and keeps the DFA numeric equality check for the digit pattern.

`XXE_attack_detect` list A markers:

`ENTITY`, `xi:include`.

`XXE_attack_detect` list B markers:

`xxe`, `SYSTEM`, `etc/password`, `eval`, `exfil`, `xmlns:xi`, `send`, `DOCTYPE`, `soap`, `file`.

When KrakenWAF is compiled with the Vectorscan feature and started with `--enable-vectorscan`, the XXE detector uses Vectorscan for the literal list checks. If the normalized request contains UTF-16LE/BE payload bytes represented as NUL-interleaved text after URL decoding, the XXE detector decodes that view before matching so encoded external entity payloads are still blocked.

All DFA modules are implemented as safe Rust state scanners without `unsafe`, following a generated-DFA style layout appropriate for future re2rust migration.

When a DFA returns true, KrakenWAF emits the same structured block event pipeline used by regex, keyword, Vectorscan and libinjection:

- JSONL log
- raw critical log
- SQLite evidence row

The event engine is recorded as `dfa` and the rule source uses the form `dfa/<module>.rs:generated`.
