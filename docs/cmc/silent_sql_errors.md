# CMC Module: `Silent_sql_errors`

## Overview

`Silent_sql_errors` is a KrakenWaf CMC (Custom Multi-signal Check) module that
inspects upstream HTTP **response bodies** for verbose DBMS error fingerprints
and — depending on the global `Untrust` level — either **scrubs** the matched
substring or **blocks** the response entirely.

Unlike [`Detect_db_errors`](detect_db_errors.md), which always blocks when a
regex matches, this module's default action at lower paranoia levels is to
rewrite the response so the error fingerprint is invisible to the attacker
while the legitimate application response still reaches the browser intact
(only the DBMS-error giveaway is replaced with a single ASCII space).

---

## Research Basis

The pattern set was derived from a study of the **OWASP ModSecurity Core Rule
Set (CRS)** — specifically the
[`rules/sql-errors.data`](https://github.com/coreruleset/coreruleset/blob/main/rules/sql-errors.data)
data file used by CRS's `942100–942999` SQLi response-detection rule range.
Each line in that file is a literal substring that CRS treats as evidence of
a leaking DBMS error.  KrakenWaf reuses the same literals locally as the
fingerprint set; matches are *byte-for-byte*, no regex interpretation.

The list covers all common SQL and many NoSQL/embedded engines:
MySQL/MariaDB/Drizzle, PostgreSQL, Oracle, MSSQL, SQLite, IBM DB2, Informix,
Firebird, Sybase, Ingres, HSQLDB/H2/Derby, MonetDB, Vertica, Presto/Trino,
ClickHouse, MemSQL, CrateDB, Snowflake, Virtuoso, Altibase, FrontBase, Mimer,
Neo4j/Cypher, plus JDBC/ODBC/JCC/.NET connector identifiers
(`Npgsql.`, `Zend_Db_Adapter_*_Exception`, `org.postgresql.util.PSQLException`,
`System.Data.SqlClient.SqlException`, `OracleException`, etc.).

---

## Detection Architecture

### Pattern file

Literal strings are loaded from `rules/error_msgs/sql_errors_static.txt`
at WAF startup. Each non-empty, non-comment line is one literal. Comments
start with `#` and are ignored.

### Startup compilation

When the module is enabled the WAF:

1. Reads every line from the file and filters out comments / empty lines.
2. Builds a `memchr::memmem::Finder` per pattern for the CPU fast path.
   `memmem` is a Boyer-Moore-like substring search optimised for short
   needles — the lookup is sub-linear in the haystack length and benefits
   from the standard library's SIMD acceleration on x86_64.
3. *(Vectorscan path)* When `--enable-vectorscan` is passed, a Hyperscan
   `BlockDatabase` is built from the regex-escaped patterns with
   `SOM_LEFTMOST | SINGLEMATCH` flags so the SIMD engine reports the exact
   match offsets needed to perform the scrub.

### Per-response cost

- One linear scan across the body, short-circuiting on first match.
- No pattern recompilation at request time.
- Match offsets (`start`, `end`) are recorded so the scrubber can slice the
  body around the matched range without re-scanning.

---

## Action: Scrub vs Block

The module respects the global `Untrust` level configured in
`conf/filter.yaml`:

| `Untrust` | Action | Severity |
|---|---|---|
| `>= 80` | **Block** — WAF returns 403; the response never reaches the client | High |
| `< 80` (default) | **Silent scrub** — the matched literal is replaced with a single ASCII space; `Content-Length` is recomputed; the response is forwarded to the client | Low |

### Scrub mechanics

When the response body is `body` and the match spans `body[start..end]`:

```
new_body = body[..start] + b" " + body[end..]
Content-Length = new_body.len()
```

The single-space replacement keeps the surrounding markup intact (so HTML or
JSON does not become structurally invalid) and is short enough that the
attacker cannot infer the original error length from the modified
`Content-Length`.

### Why log even on silent scrub?

The finding is still written to all security outputs (`raw`, `JSONL`,
`SQLite`) with severity `Low`. This gives operators visibility into
"something looked like a DBMS error escaped to the front-end" without
breaking the user-visible flow — exactly the trade-off CRS's
paranoia-level-1 rules embody.

---

## Configuration

Enable the module by adding `Silent_sql_errors: true` under `CMC-Rules` in
`conf/filter.yaml`:

```yaml
global-options:
  Untrust: 60          # < 80 → scrub; >= 80 → block

CMC-Rules:
  Silent_sql_errors: true
```

The module is **disabled by default** (`false`) for backwards compatibility.

### Interaction with `Detect_db_errors`

When both `Detect_db_errors` and `Silent_sql_errors` are enabled and a
response body matches **both** modules' pattern sets,
`Detect_db_errors` is checked first in `inspect_response_body` and will
**block** the response before `Silent_sql_errors` runs.  This means the
silent-scrub path is never observed for responses that also trip
`Detect_db_errors`.

> Enabling both modules together is **safe and recommended as
> defence-in-depth**, but verify that none of the OWASP CRS literals appears
> in *legitimate* application responses (e.g., documentation sites that may
> echo strings like `SQL syntax` in body text) before going to production.
> If a legitimate response is being scrubbed, audit it: set
> `Detect_db_errors: false` and observe what `Silent_sql_errors` would
> rewrite, then add an `allow_paths` rule or remove the offending literal
> from `sql_errors_static.txt`.

---

## Pattern File Location

```
rules/
└── error_msgs/
    └── sql_errors_static.txt   ← one literal substring per line
```

The path is resolved relative to the `--rules-dir` argument. Custom literals
can be added by appending lines to `sql_errors_static.txt`; the WAF must be
restarted to pick up changes.

---

## Findings

When the module fires, the security event contains:

| Field | Value |
|---|---|
| `title` | `CMC silent SQL error scrubber` |
| `severity` | `Low` (scrub mode) / `High` (block mode) |
| `cwe` | `CWE-209` (Information Exposure Through an Error Message) |
| `rule_match` | `cmc::silent_sql_errors:literal=<matched_string>` |
| `request_payload` | First 256 characters of the response body |
| `reference_url` | OWASP CRS `sql-errors.data` upstream link |

---

## Limitations

- Only inspects **response bodies** — request bodies are not scanned by this
  module (other CMC modules cover request-side injection signals).
- Generic literals such as `SQL syntax`, `Exception`, or `SQL Server` may
  fire on legitimate body text that happens to use the same wording (e.g.,
  documentation, error-message catalogues). Audit before enabling in
  paranoid environments.
- The single-space replacement preserves HTML / JSON structure for almost all
  realistic responses, but pathological cases — e.g., the matched literal is
  the *entire* JSON value — can produce invalid JSON. Operators handling
  such APIs should evaluate the trade-off and either disable the module on
  those routes (via `allow_paths`) or accept the structural breakage as the
  lesser evil compared to disclosing DBMS internals.
- Pattern accuracy is inherited from OWASP CRS research; false positives are
  possible on applications that legitimately echo DB-related strings in
  responses. Use scrub mode (`Untrust < 80`) in development to collect
  telemetry first.
