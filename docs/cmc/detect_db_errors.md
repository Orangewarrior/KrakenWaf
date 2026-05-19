# CMC Module: `Detect_db_errors`

## Overview

`Detect_db_errors` is a KrakenWaf CMC (Custom Multi-signal Check) module that
intercepts upstream HTTP **response bodies** containing database error messages
before they reach the client.

When an attacker probes a web application with injection payloads, the DBMS
often reflects a verbose error string back through the application layer.
Intercepting that response:

- Denies the **error-based SQL/NoSQL injection feedback loop** that tools like
  SQLmap and NoSQLmap rely on to enumerate schema, data, and blind boolean
  conditions.
- Prevents **information disclosure** about the DB engine, version, schema
  names, or column names that appear in native error messages.

---

## Research Basis

This module was built by studying the error-fingerprint databases used by the
open-source web-security tools **SQLmap** (`sqlmap/data/errormessages/`) and
**NoSQLmap**. Those tools maintain curated regex patterns for dozens of DBMS
engines precisely so they can confirm which engine is running from error
responses. KrakenWaf inverts that knowledge: the same patterns that help
attackers enumerate a target are used here to block the exfiltration channel.

The pattern set covers **all major SQL and NoSQL engines**, including:

| Category | Engines |
|---|---|
| SQL RDBMS | MySQL, MariaDB, Drizzle, TiDB, PostgreSQL, Oracle, MSSQL, SQLite, IBM DB2, Informix, Firebird, SAP MaxDB, Sybase, Ingres, HSQLDB, H2, Derby, MonetDB, Vertica, Presto/Trino, ClickHouse, CrateDB, Snowflake, Virtuoso, Altibase, FrontBase, Mimer |
| NoSQL | MongoDB / Mongoose, CouchDB, Couchbase / N1QL, Elasticsearch, Redis, Memcached |
| Graph DB | Neo4j / Cypher |

---

## Detection Architecture

### Pattern file

Patterns are loaded from `rules/error_msgs/sql_errors.txt` at WAF startup.
Each non-empty, non-comment line is a PCRE-compatible regex. Lines beginning
with `#` are comments and are ignored. The placeholder `<REGEX_LITERAL>` is
also silently skipped if present (artefact of template-based rule sets).

### Startup compilation

When the module is enabled the WAF:

1. Reads every pattern from `sql_errors.txt`.
2. Validates each pattern individually with `regex::Regex::new()` — invalid
   patterns are skipped with a startup warning so a single bad rule cannot
   disable the whole module.
3. Compiles all valid patterns into a single `regex::RegexSet`.  `RegexSet`
   internally builds a unified NFA/DFA so the entire set can be matched in
   **O(n) time** in the length of the body, with no per-pattern overhead.
4. *(Vectorscan path)* When `--enable-vectorscan` is passed, attempts to build
   a `BlockDatabase` from the same patterns using the Hyperscan SIMD engine.
   If the database compiles successfully, Hyperscan is used for scanning and
   can achieve 3–5× higher throughput than the CPU regex engine on long
   response bodies.  If any pattern fails to compile in Hyperscan (some
   advanced PCRE constructs are unsupported), the entire Hyperscan path falls
   back to `RegexSet` — detection is never degraded.

### Per-request cost

- Each inspected response body incurs exactly **one scan** over the pattern set.
- No pattern recompilation occurs at request time.
- The scan terminates as soon as the first matching pattern is found.

---

## Action: Block vs Monitor

The module respects the global `untrust_level` configured in
`rules/cmc/config.yaml`:

| `untrust_level` | Detection action |
|---|---|
| ≥ 60 (default) | **Block** — WAF returns 403, logs event to raw / JSONL / SQLite |
| < 60 | **Monitor** — WAF forwards upstream response, logs event to raw / JSONL / SQLite without blocking |

This lets operators in "paranoia-off" mode collect telemetry about potential
attacks without impacting legitimate traffic, then raise `untrust_level` to 60
once they have confidence in the pattern set.

---

## Configuration

Enable the module by adding `Detect_db_errors: true` under `CMC-Rules` in
`rules/cmc/config.yaml`:

```yaml
global-options:
  Untrust: 60          # ≥ 60 → block; < 60 → monitor/log only

CMC-Rules:
  Detect_db_errors: true
```

The module is **disabled by default** (`false`) for backwards compatibility.

---

## Pattern File Location

```
rules/
└── error_msgs/
    └── sql_errors.txt   ← one PCRE regex per line
```

The path is resolved relative to the `--rules-dir` argument.  Custom patterns
can be added by appending lines to `sql_errors.txt`; the WAF must be restarted
(or `--rules-dir` reloaded) to pick up changes.

---

## Findings

When the module fires, the security event contains:

| Field | Value |
|---|---|
| `title` | `CMC DB error-based attack detection` |
| `severity` | `High` |
| `cwe` | `CWE-209` (Information Exposure Through an Error Message) |
| `rule_match` | `cmc::detect_db_errors:pattern=<matched_regex>` |
| `request_payload` | First 256 characters of the response body |

---

## Limitations

- Only inspects **response bodies** — request bodies are not scanned by this
  module (other CMC modules cover request-side injection signals).
- Generic patterns such as `(?i)\bSyntaxError\b` or `(?i)\bReferenceError\b`
  may fire on legitimate JavaScript stack traces embedded in HTML error pages.
  Tune `untrust_level < 60` (monitor mode) in development environments.
- Pattern accuracy is inherited from SQLmap / NoSQLmap research; false
  positives are possible on applications that legitimately echo DB-related
  strings in responses (e.g., documentation sites).
