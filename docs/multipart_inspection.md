# Multipart request inspection

`multipart/form-data` bodies are parsed into their constituent parts so each
part's payload is fed to the matchers as its own inspection unit, instead of the
matchers seeing one opaque blob glued together with boundary and MIME headers
(which would defeat word-boundary-anchored keyword rules).

This document describes two AppSec properties of the parser and the
per-part inspection that callers rely on.

## Boundary delimiters are anchored to a line start

A multipart delimiter is the byte sequence `--<boundary>`. Per RFC 2046
§5.1.1 every delimiter in a well-formed body is preceded by a CRLF (or sits at
the very start of the body).

KrakenWaf only treats a `--<boundary>` occurrence as a real delimiter when it
is at offset 0 **or** immediately follows a line ending (`\n`, which also covers
`\r\n`). Matching the boundary at an arbitrary offset would let an attacker
embed the literal `--<boundary>` token *inside* a part body to fragment the
inspection window and split a single keyword across two synthetic parts:

```text
union--<boundary>select      # NOT split: the embedded token is mid-line
```

Bare-LF bodies (no carriage return) are still parsed, so non-browser clients are
unaffected.

## Binary parts are inspected up to a bounded prefix (polyglot defence)

Each part's body is classified before inspection:

| Declared `Content-Type`            | Inspected bytes                |
| ---------------------------------- | ------------------------------ |
| Textual (`text/*`, JSON, XML, …)   | full body                      |
| Binary (`image/*`, `octet-stream`) | bounded prefix (first 8 KiB)   |
| Absent / unknown — sniffs as text  | full body                      |
| Absent / unknown — sniffs binary   | bounded prefix (first 8 KiB)   |

Part **metadata** (the `Content-Disposition`, `filename`, `Content-Type`
headers) is always inspected regardless of body type.

Earlier releases skipped binary part bodies entirely. That left a *polyglot*
gap: a text attack payload smuggled under, say, `Content-Type: image/png` was
never scanned. KrakenWaf now inspects a **bounded prefix** of every binary part:

- payloads in practice live near the start of the part, so the prefix catches
  the common case, **and**
- a genuinely large binary upload is not scanned in full, so the cost stays
  bounded (a multi-megabyte image does not become a multi-megabyte scan).

The prefix size is a compile-time constant (`8 KiB`) chosen to cover real
polyglot headers comfortably while keeping per-upload work small.

## Bounds

- At most 256 parts are extracted from a single body; the rest are ignored.
- Boundary tokens longer than 70 characters (RFC 2046 limit) are rejected.
- When the body cannot be parsed the caller falls back to inspecting the raw
  bytes, so there is no false-negative window.
