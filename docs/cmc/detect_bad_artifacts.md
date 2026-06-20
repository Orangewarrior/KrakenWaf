# CMC Module: `Detect_bad_artifacts`

## Overview

`Detect_bad_artifacts` is a KrakenWaf CMC (Custom Multi-signal Check) module
that inspects request **URI paths** for sensitive file and directory artifact
patterns that should never be publicly accessible.

The module targets a broad class of information-disclosure vulnerabilities: when
a web server accidentally exposes dotfiles, configuration files, debug logs,
credentials, CI/CD artefacts, or Linux pseudo-filesystem entries, an attacker
can retrieve secrets without exploiting any application logic. This module
closes that gap at the WAF level by matching URI paths against a comprehensive
list of known-sensitive patterns.

---

## Research Basis

The pattern set was derived from the **OWASP ModSecurity Core Rule Set (CRS)**
[`restricted-files.data`](https://github.com/coreruleset/coreruleset/blob/main/rules/restricted-files.data)
data file — the same literals used by CRS's restricted-file access detection
rules. The list has been extended with additional patterns observed in the wild.

Categories covered:

- **Apache artefacts** — `.htaccess`, `.htdigest`, `.htpasswd`
- **Home-level dotfiles** — `.env`, `.envrc`, `.ssh/`, `.aws/`, `.azure/`,
  `.git/`, `.gitconfig`, `.netrc`, `.npmrc`, `.gnupg/`, etc.
- **Generic config filenames** — `config.json`, `config.yaml`, `config.php`,
  `config.ini`, `config.toml`, `config.xml`, `config.yml`, and dev/prod/test
  variants with underscore, hyphen, and dot separators.
- **Credentials files** — `credentials.json`, `secrets.json`, `secrets.yaml`,
  `.git-credentials`, `user_secrets.yml`
- **Compressed database dumps** — `.sql.gz`, `.sql.tar`, `.sql.bz`, `.sql.rar`
  and 25 other archive extensions
- **CMS-specific paths** — WordPress (`wp-config.`, `debug.log`), Symfony,
  Drupal, PrestaShop, Magento, October CMS
- **Framework configs** — ASP.NET `Web.config`, Node `package.json`,
  `webpack.config.js`, Composer `composer.json`, `composer.lock`
- **CI/CD artefacts** — `.gitlab-ci.yml`, `.travis.yml`, `Dockerfile`,
  `compose.yml`
- **Package manager files** — `.yarnrc`, `.npmrc`, `.bowerrc`, `bower.json`,
  `pyproject.toml`, `go.mod`, `cargo.toml`
- **Linux pseudo-filesystem** — `proc/cpuinfo`, `proc/meminfo`, `proc/self`,
  `/proc/` prefix, and 80+ other `/proc` entries; `sys/block`, `sys/devices`,
  `/sys/` prefix
- **CVE-specific patterns** — CVE-2023-5003 (`ldap-authentication-report.csv`),
  CVE-2023-49103 (`phpinfo.php`), CVE-2025-30208 (`/@fs/`, `/@id/`)
- **Shell history and rc files** — `.bash_history`, `.zsh_history`, `.ashrc`,
  `.kshrc`, `.screenrc`, etc.
- **IDE and editor artefacts** — `.idea`, `.vscode`, `.editorconfig`, `nbproject/`
- **Database client configs** — `.my.cnf`, `.pgpass`, `.dbshell`, `login.sql`

---

## Detection Architecture

### Pattern file

Literal strings are loaded from `rules/artifacts/file_pitfalls.txt` at WAF
startup. Each non-empty, non-comment line is one literal. Comments start with
`#` and are ignored.

### Startup compilation

When the module is enabled the WAF:

1. Reads every line from the file and filters out comments / empty lines.
2. Builds a `memchr::memmem::Finder` per pattern for the CPU fast path.
   `memmem` is a Boyer-Moore-like substring search optimised for short
   needles — the lookup benefits from SIMD acceleration on x86_64.
3. *(Vectorscan path)* When `--enable-vectorscan` is passed, a Hyperscan
   `BlockDatabase` is built from the regex-escaped patterns with `SINGLEMATCH`
   flags (no `SOM_LEFTMOST` needed since only presence, not offset, matters).

### Per-request cost

- Called from `inspect_uri()` in the early request phase, before the body is
  assembled — no latency penalty for clean traffic.
- One linear scan across the URI path patterns, short-circuiting on first match.
- No pattern recompilation at request time.

---

## Action Policy

The module respects the global `Untrust` level configured in
`conf/filter.yaml`:

| `Untrust` | Action | Severity |
|---|---|---|
| `>= 60` (default) | **Block** — WAF returns 403; request never reaches the upstream | High |
| `< 60` | **Silent log** — request is forwarded; a warning is emitted via `tracing::warn!` | — |

---

## Configuration

Enable the module by adding `Detect_bad_artifacts: true` under `CMC-Rules` in
`conf/filter.yaml`:

```yaml
global-options:
  Untrust: 60          # >= 60 → block; < 60 → silent log

CMC-Rules:
  Detect_bad_artifacts: true
```

The module is **enabled** in the default `conf/filter.yaml` shipped with
KrakenWaf. It can be disabled by setting `Detect_bad_artifacts: false` or
removing the key.

---

## Pattern File Location

```
rules/
└── artifacts/
    └── file_pitfalls.txt   ← one literal substring per line
```

The path is resolved relative to the `--rules-dir` argument. Custom literals
can be added by appending lines; the WAF must be restarted to pick them up.

---

## Findings

When the module fires, the security event contains:

| Field | Value |
|---|---|
| `title` | `CMC sensitive artifact access detection` |
| `severity` | `High` |
| `cwe` | `CWE-538` (File and Directory Information Exposure) |
| `rule_match` | `cmc::detect_bad_artifacts:pattern=<matched_pattern>` |
| `request_payload` | `<METHOD> <PATH>` |
| `reference_url` | OWASP CRS `restricted-files.data` upstream link |

---

## Limitations

- Matches are **substring** checks on the URI path — a pattern like `.env`
  matches `/app/.env`, `/prod/.env.bak`, etc. This is intentional but may
  produce false positives for applications that legitimately serve files whose
  names contain these substrings (e.g., `/templates/env-example.html`). Use
  `allow_paths` to exempt specific routes.
- The module inspects the **raw URI path** as received by the WAF. Percent-
  encoded paths (e.g., `%2E%65%6E%76`) are not decoded before matching. A
  future version may add a decode pass.
- Patterns are case-sensitive. A server exposing `/.ENV` would not be matched
  by the `.env` pattern. Extend `file_pitfalls.txt` with uppercase variants if
  needed.
- The module does not distinguish between GET, POST, PUT, or DELETE — any HTTP
  method targeting a matched URI path is blocked/logged. If your application
  legitimately POSTs to a path that matches (e.g., `/debug.log` as a webhook
  sink), exempt it with `allow_paths`.
