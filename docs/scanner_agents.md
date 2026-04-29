# Scanner / Crawler User-Agent Blocking

KrakenWAF v2.10.0 ships a built-in scanner and crawler User-Agent blocklist,
derived from the **OWASP Core Rule Set** (CRS)
`scanners-user-agents.data` file.

## How it works

On every incoming request KrakenWAF extracts the `User-Agent` header and
matches it (case-insensitively) against every pattern in
`rules/user_agents/scanners.txt`.

- **Match** → HTTP 403 + Alert logged to JSON, raw critical, and SQLite.
- **No match** → request continues through the normal inspection pipeline.

The matching engine used depends on the build:

| Build | Engine |
|-------|--------|
| Default | Aho-Corasick (multi-pattern substring search) |
| `--features vectorscan-engine` + `--enable-vectorscan` | Vectorscan |

## Pattern file format

`rules/user_agents/scanners.txt`:

```
# Lines starting with # are comments.
# One substring per line — matched case-insensitively against User-Agent.
nikto
sqlmap
nmap
```

Patterns are substrings, not full regex. A pattern matches if it appears
anywhere inside the `User-Agent` value.

## Covered tools (v2.10.0)

The bundled list includes patterns for 78 tools, among them:

`arachni`, `burpsuite`, `commix`, `dirbuster`, `gobuster`, `havij`,
`masscan`, `metasploit`, `nessus`, `nikto`, `nmap`, `openvas`, `sqlmap`,
`wfuzz`, `zaproxy`, and many others.

## Customisation

Add or remove lines in `rules/user_agents/scanners.txt` to tune the list.
Changes take effect after a hot-reload (`kill -HUP <pid>` on Linux) or a
WAF restart.

To disable scanner-UA blocking entirely, remove or empty the file. The WAF
starts cleanly with an empty or absent `scanners.txt`.
