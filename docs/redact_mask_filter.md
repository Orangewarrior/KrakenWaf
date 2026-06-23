# Redact Mask Filter

`redact-mask-filter` controls how KrakenWAF persists sensitive request evidence
for UI consumers.

```yaml
redact-mask-filter: true
```

The default is `true`. When enabled, KrakenWAF stores both:

- raw forensic fields in `vulnerabilities`, intended for admin-only access;
- masked fields in `request_uri_masked`, `fullpath_evidence_masked`, and
  `request_payload_masked`, plus the `vulnerabilities_masked` view for
  non-admin UI roles.

Kraken UI should use the raw `vulnerabilities` fields for `admin` users and the
`vulnerabilities_masked` view, or the `*_masked` columns, for `operator` and
`auditor` users.

When disabled, the masked columns are populated with the raw values so all roles
see the same request evidence.

## Masked Values

Sensitive values are replaced with:

```text
++++
```

The filter masks values in:

- query-string parameters;
- form-encoded POST bodies;
- JSON object fields;
- `Cookie` / `Set-Cookie` pairs;
- `Authorization` credentials such as bearer tokens;
- headers whose names contain sensitive words, such as `X-Api-Key`.

The match is based on sensitive parameter/header names, including localized
terms for password, token, key, code, bearer, and related words across French,
German, Portuguese, Spanish, English, Russian, Chinese, Japanese, and
Indonesian.

## SQLite Contract

Admin queries can read the raw table:

```sql
SELECT request_uri, fullpath_evidence, request_payload
FROM vulnerabilities
ORDER BY id DESC
LIMIT 10;
```

Operator/auditor queries should read the masked view:

```sql
SELECT request_uri, fullpath_evidence, request_payload
FROM vulnerabilities_masked
ORDER BY id DESC
LIMIT 10;
```

The view keeps the legacy column names while sourcing request evidence from the
masked columns.
