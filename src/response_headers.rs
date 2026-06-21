use anyhow::{Context, Result};
use http::{HeaderMap, HeaderName, HeaderValue};
use std::{fs, path::Path};

#[derive(Debug, Clone)]
pub struct ResponseHeaderPolicy {
    entries: Vec<(HeaderName, HeaderValue)>,
}

impl Default for ResponseHeaderPolicy {
    fn default() -> Self {
        Self {
            entries: default_entries(),
        }
    }
}

impl ResponseHeaderPolicy {
    /// # Errors
    /// Returns an error if the file cannot be read or contains malformed header entries.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read response header policy {}", path.display()))?;
        let mut entries = Vec::new();
        for (idx, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((name_raw, value_raw)) = line.split_once(':') else {
                anyhow::bail!(
                    "invalid header policy line {} in {}. Expected 'Header-Name: value'",
                    idx + 1,
                    path.display()
                );
            };
            let name = HeaderName::from_bytes(name_raw.trim().as_bytes()).with_context(|| {
                format!("invalid header name at {}:{}", path.display(), idx + 1)
            })?;
            let value = HeaderValue::from_str(value_raw.trim()).with_context(|| {
                format!("invalid header value at {}:{}", path.display(), idx + 1)
            })?;
            entries.push((name, value));
        }
        if entries.is_empty() {
            anyhow::bail!(
                "response header policy {} contains no active headers",
                path.display()
            );
        }
        Ok(Self { entries })
    }

    pub fn apply(&self, headers: &mut HeaderMap, is_websocket_upgrade: bool) {
        if is_websocket_upgrade {
            // CSP and X-Frame-Options legitimately do not apply to WebSocket upgrade
            // responses, but X-Content-Type-Options and Referrer-Policy are still
            // meaningful and cheap. Apply only those two so the upgrade response is
            // not left completely bare of hardening headers.
            apply_minimal_ws_headers(headers);
            return;
        }
        for (name, value) in &self.entries {
            headers.insert(name.clone(), value.clone());
        }
    }
}

fn apply_minimal_ws_headers(headers: &mut HeaderMap) {
    static NOSNIFF: HeaderName = HeaderName::from_static("x-content-type-options");
    static REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
    if !headers.contains_key(&NOSNIFF) {
        headers.insert(NOSNIFF.clone(), HeaderValue::from_static("nosniff"));
    }
    if !headers.contains_key(&REFERRER_POLICY) {
        headers.insert(
            REFERRER_POLICY.clone(),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
    }
}

fn default_entries() -> Vec<(HeaderName, HeaderValue)> {
    vec![
        (
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("SAMEORIGIN"),
        ),
        (
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ),
        (
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ),
        (
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; base-uri 'self'; frame-ancestors 'self'; object-src 'none'; form-action 'self'; upgrade-insecure-requests",
            ),
        ),
        (
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000"),
        ),
        (
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), camera=(), microphone=()"),
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin-allow-popups"),
        ),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-site"),
        ),
        (
            HeaderName::from_static("cross-origin-embedder-policy"),
            HeaderValue::from_static("unsafe-none"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_applies_hardening_headers() {
        let policy = ResponseHeaderPolicy::default();
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, false);
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert!(headers.contains_key("content-security-policy"));
    }

    #[test]
    fn websocket_upgrade_gets_minimal_headers() {
        let policy = ResponseHeaderPolicy::default();
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, true);
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert!(!headers.contains_key("content-security-policy"));
    }

    #[test]
    fn explicit_empty_policy_file_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("headers.txt");
        std::fs::write(&path, "# comments only\n\n").expect("write");
        let err = ResponseHeaderPolicy::from_file(&path).expect_err("empty policy must fail");
        assert!(err.to_string().contains("contains no active headers"));
    }
}
