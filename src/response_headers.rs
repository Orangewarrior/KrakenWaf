use anyhow::{Context, Result};
use http::{HeaderMap, HeaderName, HeaderValue};
use std::{fs, path::Path};

#[derive(Debug, Clone, Default)]
pub struct ResponseHeaderPolicy {
    entries: Vec<(HeaderName, HeaderValue)>,
}

impl ResponseHeaderPolicy {
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
                anyhow::bail!("invalid header policy line {} in {}. Expected 'Header-Name: value'", idx + 1, path.display());
            };
            let name = HeaderName::from_bytes(name_raw.trim().as_bytes())
                .with_context(|| format!("invalid header name at {}:{}", path.display(), idx + 1))?;
            let value = HeaderValue::from_str(value_raw.trim())
                .with_context(|| format!("invalid header value at {}:{}", path.display(), idx + 1))?;
            entries.push((name, value));
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
        if self.entries.is_empty() {
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
