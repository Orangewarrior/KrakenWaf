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

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn apply(&self, headers: &mut HeaderMap, is_websocket_upgrade: bool) {
        if is_websocket_upgrade || self.entries.is_empty() {
            return;
        }
        for (name, value) in &self.entries {
            headers.insert(name.clone(), value.clone());
        }
    }
}
