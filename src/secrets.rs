//! Secret loading with a **file-first, environment-fallback** strategy.
//!
//! Passing secrets through environment variables is convenient but weak: a
//! process environment is readable via `/proc/<pid>/environ` by any process
//! sharing the UID, leaks into crash dumps, and is inherited by every child
//! process (`Command`). File-based secrets — as mounted by Docker secrets,
//! Kubernetes projected volumes, and systemd `LoadCredential=` — avoid all
//! three problems.
//!
//! [`load_secret`] resolves a secret named `NAME` in this order:
//!
//! 1. **`<NAME>_FILE`** — if set, read the file at that path. This is the
//!    Docker-Compose / `*_FILE` convention and lets operators point a secret
//!    anywhere on disk.
//! 2. **`/run/secrets/krakenwaf/<NAME>`** — the conventional mount directory.
//!    A Kubernetes secret projected here, or a Docker secret (which lands in
//!    `/run/secrets/<NAME>`, symlink/bind this dir), is picked up with zero
//!    configuration. Example: `/run/secrets/krakenwaf/MAXMIND_LICENSE_KEY`.
//! 3. **`NAME`** — the plain environment variable (legacy / 12-factor). Kept
//!    for backward compatibility so existing deployments are unaffected.
//!
//! File contents are trimmed of surrounding whitespace (so a trailing newline
//! left by `echo "secret" > file` does not corrupt the value). An empty or
//! whitespace-only file is treated as "not present" and resolution falls
//! through to the next source.

use std::path::Path;

/// Conventional directory for `KrakenWaf` file-based secrets. A secret named
/// `FOO` is read from `/run/secrets/krakenwaf/FOO`.
pub const SECRETS_DIR: &str = "/run/secrets/krakenwaf";

/// Resolve a secret by name using the file-first, env-fallback chain described
/// at the module level. Returns `None` when no source yields a non-empty value.
#[must_use]
pub fn load_secret(name: &str) -> Option<String> {
    // 1. Explicit per-secret path override: `<NAME>_FILE` (Docker / compose idiom).
    if let Ok(path) = std::env::var(format!("{name}_FILE")) {
        let path = path.trim();
        if !path.is_empty() {
            if let Some(value) = read_secret_file(Path::new(path)) {
                return Some(value);
            }
        }
    }

    // 2. Conventional mount path: `/run/secrets/krakenwaf/<NAME>`.
    if let Some(value) = read_secret_file(&Path::new(SECRETS_DIR).join(name)) {
        return Some(value);
    }

    // 3. Environment-variable fallback (legacy / 12-factor).
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

/// Read a secret file, returning its trimmed contents. `None` when the file is
/// absent, unreadable, or effectively empty.
fn read_secret_file(path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn name_file_override_is_read_and_trimmed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("license");
        let mut f = std::fs::File::create(&path).expect("create");
        // Trailing newline must be stripped.
        writeln!(f, "  super-secret-value  ").expect("write");

        let var = "KWAF_TEST_FILE_OVERRIDE";
        std::env::set_var(format!("{var}_FILE"), &path);
        let got = load_secret(var);
        std::env::remove_var(format!("{var}_FILE"));

        assert_eq!(got.as_deref(), Some("super-secret-value"));
    }

    #[test]
    fn falls_back_to_env_when_no_file() {
        let var = "KWAF_TEST_ENV_FALLBACK";
        std::env::set_var(var, "from-env");
        let got = load_secret(var);
        std::env::remove_var(var);
        assert_eq!(got.as_deref(), Some("from-env"));
    }

    #[test]
    fn empty_file_falls_through_to_env() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty");
        std::fs::write(&path, "   \n").expect("write empty");

        let var = "KWAF_TEST_EMPTY_FILE";
        std::env::set_var(format!("{var}_FILE"), &path);
        std::env::set_var(var, "env-wins-when-file-empty");
        let got = load_secret(var);
        std::env::remove_var(format!("{var}_FILE"));
        std::env::remove_var(var);

        assert_eq!(got.as_deref(), Some("env-wins-when-file-empty"));
    }

    #[test]
    fn missing_everywhere_is_none() {
        // A name that exists in no source resolves to None.
        assert_eq!(load_secret("KWAF_TEST_DEFINITELY_UNSET_XYZ"), None);
    }
}
