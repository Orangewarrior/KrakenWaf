//! Rorschach Token — a rotating, time-windowed bearer credential for the
//! `KrakenWaf` **rule management** control plane.
//!
//! Named (a small homage) after the Watchmen character because, like the mask,
//! the token's face keeps shifting: it is recomputed every **5-minute** window
//! so a captured token is worthless once the window rolls over.
//!
//! # Construction (the only cryptography used here)
//!
//! No bespoke cryptography is invented. The token is a single keyed MAC over a
//! canonical, newline-delimited message, using the audited [`orion`] crate:
//!
//! * **Keyed MAC** — [`orion::auth`] (BLAKE2b-256 in keyed mode) authenticates
//!   the message with a per-parity secret. This binds the request method, path
//!   and a hash of the body into the token, so altering any of them invalidates
//!   it.
//! * **Body hash** — [`orion::hash`] (unkeyed BLAKE2b-256) of the raw request
//!   body bytes. The resulting `body_hash` is embedded *inside* the
//!   MAC-authenticated message, so the body is covered by the token without the
//!   server having to MAC the (possibly large) body twice.
//!
//! # Canonical message
//!
//! ```text
//! rorschach-v1\n{client_id}\n{step}\n{nonce_b64}\n{method}\n{path}\n{body_hash}
//! ```
//!
//! * `step` = `floor(unix_time_utc / 300)` — the 5-minute window index.
//! * `nonce_b64` = base64url(no-pad) of 64 random bytes, chosen by the client.
//! * `method` = upper-case HTTP method (`GET`, `POST`, …).
//! * `path` = the request URI path component (no query string).
//! * `body_hash` = base64url(no-pad) of BLAKE2b-256 over the raw body bytes.
//!
//! The secret is selected by parity of `step`: `secret_even` when `step` is
//! even, `secret_odd` when odd. Both secrets are operator-provided, random, and
//! rotated independently.
//!
//! # Wire format
//!
//! The token is presented as an HTTP bearer credential:
//!
//! ```text
//! Authorization: Bearer rch1.<client_id>.<step>.<nonce_b64>.<token_b64>
//! ```
//!
//! where `token_b64` = base64url(no-pad) of the 32-byte `BLAKE2b` keyed tag.
//!
//! # Validation guarantees
//!
//! * **Window + skew** — the presented `step` must fall within ±60 s of the
//!   server's clock (so a client whose clock drifts up to a minute still
//!   validates) but no further: a far-future or stale step is rejected.
//! * **Constant-time** — the tag is verified with orion's constant-time
//!   comparison; no byte-by-byte early exit leaks the expected tag.
//! * **Anti-replay** — a `(client_id, step, nonce)` triple is accepted at most
//!   once; a repeat within the window is rejected even with a valid tag.
//! * **No detail leak** — every failure collapses to a single opaque outcome at
//!   the HTTP layer; the presented token is never logged (see [`REDACTED_TOKEN`]).

use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::{mapref::entry::Entry, DashMap};
use orion::auth;
use orion::hash;

/// Environment / file secret name for the even-parity Rorschach secret.
/// Resolved through [`crate::secrets::load_secret`] (file-first, env fallback)
/// so the value is never hard-coded — CIS-benchmark aligned, like every other
/// `KrakenWaf` credential (see `docs/secrets.md`).
pub const SECRET_EVEN_NAME: &str = "RORSCHACH_SECRET_EVEN";
/// Environment / file secret name for the odd-parity Rorschach secret.
pub const SECRET_ODD_NAME: &str = "RORSCHACH_SECRET_ODD";

/// Width of the time window, in seconds. `step = floor(unix_time / 300)`.
pub const STEP_SECONDS: i64 = 300;
/// Maximum tolerated clock drift/skew, in seconds, when validating `step`.
pub const MAX_SKEW_SECONDS: i64 = 60;
/// Minimum length (bytes) a decoded secret must have. The keyed `BLAKE2b` MAC
/// uses the first 64 bytes; orion caps the key at 64 bytes.
pub const MIN_SECRET_BYTES: usize = 64;
/// Length (bytes) of the `BLAKE2b` keyed tag and unkeyed digest.
const TAG_BYTES: usize = 32;
/// Versioned prefix of the bearer credential.
pub const TOKEN_PREFIX: &str = "rch1";

/// Placeholder substituted for the Rorschach token in every log line so the
/// secret credential never reaches disk, a log shipper, or a crash dump.
pub const REDACTED_TOKEN: &str = "+++++";

/// A pair of validated Rorschach secrets (even/odd parity), each already
/// reduced to a 64-byte keyed-MAC key.
pub struct RorschachSecrets {
    even: auth::SecretKey,
    odd: auth::SecretKey,
}

impl std::fmt::Debug for RorschachSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material.
        f.debug_struct("RorschachSecrets").finish_non_exhaustive()
    }
}

impl RorschachSecrets {
    /// Decode and validate both secrets from their base64url (no-pad) forms.
    ///
    /// # Errors
    /// Returns an error when either secret is not valid base64url, decodes to
    /// fewer than [`MIN_SECRET_BYTES`] bytes, or is otherwise rejected by the
    /// keyed-MAC key constructor. The error message names which secret failed
    /// and why, but never echoes the secret value.
    pub fn from_base64(even_b64: &str, odd_b64: &str) -> Result<Self, String> {
        let even = decode_secret_key(SECRET_EVEN_NAME, even_b64)?;
        let odd = decode_secret_key(SECRET_ODD_NAME, odd_b64)?;
        Ok(Self { even, odd })
    }

    /// Select the secret matching the parity of `step`.
    #[allow(clippy::manual_is_multiple_of)]
    fn key_for_step(&self, step: u64) -> &auth::SecretKey {
        if step % 2 == 0 {
            &self.even
        } else {
            &self.odd
        }
    }
}

/// Decode a single base64url (no-pad) secret into a keyed-MAC key.
fn decode_secret_key(name: &str, b64: &str) -> Result<auth::SecretKey, String> {
    let raw = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .map_err(|_| format!("{name} is not valid base64url (no padding) data"))?;
    if raw.len() < MIN_SECRET_BYTES {
        return Err(format!(
            "{name} decoded to {} bytes; a minimum of {MIN_SECRET_BYTES} random bytes is required",
            raw.len()
        ));
    }
    // orion's keyed BLAKE2b accepts 32..=64 byte keys; use the first 64 bytes of
    // the (>= 64-byte) secret as the MAC key.
    auth::SecretKey::from_slice(&raw[..MIN_SECRET_BYTES])
        .map_err(|_| format!("{name} could not be used as a BLAKE2b keyed-MAC key"))
}

/// Outcome of resolving the Rorschach secrets at startup.
#[derive(Debug)]
pub enum SecretsConfig {
    /// Neither secret was provisioned — the rule-management control plane stays
    /// disabled and its listener is never opened.
    Disabled,
    /// Both secrets were provisioned and validated.
    Enabled(RorschachSecrets),
}

/// Resolve the even/odd Rorschach secrets via the standard file-first,
/// env-fallback secret chain (see [`crate::secrets::load_secret`]).
///
/// * Neither secret set ⇒ [`SecretsConfig::Disabled`] (feature off).
/// * Both set and valid ⇒ [`SecretsConfig::Enabled`].
///
/// # Errors
/// Returns an error (which must abort startup — fail-closed) when exactly one
/// secret is set, or when a provisioned secret fails to decode/validate.
pub fn load_secrets() -> Result<SecretsConfig, String> {
    let even = crate::secrets::load_secret(SECRET_EVEN_NAME);
    let odd = crate::secrets::load_secret(SECRET_ODD_NAME);
    match (even, odd) {
        (None, None) => Ok(SecretsConfig::Disabled),
        (Some(_), None) => Err(format!(
            "{SECRET_EVEN_NAME} is set but {SECRET_ODD_NAME} is missing; both Rorschach secrets \
             must be provisioned to enable the rule-management control plane"
        )),
        (None, Some(_)) => Err(format!(
            "{SECRET_ODD_NAME} is set but {SECRET_EVEN_NAME} is missing; both Rorschach secrets \
             must be provisioned to enable the rule-management control plane"
        )),
        (Some(even_b64), Some(odd_b64)) => {
            RorschachSecrets::from_base64(&even_b64, &odd_b64).map(SecretsConfig::Enabled)
        }
    }
}

/// A parsed (but not yet verified) Rorschach bearer credential.
#[derive(Debug, Clone)]
pub struct RorschachCredential {
    pub client_id: String,
    pub step: u64,
    pub nonce_b64: String,
    pub token_b64: String,
}

impl RorschachCredential {
    /// Parse a `rch1.<client_id>.<step>.<nonce_b64>.<token_b64>` credential
    /// (the token portion of an `Authorization: Bearer …` header).
    ///
    /// Returns `None` for any structurally invalid credential. The `client_id`
    /// is constrained to `[A-Za-z0-9_-]` so the dot delimiter is unambiguous.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.split('.');
        let prefix = parts.next()?;
        if prefix != TOKEN_PREFIX {
            return None;
        }
        let client_id = parts.next()?;
        let step_str = parts.next()?;
        let nonce_b64 = parts.next()?;
        let token_b64 = parts.next()?;
        // Exactly five dot-separated fields — reject anything with extras.
        if parts.next().is_some() {
            return None;
        }
        if client_id.is_empty()
            || !client_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return None;
        }
        let step = step_str.parse::<u64>().ok()?;
        if nonce_b64.is_empty() || token_b64.is_empty() {
            return None;
        }
        Some(Self {
            client_id: client_id.to_string(),
            step,
            nonce_b64: nonce_b64.to_string(),
            token_b64: token_b64.to_string(),
        })
    }
}

/// Reason a Rorschach verification failed. All variants map to HTTP 401 at the
/// transport layer; the distinction exists only for internal (token-free) logs
/// and tests, never for the client response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The presented `step` is outside the ±skew acceptance window.
    StepWindow,
    /// The token field is not valid base64url or not a 32-byte tag, or the
    /// keyed MAC did not verify (wrong secret / altered method/path/body).
    BadToken,
    /// The `(client_id, step, nonce)` triple was already consumed.
    Replay,
}

impl VerifyError {
    /// A short, token-free reason string for internal logging.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            VerifyError::StepWindow => "step outside skew window",
            VerifyError::BadToken => "invalid or unverifiable token",
            VerifyError::Replay => "nonce already used",
        }
    }
}

/// Compute the canonical `body_hash`: base64url(no-pad) of BLAKE2b-256 over the
/// raw body bytes.
#[must_use]
pub fn body_hash(body: &[u8]) -> String {
    // `orion::hash::digest` is unkeyed BLAKE2b-256 and is infallible for an
    // in-memory slice; the `unwrap_or_default` fallback is defensive and never
    // taken in practice (an empty digest would simply encode to "").
    let digest = hash::digest(body)
        .map(|d| d.as_ref().to_vec())
        .unwrap_or_default();
    URL_SAFE_NO_PAD.encode(digest)
}

/// Build the canonical newline-delimited message that the token authenticates.
#[must_use]
fn build_message(
    client_id: &str,
    step: u64,
    nonce_b64: &str,
    method: &str,
    path: &str,
    body_hash: &str,
) -> String {
    format!("rorschach-v1\n{client_id}\n{step}\n{nonce_b64}\n{method}\n{path}\n{body_hash}")
}

/// The set of `step` values acceptable for `now_unix` given ±[`MAX_SKEW_SECONDS`]
/// of tolerated clock drift. A presented step is valid iff it equals the step of
/// `now-skew`, `now`, or `now+skew`.
fn acceptable_steps(now_unix: i64) -> [u64; 3] {
    let step_at = |t: i64| -> u64 { u64::try_from(t.max(0) / STEP_SECONDS).unwrap_or(0) };
    [
        step_at(now_unix - MAX_SKEW_SECONDS),
        step_at(now_unix),
        step_at(now_unix + MAX_SKEW_SECONDS),
    ]
}

/// Generate a fresh 64-byte nonce, base64url(no-pad) encoded, using orion's
/// CSPRNG. Client-side helper (used by the integration tests and portable to a
/// reference client such as kraken-ui).
///
/// # Errors
/// Returns an error if the system CSPRNG is unavailable.
#[allow(dead_code)]
pub fn random_nonce_b64() -> Result<String, String> {
    let key = auth::SecretKey::generate(64).map_err(|_| "CSPRNG unavailable".to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(key.unprotected_as_bytes()))
}

/// Sign a Rorschach token (the **client** side of the protocol).
///
/// Returned value is the full bearer credential
/// `rch1.<client_id>.<step>.<nonce_b64>.<token_b64>`. Exposed so the
/// integration tests (and a reference client such as kraken-ui) compute tokens
/// through exactly the same code path the server verifies against.
///
/// # Errors
/// Returns an error only if the underlying keyed-MAC computation fails.
// Reference client-side signer: used by the integration tests (and portable to
// kraken-ui); the WAF binary itself only ever verifies.
#[allow(dead_code)]
pub fn sign_token(
    secrets: &RorschachSecrets,
    client_id: &str,
    step: u64,
    nonce_b64: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String, String> {
    let bh = body_hash(body);
    let message = build_message(client_id, step, nonce_b64, method, path, &bh);
    let key = secrets.key_for_step(step);
    let tag = auth::authenticate(key, message.as_bytes())
        .map_err(|_| "failed to compute Rorschach keyed MAC".to_string())?;
    let token_b64 = URL_SAFE_NO_PAD.encode(tag.unprotected_as_bytes());
    Ok(format!(
        "{TOKEN_PREFIX}.{client_id}.{step}.{nonce_b64}.{token_b64}"
    ))
}

/// Verifies Rorschach credentials and enforces single-use of each
/// `(client_id, step, nonce)` triple within the active window.
#[derive(Debug)]
pub struct RorschachValidator {
    secrets: RorschachSecrets,
    /// Consumed nonces keyed by `"{client_id}\n{step}\n{nonce}"`, valued by the
    /// unix time after which the entry may be pruned.
    seen_nonces: DashMap<String, i64>,
}

impl RorschachValidator {
    #[must_use]
    pub fn new(secrets: RorschachSecrets) -> Self {
        Self {
            secrets,
            seen_nonces: DashMap::new(),
        }
    }

    /// Absolute unix time after which a nonce reserved at `now_unix` for `step`
    /// can no longer be presented (window end + a full skew of slack).
    fn nonce_expiry(step: u64, now_unix: i64) -> i64 {
        let window_end = i64::try_from(step)
            .ok()
            .and_then(|s| s.checked_add(1))
            .and_then(|s| s.checked_mul(STEP_SECONDS))
            .unwrap_or(now_unix);
        window_end.max(now_unix) + MAX_SKEW_SECONDS
    }

    /// Verify a parsed credential against the request it accompanies.
    ///
    /// On success the nonce is consumed (single-use). `now_unix` is the server's
    /// current UTC unix time in seconds.
    ///
    /// # Errors
    /// Returns the [`VerifyError`] describing why validation failed.
    pub fn verify(
        &self,
        cred: &RorschachCredential,
        method: &str,
        path: &str,
        body: &[u8],
        now_unix: i64,
    ) -> Result<(), VerifyError> {
        // 1. Window + skew: reject a step the server's clock cannot accept.
        if !acceptable_steps(now_unix).contains(&cred.step) {
            return Err(VerifyError::StepWindow);
        }

        // 2. Recompute the authenticated message and verify the keyed MAC in
        //    constant time. The token field must be a 32-byte base64url tag.
        let bh = body_hash(body);
        let message = build_message(
            &cred.client_id,
            cred.step,
            &cred.nonce_b64,
            method,
            path,
            &bh,
        );
        let tag_bytes = URL_SAFE_NO_PAD
            .decode(&cred.token_b64)
            .map_err(|_| VerifyError::BadToken)?;
        if tag_bytes.len() != TAG_BYTES {
            return Err(VerifyError::BadToken);
        }
        let tag = auth::Tag::from_slice(&tag_bytes).map_err(|_| VerifyError::BadToken)?;
        let key = self.secrets.key_for_step(cred.step);
        auth::authenticate_verify(&tag, key, message.as_bytes())
            .map_err(|_| VerifyError::BadToken)?;

        // 3. Anti-replay: reserve the (client_id, step, nonce) triple exactly
        //    once. Only valid tokens reach this point, so a flood of garbage
        //    cannot grow the nonce table.
        let nonce_key = format!("{}\n{}\n{}", cred.client_id, cred.step, cred.nonce_b64);
        match self.seen_nonces.entry(nonce_key) {
            Entry::Occupied(_) => Err(VerifyError::Replay),
            Entry::Vacant(slot) => {
                slot.insert(Self::nonce_expiry(cred.step, now_unix));
                Ok(())
            }
        }
    }

    /// Drop nonce entries whose acceptance window has fully elapsed.
    pub fn sweep(&self, now_unix: i64) {
        self.seen_nonces.retain(|_, &mut expiry| expiry > now_unix);
    }

    /// Number of currently-reserved nonces (test/observability aid).
    #[must_use]
    #[allow(dead_code)]
    pub fn reserved_nonce_count(&self) -> usize {
        self.seen_nonces.len()
    }
}

/// Recommended interval between [`RorschachValidator::sweep`] passes.
pub const NONCE_SWEEP_INTERVAL: Duration = Duration::from_secs(120);

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secrets() -> RorschachSecrets {
        // 64 distinct bytes for each parity.
        let even: Vec<u8> = (0u8..64).collect();
        let odd: Vec<u8> = (64u8..128).collect();
        RorschachSecrets::from_base64(
            &URL_SAFE_NO_PAD.encode(&even),
            &URL_SAFE_NO_PAD.encode(&odd),
        )
        .expect("valid 64-byte secrets")
    }

    fn now() -> i64 {
        // A fixed, mid-window timestamp keeps the tests deterministic.
        1_700_000_000
    }

    #[test]
    fn round_trip_verifies() {
        let secrets = test_secrets();
        let step = u64::try_from(now() / STEP_SECONDS).expect("test");
        let nonce = URL_SAFE_NO_PAD.encode([7u8; 64]);
        let token = sign_token(
            &secrets,
            "kraken-ui",
            step,
            &nonce,
            "POST",
            "/rule/control/cmc/update",
            b"{}",
        )
        .expect("sign");
        let cred = RorschachCredential::parse(&token).expect("parse");
        let validator = RorschachValidator::new(secrets);
        validator
            .verify(&cred, "POST", "/rule/control/cmc/update", b"{}", now())
            .expect("verify");
    }

    #[test]
    fn replayed_nonce_is_rejected() {
        let secrets = test_secrets();
        let step = u64::try_from(now() / STEP_SECONDS).expect("test");
        let nonce = URL_SAFE_NO_PAD.encode([9u8; 64]);
        let token = sign_token(
            &secrets,
            "c1",
            step,
            &nonce,
            "GET",
            "/rule/control/cmc/list",
            b"",
        )
        .expect("sign");
        let cred = RorschachCredential::parse(&token).expect("parse");
        let validator = RorschachValidator::new(secrets);
        validator
            .verify(&cred, "GET", "/rule/control/cmc/list", b"", now())
            .expect("first use ok");
        assert_eq!(
            validator.verify(&cred, "GET", "/rule/control/cmc/list", b"", now()),
            Err(VerifyError::Replay)
        );
    }

    #[test]
    fn altered_path_is_rejected() {
        let secrets = test_secrets();
        let step = u64::try_from(now() / STEP_SECONDS).expect("test");
        let nonce = URL_SAFE_NO_PAD.encode([1u8; 64]);
        let token = sign_token(
            &secrets,
            "c1",
            step,
            &nonce,
            "GET",
            "/rule/control/cmc/list",
            b"",
        )
        .expect("sign");
        let cred = RorschachCredential::parse(&token).expect("parse");
        let validator = RorschachValidator::new(secrets);
        assert_eq!(
            validator.verify(&cred, "GET", "/rule/control/cmc/other", b"", now()),
            Err(VerifyError::BadToken)
        );
    }

    #[test]
    fn altered_body_is_rejected() {
        let secrets = test_secrets();
        let step = u64::try_from(now() / STEP_SECONDS).expect("test");
        let nonce = URL_SAFE_NO_PAD.encode([2u8; 64]);
        let token = sign_token(
            &secrets,
            "c1",
            step,
            &nonce,
            "POST",
            "/rule/control/cmc/update",
            b"{\"a\":1}",
        )
        .expect("sign");
        let cred = RorschachCredential::parse(&token).expect("parse");
        let validator = RorschachValidator::new(secrets);
        assert_eq!(
            validator.verify(
                &cred,
                "POST",
                "/rule/control/cmc/update",
                b"{\"a\":2}",
                now()
            ),
            Err(VerifyError::BadToken)
        );
    }

    #[test]
    fn altered_method_is_rejected() {
        let secrets = test_secrets();
        let step = u64::try_from(now() / STEP_SECONDS).expect("test");
        let nonce = URL_SAFE_NO_PAD.encode([3u8; 64]);
        let token = sign_token(
            &secrets,
            "c1",
            step,
            &nonce,
            "GET",
            "/rule/control/cmc/list",
            b"",
        )
        .expect("sign");
        let cred = RorschachCredential::parse(&token).expect("parse");
        let validator = RorschachValidator::new(secrets);
        assert_eq!(
            validator.verify(&cred, "POST", "/rule/control/cmc/list", b"", now()),
            Err(VerifyError::BadToken)
        );
    }

    #[test]
    fn future_step_is_rejected() {
        let secrets = test_secrets();
        let step = u64::try_from(now() / STEP_SECONDS).expect("test") + 10;
        let nonce = URL_SAFE_NO_PAD.encode([4u8; 64]);
        let token = sign_token(
            &secrets,
            "c1",
            step,
            &nonce,
            "GET",
            "/rule/control/cmc/list",
            b"",
        )
        .expect("sign");
        let cred = RorschachCredential::parse(&token).expect("parse");
        let validator = RorschachValidator::new(secrets);
        assert_eq!(
            validator.verify(&cred, "GET", "/rule/control/cmc/list", b"", now()),
            Err(VerifyError::StepWindow)
        );
    }

    #[test]
    fn skew_within_one_minute_is_accepted() {
        let secrets = test_secrets();
        // Pick a timestamp 30 s into a window so now-60 lands in the previous
        // step; a client one step "behind" (clock 60 s slow) must still verify.
        let base = (now() / STEP_SECONDS) * STEP_SECONDS + 30;
        let prev_step = u64::try_from(base / STEP_SECONDS).expect("test") - 1;
        let nonce = URL_SAFE_NO_PAD.encode([5u8; 64]);
        let token = sign_token(
            &secrets,
            "c1",
            prev_step,
            &nonce,
            "GET",
            "/rule/control/cmc/list",
            b"",
        )
        .expect("sign");
        let cred = RorschachCredential::parse(&token).expect("parse");
        let validator = RorschachValidator::new(secrets);
        validator
            .verify(&cred, "GET", "/rule/control/cmc/list", b"", base)
            .expect("±60s skew accepted");
    }

    #[test]
    fn parse_rejects_malformed_credentials() {
        assert!(RorschachCredential::parse("rch2.c.1.n.t").is_none()); // bad prefix
        assert!(RorschachCredential::parse("rch1.c.x.n.t").is_none()); // step not a number
        assert!(RorschachCredential::parse("rch1.c.1.n").is_none()); // too few fields
        assert!(RorschachCredential::parse("rch1.c.1.n.t.extra").is_none()); // too many
        assert!(RorschachCredential::parse("rch1.cli.ent.1.n.t").is_none()); // dot in client_id
        assert!(RorschachCredential::parse("rch1.c.1..t").is_none()); // empty nonce
    }

    #[test]
    fn secret_shorter_than_64_bytes_is_rejected() {
        let short = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let ok = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let err = RorschachSecrets::from_base64(&short, &ok).expect_err("must reject short even");
        assert!(err.contains(SECRET_EVEN_NAME));
        let err = RorschachSecrets::from_base64(&ok, &short).expect_err("must reject short odd");
        assert!(err.contains(SECRET_ODD_NAME));
    }

    #[test]
    fn non_base64_secret_is_rejected() {
        let ok = URL_SAFE_NO_PAD.encode([0u8; 64]);
        assert!(RorschachSecrets::from_base64("not base64!!", &ok).is_err());
    }
}
