use super::CmcManager;
use crate::waf::normalize_str;

/// Location in the request where an HTTP Parameter Pollution duplicate was
/// found. Reported in the finding so an operator can tell a polluted query
/// string apart from a polluted body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HppLocation {
    /// The URL query string (e.g. `GET /x?a=1&a=2`).
    Query,
    /// The request body (e.g. an `application/x-www-form-urlencoded` POST).
    Body,
}

impl HppLocation {
    /// Lowercase label used in finding messages and rule-match descriptors.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HppLocation::Query => "query",
            HppLocation::Body => "body",
        }
    }
}

/// A single HTTP Parameter Pollution detection: the duplicated parameter name
/// (in the casing first seen) and where it occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HppMatch {
    parameter: String,
    location: HppLocation,
}

impl HppMatch {
    /// The duplicated parameter name, in the casing of its first occurrence.
    #[must_use]
    pub fn parameter(&self) -> &str {
        &self.parameter
    }

    /// Where the duplicate was found (query string or body).
    #[must_use]
    pub fn location(&self) -> HppLocation {
        self.location
    }
}

/// Detector for HTTP Parameter Pollution (HPP).
///
/// HPP is the same parameter name appearing two or more times within a single
/// location (query string or body). Attackers use it to confuse downstream
/// parsers that disagree on which occurrence wins, smuggling a value past
/// validation or a WAF (e.g. `email=safe@x&eMail=<payload>`).
///
/// The detector is a zero-config newtype so it mirrors the other CMC modules'
/// builder pattern; all logic lives in the free pure helpers
/// ([`normalized_eq_count`], [`parse_keys`], [`find_duplicate`]) and in
/// [`HppDetector::detect`].
#[derive(Debug, Clone, Default)]
pub struct HppDetector;

#[derive(Debug, Default)]
pub struct HppDetectorBuilder;

impl HppDetectorBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // `self`-by-value mirrors the other CMC builders even though HPP is
    // zero-config and carries no state to move into the detector.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn build(self) -> HppDetector {
        HppDetector
    }
}

impl HppDetector {
    /// Inspect one raw location value (the raw query string or raw body) for a
    /// duplicated parameter name.
    ///
    /// The raw input is normalized first via the project's global
    /// [`normalize`] so percent-, double-percent-, and UTF-16-encoded
    /// separators are neutralised before any `=`/`&` parsing. Counting and
    /// parsing therefore always run on the normalized string, never the raw
    /// one.
    ///
    /// Returns `Some(HppMatch)` naming the first duplicated parameter (compared
    /// case-insensitively) when one exists, otherwise `None`.
    ///
    /// Takes `&self` to match the call shape of the other CMC detectors; the
    /// detector itself is stateless.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn detect(&self, raw: &str, location: HppLocation) -> Option<HppMatch> {
        let normalized = normalize_str(raw);
        // Fewer than two '=' cannot encode two parameters with values.
        if count_equals(&normalized) < 2 {
            return None;
        }
        let keys = parse_keys(&normalized);
        let parameter = find_duplicate(&keys)?;
        Some(HppMatch {
            parameter,
            location,
        })
    }
}

/// Count the `=` characters in `s`.
///
/// Pure helper kept separate so tests can assert the gating rule directly.
#[must_use]
pub fn count_equals(s: &str) -> usize {
    s.bytes().filter(|&b| b == b'=').count()
}

/// Normalize `raw` with the global normalizer, then count `=` in the result.
///
/// This is the exact value the detector gates on (`>= 2` arms the parser).
/// Exposed as a pure function so callers and tests can verify the
/// "normalize-then-count-'='" rule in one call without reaching into the
/// detector. Not invoked on the hot path (the detector keeps the normalized
/// string it already produced), so it is `dead_code` for non-test builds.
#[must_use]
#[allow(dead_code)]
pub fn normalized_eq_count(raw: &str) -> usize {
    count_equals(&normalize_str(raw))
}

/// Parse parameter names (keys) from an already-normalized location string.
///
/// The string is split on `&` into segments; for each segment the substring
/// **before the first `=`** is the key. Splitting on the first `=` only means
/// values may themselves contain `=` (e.g. base64 padding `==`) without
/// corrupting the key. Empty segments (e.g. from a leading/trailing/`&&`) are
/// skipped; a segment with no `=` contributes its whole text as a key.
///
/// Keys are returned in source order, preserving original casing.
#[must_use]
pub fn parse_keys(normalized: &str) -> Vec<String> {
    normalized
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| match segment.split_once('=') {
            Some((key, _value)) => key.to_string(),
            None => segment.to_string(),
        })
        .collect()
}

/// Return the first key that appears two or more times, compared
/// case-insensitively (ASCII), or `None` when all keys are unique.
///
/// The returned name keeps the casing of its first occurrence so the finding
/// message shows what the client actually sent.
#[must_use]
pub fn find_duplicate(keys: &[String]) -> Option<String> {
    for (i, key) in keys.iter().enumerate() {
        if keys[..i].iter().any(|seen| seen.eq_ignore_ascii_case(key)) {
            return Some(key.clone());
        }
    }
    None
}

impl CmcManager {
    /// Inspect a request's query string and body for HTTP Parameter Pollution.
    ///
    /// Each location is normalized and checked independently (per-location key
    /// sets), exactly as required by the spec, so a duplicate in the query is
    /// reported separately from one in the body. The query is checked first.
    ///
    /// Returns `Some(Finding)` (severity `Critical`) on the first detection so
    /// that the existing untrust scoring pushes the request to the `>= 60`
    /// block threshold. Returns `None` when the module is disabled or no
    /// duplicate is found.
    #[must_use]
    pub fn inspect_hpp(&self, query: &str, body: &str) -> Option<super::Finding> {
        let detector = self.hpp_detect.as_ref()?;
        let matched = detector
            .detect(query, HppLocation::Query)
            .or_else(|| detector.detect(body, HppLocation::Body))?;
        Some(super::finding(
            "CMC HTTP Parameter Pollution detection",
            super::Severity::Critical,
            "CWE-235",
            &format!(
                "Detected HTTP Parameter Pollution: parameter '{param}' appears two or more \
                 times (case-insensitively) in the request {loc}. Duplicate parameters let \
                 attackers exploit parser disagreements to smuggle a value past validation.",
                param = matched.parameter(),
                loc = matched.location().as_str(),
            ),
            "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
            format!(
                "cmc::hpp_detect:location={} parameter={}",
                matched.location().as_str(),
                matched.parameter()
            ),
            "cmc/hpp_detect.rs:generated",
            if matched.location() == HppLocation::Query {
                query
            } else {
                body
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        count_equals, find_duplicate, normalized_eq_count, parse_keys, HppDetector, HppLocation,
    };

    fn detector() -> HppDetector {
        super::HppDetectorBuilder::new().build()
    }

    #[test]
    fn clean_query_has_no_duplicate() {
        // The non-vulnerable example from the spec: three distinct keys.
        let raw = "name=Antonio&email=antonio@example.com&age=39";
        assert!(detector().detect(raw, HppLocation::Query).is_none());
    }

    #[test]
    fn case_insensitive_duplicate_is_detected() {
        // The vulnerable example: `email` repeated as `eMail`.
        let raw = "name=Antonio&email=antonio@example.com&age=39&eMail=<bingo>";
        let m = detector()
            .detect(raw, HppLocation::Query)
            .expect("duplicate email must be detected");
        assert!(m.parameter().eq_ignore_ascii_case("email"));
        assert_eq!(m.location(), HppLocation::Query);
    }

    #[test]
    fn same_case_duplicate_is_detected() {
        assert!(detector().detect("a=1&a=2", HppLocation::Query).is_some());
    }

    #[test]
    fn value_containing_equals_is_not_a_false_duplicate() {
        // base64 padding `==` lives in the value; only one key (`token`) exists.
        assert!(detector()
            .detect("data=YWJj==", HppLocation::Body)
            .is_none());
        // …but a real duplicate is still caught even when a value carries `=`.
        let m = detector()
            .detect("token=YWJj==&token=x", HppLocation::Body)
            .expect("real token duplicate must be detected");
        assert_eq!(m.parameter(), "token");
    }

    #[test]
    fn fewer_than_two_equals_is_skipped() {
        // Gate: a single `=` can never describe two valued parameters.
        assert_eq!(normalized_eq_count("a=1"), 1);
        assert!(detector().detect("a=1", HppLocation::Query).is_none());
        assert!(detector().detect("a", HppLocation::Query).is_none());
    }

    #[test]
    fn body_location_is_reported() {
        let m = detector()
            .detect("p=1&P=2", HppLocation::Body)
            .expect("duplicate in body");
        assert_eq!(m.location(), HppLocation::Body);
    }

    #[test]
    fn percent_encoded_separators_are_normalized_then_detected() {
        // `email=a&eMail=b` with `=`→%3D and `&`→%26.
        let raw = "email%3Da%26eMail%3Db";
        assert_eq!(normalized_eq_count(raw), 2);
        assert!(detector().detect(raw, HppLocation::Query).is_some());
    }

    #[test]
    fn double_encoded_separators_are_normalized_then_detected() {
        // `=`→%253D and `&`→%2526 (double percent-encoding).
        let raw = "email%253Da%2526eMail%253Db";
        assert!(detector().detect(raw, HppLocation::Query).is_some());
    }

    #[test]
    fn count_equals_counts_only_equals() {
        assert_eq!(count_equals("a=1&b=2&c=3"), 3);
        assert_eq!(count_equals("nothing-here"), 0);
    }

    #[test]
    fn parse_keys_splits_on_first_equals_only() {
        let keys = parse_keys("a=1=2&b=3");
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn parse_keys_skips_empty_segments() {
        // Leading/trailing/`&&` produce empty segments that must be ignored.
        let keys = parse_keys("&a=1&&b=2&");
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn find_duplicate_keeps_first_casing() {
        let keys = vec!["Email".to_string(), "email".to_string()];
        assert_eq!(find_duplicate(&keys).as_deref(), Some("email"));
    }
}
