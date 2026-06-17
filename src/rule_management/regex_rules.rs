//! Regex rule-management endpoints — inspect and **replace** the regex (and the
//! closely-related keyword / scanner) rule files in real time, then hot-reload
//! the live detection engine without restarting the WAF.
//!
//! These complement the CMC toggle endpoints in [`super::cmc`]. Where CMC flips
//! whole detection modules on and off, these endpoints edit the *content* of
//! the rule files that drive the regex / keyword / scanner matchers, replacing
//! every rule in a context in one atomic write + reload.
//!
//! # Endpoints
//!
//! * `POST /rule/control/regex/view` — body `{ "rule_view": "<name>" }`. Streams
//!   the named rule file back line-by-line in the JSON response `content` field.
//! * `POST /rule/control/regex/update/<name>` — body carries the full new rule
//!   set. The old rules are discarded, the new ones validated and written, and
//!   [`crate::waf::WafEngine::reload_from_dir`] re-reads every rule file and
//!   atomically swaps the live snapshot — so the new rules filter traffic
//!   immediately.
//!
//! `<name>` is resolved through [`super::factory`], a closed allowlist of five
//! files. Any name outside it is rejected; there is no way to read or write an
//! arbitrary path. All access control (IP allowlist + Rorschach token) is
//! enforced by [`super::handle_rule_management`] before either handler runs.

// This module deliberately uses `match` for every Option/Result branch rather
// than `let ... else`, `if let`, or the `.ok()` / `ok_or` combinators — a coding
// requirement of this control-plane feature that keeps each fallible step and
// its failure response visible side by side. Silence the clippy style lints that
// would otherwise push the code back toward those forms.
#![allow(
    clippy::manual_let_else,
    clippy::manual_ok_err,
    clippy::single_match,
    clippy::single_match_else
)]

use std::{io::BufRead, path::Path, sync::Arc};

use http::StatusCode;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use super::factory::{RuleFileFactory, RuleFileKind};
use crate::{
    app::AppState,
    proxy::WafResponse,
    rules::{HttpAction, Severity},
};

/// Route prefix for the update endpoint. The trailing segment after this prefix
/// is the rule name resolved through the factory.
pub(super) const UPDATE_PREFIX: &str = "/rule/control/regex/update/";

/// Same compiled-size guards the loader applies, so a pattern accepted here
/// cannot be rejected later by the loader for exceeding a size budget.
const REGEX_SIZE_LIMIT: usize = 10_000_000;
const REGEX_DFA_SIZE_LIMIT: usize = 2_000_000;

fn default_enable() -> u8 {
    1
}

fn default_score() -> u32 {
    1000
}

// ── JSON contracts ────────────────────────────────────────────────────────────

/// `POST /rule/control/regex/view` request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewRequest {
    /// Name of the rule context to read; must be in the factory allowlist.
    rule_view: String,
}

/// `POST /rule/control/regex/view` success response.
#[derive(Debug, Serialize)]
struct ViewResponse<'a> {
    status: &'static str,
    context: &'static str,
    rule: &'a str,
    /// The full file content, read line-by-line into a single buffer.
    content: String,
}

/// `POST /rule/control/regex/update/<name>` success response.
#[derive(Debug, Serialize)]
struct UpdateResponse<'a> {
    status: &'static str,
    context: &'static str,
    rule: &'a str,
    rules_written: usize,
}

/// Generic error envelope. Returned for both client and server faults with a
/// short, non-sensitive message (the control plane is authenticated, so naming
/// the failure class is helpful and leaks no internal detail).
#[derive(Debug, Serialize)]
struct ErrorBody {
    status: &'static str,
    error: &'static str,
    message: &'static str,
}

fn error_response(
    state: &Arc<AppState>,
    status: StatusCode,
    error: &'static str,
    message: &'static str,
) -> WafResponse {
    super::json_response(
        state,
        status,
        &ErrorBody {
            status: "error",
            error,
            message,
        },
    )
}

// ── Rule documents (for the two JSON file kinds) ──────────────────────────────

/// One rule, mirroring the loader's on-disk schema so a document written here
/// round-trips through [`crate::rules::RuleSet::from_dir`] unchanged. Field
/// order matches the shipped files for clean diffs; `deny_unknown_fields`
/// rejects any out-of-shape entry.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuleEntry {
    #[serde(default = "default_enable")]
    enable: u8,
    #[serde(default)]
    http_action: HttpAction,
    title: String,
    severity: Severity,
    cwe: String,
    description: String,
    url: String,
    rule_match: String,
    #[serde(default)]
    id: String,
    #[serde(default = "default_score")]
    score: u32,
}

/// `{ "rules": [ ... ] }` envelope shared by the regex and keyword files.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RulesDoc {
    rules: Vec<RuleEntry>,
}

/// `{ "lines": [ ... ] }` envelope for the plain-text scanner list.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinesDoc {
    lines: Vec<String>,
}

/// Validated, ready-to-write file content plus the number of rules it carries.
struct NewContent {
    text: String,
    rule_count: usize,
}

// ── View ──────────────────────────────────────────────────────────────────────

/// Handle `POST /rule/control/regex/view`.
pub(super) fn handle_view(state: &Arc<AppState>, body: &[u8]) -> WafResponse {
    let request: ViewRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(_) => return super::bad_request_json(state),
    };

    let rule_file = match RuleFileFactory::resolve(&request.rule_view) {
        Some(rule_file) => rule_file,
        None => {
            warn!(
                target: "krakenwaf",
                rule = %request.rule_view,
                "rule-management: regex view rejected — name not in the managed allowlist"
            );
            return error_response(
                state,
                StatusCode::BAD_REQUEST,
                "unknown_rule",
                "rule name is not in the managed allowlist",
            );
        }
    };

    let path = rule_file.absolute_path(&state.rules_dir);
    match read_file_buffered(&path) {
        Ok(content) => {
            info!(
                target: "krakenwaf",
                rule = rule_file.name,
                bytes = content.len(),
                "rule-management: regex view served"
            );
            super::json_response(
                state,
                StatusCode::OK,
                &ViewResponse {
                    status: "ok",
                    context: "regex_view",
                    rule: rule_file.name,
                    content,
                },
            )
        }
        Err(err) => {
            error!(
                target: "krakenwaf",
                rule = rule_file.name,
                error = %err,
                "rule-management: failed to read rule file for view"
            );
            error_response(
                state,
                StatusCode::INTERNAL_SERVER_ERROR,
                "read_failed",
                "failed to read the rule file",
            )
        }
    }
}

/// Open `path` and concatenate its lines into a single string buffer.
fn read_file_buffered(path: &Path) -> std::io::Result<String> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut buffer = String::new();
    for line in reader.lines() {
        match line {
            Ok(text) => {
                buffer.push_str(&text);
                buffer.push('\n');
            }
            Err(err) => return Err(err),
        }
    }
    Ok(buffer)
}

// ── Update ──────────────────────────────────────────────────────────────────

/// Handle `POST /rule/control/regex/update/<name>`.
pub(super) async fn handle_update(
    state: &Arc<AppState>,
    request_path: &str,
    body: &[u8],
) -> WafResponse {
    let name = match request_path.strip_prefix(UPDATE_PREFIX) {
        Some(name) => name,
        // The router only dispatches here for paths carrying the prefix; treat a
        // missing prefix defensively as "no such route".
        None => return super::not_found(state),
    };

    let rule_file = match RuleFileFactory::resolve(name) {
        Some(rule_file) => rule_file,
        None => {
            warn!(
                target: "krakenwaf",
                rule = %name,
                "rule-management: regex update rejected — name not in the managed allowlist"
            );
            return error_response(
                state,
                StatusCode::BAD_REQUEST,
                "unknown_rule",
                "rule name is not in the managed allowlist",
            );
        }
    };

    // Validate the incoming rules for this file's format and serialize the bytes
    // to write. A bad document, an empty rule set, or an invalid regex is a 400
    // and never touches the file.
    let new_content = match build_new_content(rule_file.kind, body) {
        Ok(new_content) => new_content,
        Err(message) => {
            warn!(
                target: "krakenwaf",
                rule = rule_file.name,
                reason = message,
                "rule-management: regex update rejected — invalid rule document"
            );
            return error_response(state, StatusCode::BAD_REQUEST, "invalid_rules", message);
        }
    };
    let rules_written = new_content.rule_count;
    let target = rule_file.absolute_path(&state.rules_dir);

    // Keep the previous bytes so a failed hot-reload can be rolled back, leaving
    // the live engine consistent with what is on disk.
    let previous = match std::fs::read(&target) {
        Ok(bytes) => Some(bytes),
        Err(_) => None,
    };

    match write_atomic(&target, new_content.text.as_bytes()) {
        Ok(()) => {}
        Err(err) => {
            error!(
                target: "krakenwaf",
                rule = rule_file.name,
                error = %err,
                "rule-management: failed to persist new rule file"
            );
            return error_response(
                state,
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                "failed to persist the new rule file",
            );
        }
    }

    // Tear down every regex/keyword rule and bring them back up from the updated
    // files — a single atomic snapshot swap inside the engine.
    match state.waf.reload_from_dir(&state.rules_dir).await {
        Ok(()) => {
            info!(
                target: "krakenwaf",
                rule = rule_file.name,
                rules_written,
                "rule-management: regex rules replaced and engine hot-reloaded"
            );
            super::json_response(
                state,
                StatusCode::OK,
                &UpdateResponse {
                    status: "ok",
                    context: "regex_update",
                    rule: rule_file.name,
                    rules_written,
                },
            )
        }
        Err(err) => {
            warn!(
                target: "krakenwaf",
                rule = rule_file.name,
                error = %err,
                "rule-management: hot-reload failed after write; rolling back"
            );
            match previous {
                Some(bytes) => {
                    let _ = write_atomic(&target, &bytes);
                    let _ = state.waf.reload_from_dir(&state.rules_dir).await;
                }
                None => {}
            }
            error_response(
                state,
                StatusCode::INTERNAL_SERVER_ERROR,
                "reload_failed",
                "the new rules could not be loaded into the engine",
            )
        }
    }
}

/// Validate `body` against `kind` and return the bytes to write.
fn build_new_content(kind: RuleFileKind, body: &[u8]) -> Result<NewContent, &'static str> {
    match kind {
        RuleFileKind::RegexJson => build_json_rules(body, true),
        RuleFileKind::KeywordJson => build_json_rules(body, false),
        RuleFileKind::LineList => build_line_list(body),
    }
}

/// Validate a `{ "rules": [ ... ] }` document and re-serialize it canonically.
/// When `compile_regex` is set, every enabled rule's `rule_match` must compile.
fn build_json_rules(body: &[u8], compile_regex: bool) -> Result<NewContent, &'static str> {
    let doc: RulesDoc = match serde_json::from_slice(body) {
        Ok(doc) => doc,
        Err(_) => return Err("request body is not a valid rule document"),
    };
    if doc.rules.is_empty() {
        return Err("rule set must not be empty");
    }
    for rule in &doc.rules {
        if rule.rule_match.trim().is_empty() {
            return Err("a rule has an empty rule_match");
        }
        if compile_regex && rule.enable != 0 {
            match RegexBuilder::new(&rule.rule_match)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                .build()
            {
                Ok(_) => {}
                Err(_) => return Err("a rule contains an invalid regular expression"),
            }
        }
    }
    let rule_count = doc.rules.len();
    match serde_json::to_string_pretty(&doc) {
        Ok(mut text) => {
            text.push('\n');
            Ok(NewContent { text, rule_count })
        }
        Err(_) => Err("failed to serialize the rule document"),
    }
}

/// Validate a `{ "lines": [ ... ] }` document and join it into a newline-
/// delimited text file (the scanner User-Agent list format).
fn build_line_list(body: &[u8]) -> Result<NewContent, &'static str> {
    let doc: LinesDoc = match serde_json::from_slice(body) {
        Ok(doc) => doc,
        Err(_) => return Err("request body is not a valid line list"),
    };
    if doc.lines.is_empty() {
        return Err("rule set must not be empty");
    }
    let mut text = String::new();
    let mut rule_count = 0usize;
    for line in &doc.lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err("a line entry is empty");
        }
        if trimmed.contains('\n') || trimmed.contains('\r') {
            return Err("a line entry contains an embedded newline");
        }
        text.push_str(trimmed);
        text.push('\n');
        rule_count += 1;
    }
    Ok(NewContent { text, rule_count })
}

/// Write `bytes` to `target` atomically: stage in a sibling temp file, then
/// rename over the target so a concurrent reader (the hot-reload) never sees a
/// half-written file.
fn write_atomic(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = match target.parent() {
        Some(parent) => parent,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rule file path has no parent directory",
            ))
        }
    };
    let file_name = match target.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rule file path has no file name",
            ))
        }
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let tmp_path = parent.join(format!(".{file_name}.{stamp}.tmp"));
    std::fs::write(&tmp_path, bytes)?;
    match std::fs::rename(&tmp_path, target) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const VALID_REGEX_DOC: &str = r#"{
        "rules": [
            {
                "enable": 1,
                "http_action": "Request",
                "title": "test rule",
                "severity": "critical",
                "cwe": "CWE-78",
                "description": "valid",
                "url": "https://example.com",
                "rule_match": "(?i)attack[0-9]+",
                "id": "00001",
                "score": 1000
            }
        ]
    }"#;

    #[test]
    fn view_request_rejects_unknown_field() {
        let body = br#"{"rule_view":"body_regex","extra":1}"#;
        let parsed: Result<ViewRequest, _> = serde_json::from_slice(body);
        assert!(parsed.is_err(), "deny_unknown_fields must reject extras");
    }

    #[test]
    fn regex_doc_round_trips_and_counts_rules() {
        match build_json_rules(VALID_REGEX_DOC.as_bytes(), true) {
            Ok(content) => {
                assert_eq!(content.rule_count, 1);
                assert!(content.text.contains("\"rule_match\""));
                assert!(content.text.ends_with('\n'));
            }
            Err(message) => panic!("valid regex doc must build: {message}"),
        }
    }

    #[test]
    fn empty_rule_set_is_rejected() {
        match build_json_rules(br#"{"rules":[]}"#, true) {
            Ok(_) => panic!("empty rule set must be rejected"),
            Err(message) => assert_eq!(message, "rule set must not be empty"),
        }
    }

    #[test]
    fn invalid_regex_is_rejected() {
        let body = r#"{
            "rules": [
                {
                    "enable": 1,
                    "title": "broken",
                    "severity": "high",
                    "cwe": "CWE-78",
                    "description": "unclosed group",
                    "url": "https://example.com",
                    "rule_match": "(unclosed"
                }
            ]
        }"#;
        match build_json_rules(body.as_bytes(), true) {
            Ok(_) => panic!("invalid regex must be rejected"),
            Err(message) => assert_eq!(message, "a rule contains an invalid regular expression"),
        }
    }

    #[test]
    fn keyword_doc_skips_regex_compilation() {
        // A literal `(unclosed` would fail regex compilation but is a fine
        // keyword, so the keyword path must accept it.
        let body = r#"{
            "rules": [
                {
                    "enable": 1,
                    "title": "kw",
                    "severity": "high",
                    "cwe": "CWE-89",
                    "description": "literal",
                    "url": "https://example.com",
                    "rule_match": "(unclosed"
                }
            ]
        }"#;
        match build_json_rules(body.as_bytes(), false) {
            Ok(content) => assert_eq!(content.rule_count, 1),
            Err(message) => panic!("keyword doc must build: {message}"),
        }
    }

    #[test]
    fn line_list_builds_and_validates() {
        match build_line_list(br#"{"lines":["arachni","sqlmap"," nikto "]}"#) {
            Ok(content) => {
                assert_eq!(content.rule_count, 3);
                assert_eq!(content.text, "arachni\nsqlmap\nnikto\n");
            }
            Err(message) => panic!("valid line list must build: {message}"),
        }
    }

    #[test]
    fn line_list_rejects_empty_and_newlines() {
        match build_line_list(br#"{"lines":[]}"#) {
            Ok(_) => panic!("empty line list must be rejected"),
            Err(message) => assert_eq!(message, "rule set must not be empty"),
        }
        match build_line_list("{\"lines\":[\"good\",\"bad\\ninjected\"]}".as_bytes()) {
            Ok(_) => panic!("embedded newline must be rejected"),
            Err(message) => assert_eq!(message, "a line entry contains an embedded newline"),
        }
    }

    #[test]
    fn read_file_buffered_concatenates_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rule.txt");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(b"first\nsecond\nthird\n").expect("write");
        match read_file_buffered(&path) {
            Ok(content) => assert_eq!(content, "first\nsecond\nthird\n"),
            Err(err) => panic!("read must succeed: {err}"),
        }
    }

    #[test]
    fn write_atomic_replaces_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("regex/body_regex.json");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"old").expect("seed");
        match write_atomic(&path, b"new content") {
            Ok(()) => {
                let read_back = std::fs::read_to_string(&path).expect("read back");
                assert_eq!(read_back, "new content");
                // No leftover temp files in the directory.
                let leftovers = std::fs::read_dir(path.parent().expect("parent"))
                    .expect("read dir")
                    .filter_map(Result::ok)
                    .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
                    .count();
                assert_eq!(leftovers, 0, "temp file must be renamed away");
            }
            Err(err) => panic!("atomic write must succeed: {err}"),
        }
    }
}
