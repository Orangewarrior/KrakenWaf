
use super::{CompiledDetectionRule, DetectionRule, HttpAction, RuleSet, Severity};
use anyhow::{Context, Result};
use regex::RegexBuilder;
use serde::Deserialize;
use serde_json::Value;
use std::{collections::HashMap, fs, path::Path};
use tracing::warn;

#[derive(Debug, Deserialize)]
struct MainRulesJson {
    #[serde(default)]
    blocked_ip_prefixes: Vec<String>,
    #[serde(default)]
    uri_keywords: Vec<RuleJson>,
    #[serde(default)]
    header_keywords: Vec<RuleJson>,
    #[serde(default)]
    body_keywords: Vec<RuleJson>,
    #[serde(default)]
    allow_paths: Vec<String>,
    #[serde(default)]
    body_limits: HashMap<String, usize>,
}

#[derive(Debug, Deserialize)]
struct RegexBundle {
    #[serde(default)]
    rules: Vec<RuleJson>,
}

#[derive(Debug, Deserialize)]
struct RuleJson {
    #[serde(default)]
    id: String,
    #[serde(default = "default_rule_enabled")]
    enable: u8,
    #[serde(default)]
    http_action: HttpAction,
    title: String,
    severity: Severity,
    cwe: String,
    description: String,
    url: String,
    rule_match: String,
}


fn default_rule_enabled() -> u8 {
    1
}

pub fn load_rules_from_dir(root: &Path) -> Result<RuleSet> {
    let main = load_main_rules_json(&root.join("rules.json"))?;

    Ok(RuleSet {
        blocked_ips: load_addr_file(root, "addr/blocklist.txt")?,
        allowed_ips: load_addr_file(root, "addr/allowlist.txt")?,
        scanner_agents: load_scanner_agents(root, "user_agents/scanners.txt")?,
        blocked_ip_prefixes: main.blocked_ip_prefixes,
        uri_keywords: json_rules_to_detection_rules(main.uri_keywords, "rules.json:uri_keywords"),
        header_keywords: json_rules_to_detection_rules(main.header_keywords, "rules.json:header_keywords"),
        body_keywords: json_rules_to_detection_rules(main.body_keywords, "rules.json:body_keywords"),
        allow_paths: main.allow_paths,
        body_limits: main.body_limits,
        path_regex: load_regex_rules_json(&root.join("regex/path_regex.json"), "regex/path_regex.json")?,
        body_regex: load_regex_rules_json(&root.join("regex/body_regex.json"), "regex/body_regex.json")?,
        header_regex: load_regex_rules_json(&root.join("regex/header_regex.json"), "regex/header_regex.json")?,
        vectorscan_keywords: load_vectorscan_rules_json(&root.join("Vectorscan/strings2block.json"), "Vectorscan/strings2block.json")?,
    })
}

/// Load an address file (one IPv4/IPv6/CIDR per line) with canonicalization and
/// anti path-traversal checks so operators cannot point --rules-dir at a crafted tree.
fn load_addr_file(root: &Path, relative: &str) -> Result<Vec<String>> {
    let path = safe_join(root, relative)?;
    load_simple_lines(&path)
}

/// Load scanner user-agent patterns (one substring per line).
fn load_scanner_agents(root: &Path, relative: &str) -> Result<Vec<String>> {
    let path = safe_join(root, relative)?;
    load_simple_lines(&path)
}

/// Resolve `root/relative` and verify the result stays inside `root`.
/// Prevents path traversal attacks such as `../../etc/passwd` via rule file names.
fn safe_join(root: &Path, relative: &str) -> Result<std::path::PathBuf> {
    // Reject obvious traversal attempts before canonicalizing, to give a clear error.
    if relative.contains("..") {
        anyhow::bail!("path traversal rejected in rule path: {}", relative);
    }
    let joined = root.join(relative);
    // If the file doesn't exist we still return the path; callers use `exists()`.
    if joined.exists() {
        let canonical = joined.canonicalize()
            .with_context(|| format!("cannot canonicalize rule path {}", joined.display()))?;
        let root_canonical = root.canonicalize()
            .with_context(|| format!("cannot canonicalize rules root {}", root.display()))?;
        if !canonical.starts_with(&root_canonical) {
            anyhow::bail!(
                "rule file {} resolved outside rules root {} — possible symlink attack",
                canonical.display(), root_canonical.display()
            );
        }
        Ok(canonical)
    } else {
        Ok(joined)
    }
}

fn load_main_rules_json(path: &Path) -> Result<MainRulesJson> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read JSON rules file {}", path.display()))?;
    validate_json_mapping(&content, path)?;
    let parsed = parse_json_with_rule_escape_repair::<MainRulesJson>(&content, path, "JSON rules file")?;
    Ok(parsed)
}

fn validate_json_mapping(content: &str, path: &Path) -> Result<()> {
    let parsed: Value = parse_json_value_with_rule_escape_repair(content, path)?;
    if !parsed.is_object() {
        anyhow::bail!("top-level JSON must be an object in {}", path.display());
    }
    Ok(())
}

fn parse_json_value_with_rule_escape_repair(content: &str, path: &Path) -> Result<Value> {
    match serde_json::from_str::<Value>(content) {
        Ok(value) => Ok(value),
        Err(_) => {
            warn!(target: "krakenwaf", path = %path.display(), "rule file has invalid JSON string escapes — auto-repairing; fix the source file to suppress this warning");
            let repaired = repair_invalid_json_string_escapes(content);
            serde_json::from_str::<Value>(&repaired)
                .with_context(|| format!("failed to validate JSON structure {}", path.display()))
        }
    }
}

fn parse_json_with_rule_escape_repair<T>(content: &str, path: &Path, kind: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    match serde_json::from_str::<T>(content) {
        Ok(value) => Ok(value),
        Err(_) => {
            warn!(target: "krakenwaf", path = %path.display(), "rule file has invalid JSON string escapes — auto-repairing; fix the source file to suppress this warning");
            let repaired = repair_invalid_json_string_escapes(content);
            serde_json::from_str::<T>(&repaired)
                .with_context(|| format!("failed to parse {} {}", kind, path.display()))
        }
    }
}

fn repair_invalid_json_string_escapes(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if !in_string {
            if ch == '"' {
                in_string = true;
            }
            out.push(ch);
            continue;
        }

        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }

        match ch {
            '\\' => {
                let next = chars.peek().copied();
                match next {
                    Some('"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u') => {
                        out.push('\\');
                        escaped = true;
                    }
                    Some(_) => {
                        out.push('\\');
                        out.push('\\');
                    }
                    None => out.push('\\'),
                }
            }
            '"' => {
                in_string = false;
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }

    out
}

fn json_rules_to_detection_rules(values: Vec<RuleJson>, source: &str) -> Vec<DetectionRule> {
    values
        .into_iter()
        .enumerate()
        .filter_map(|(idx, value)| {
            if value.enable == 0 {
                return None;
            }
            let rule_match = value.rule_match.trim().to_string();
            (!rule_match.is_empty()).then(|| DetectionRule {
                id: if value.id.is_empty() { format!("{:05}", idx + 1) } else { value.id },
                title: value.title,
                severity: value.severity,
                cwe: value.cwe,
                description: value.description,
                reference_url: value.url,
                rule_match,
                source: source.to_string(),
                line: idx + 1,
                http_action: value.http_action,
            })
        })
        .collect()
}

fn load_simple_lines(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read rule file {}", path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect())
}

fn load_regex_rules_json(path: &Path, source: &str) -> Result<Vec<CompiledDetectionRule>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read regex rule file {}", path.display()))?;
    validate_json_mapping(&content, path)?;
    let parsed = parse_json_with_rule_escape_repair::<RegexBundle>(&content, path, "regex rule file")?;

    parsed
        .rules
        .into_iter()
        .enumerate()
        .filter_map(|(idx, rule)| {
            if rule.enable == 0 {
                return None;
            }
            Some((idx, rule))
        })
        .map(|(idx, rule)| {
            let line = idx + 1;
            let id = if rule.id.is_empty() { format!("{:05}", line) } else { rule.id.clone() };
            let compiled = RegexBuilder::new(&rule.rule_match)
                .size_limit(10_000_000)
                .dfa_size_limit(2_000_000)
                .build()
                .with_context(|| format!("invalid regex at {}:{} => {}", source, line, rule.rule_match))?;
            Ok(CompiledDetectionRule {
                meta: DetectionRule {
                    id,
                    title: rule.title,
                    severity: rule.severity,
                    cwe: rule.cwe,
                    description: rule.description,
                    reference_url: rule.url,
                    rule_match: rule.rule_match,
                    source: source.to_string(),
                    line,
                    http_action: rule.http_action,
                },
                compiled,
            })
        })
        .collect()
}

fn load_vectorscan_rules_json(path: &Path, source: &str) -> Result<Vec<DetectionRule>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read vectorscan rule file {}", path.display()))?;
    validate_json_mapping(&content, path)?;
    let parsed = parse_json_with_rule_escape_repair::<RegexBundle>(&content, path, "vectorscan rule file")?;
    Ok(json_rules_to_detection_rules(parsed.rules, source))
}
