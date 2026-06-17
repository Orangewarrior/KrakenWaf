//! Factory mapping a managed rule *name* to the file that backs it and the
//! strategy used to validate and serialize an update for that file.
//!
//! The five managed contexts do **not** share a single on-disk format — three
//! are regular-expression rule bundles, one is a literal-keyword bundle, and
//! one is a plain-text substring list — so a single hard-coded handler would
//! either be wrong for some files or silently corrupt them. The factory
//! resolves a caller-supplied name to a [`RuleFile`] that carries both the
//! rules-dir-relative path and the [`RuleFileKind`] selecting the validate +
//! serialize strategy.
//!
//! The resolution table ([`MANAGED`]) is a **closed allowlist**: a name outside
//! it resolves to `None`. There is no way to address an arbitrary path, so the
//! view and update endpoints cannot be coaxed into reading or writing a file
//! outside these five entries — including files that exist elsewhere in the
//! repository (e.g. `rules.json`).

// Like `regex_rules`, this module uses `match` for Option/Result branches by
// feature convention; silence the clippy lint that would prefer `if let`.
#![allow(clippy::single_match)]

use std::path::{Path, PathBuf};

/// On-disk format of a managed rule file. Selects the validate + serialize
/// strategy applied by the regex update endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuleFileKind {
    /// JSON `{ "rules": [ ... ] }` whose `rule_match` is a regular expression.
    /// Each enabled rule's pattern is compiled before the write is accepted.
    RegexJson,
    /// JSON `{ "rules": [ ... ] }` whose `rule_match` is a literal keyword.
    /// Validated structurally but not regex-compiled (the engine treats these
    /// as plain substrings).
    KeywordJson,
    /// Plain text, one substring per line (the scanner User-Agent list).
    LineList,
}

/// A single managed rule context: its public name, the rules-dir-relative path
/// of the file it edits, and the file's on-disk format.
#[derive(Debug, Clone, Copy)]
pub(super) struct RuleFile {
    /// Public name accepted by the API (the `rule_view` value, and the trailing
    /// path segment of the update route).
    pub name: &'static str,
    /// Path of the backing file, relative to the configured rules directory.
    pub relative_path: &'static str,
    /// On-disk format, selecting the validate + serialize strategy.
    pub kind: RuleFileKind,
}

impl RuleFile {
    /// Absolute on-disk path of this rule file under `rules_dir`.
    pub(super) fn absolute_path(&self, rules_dir: &Path) -> PathBuf {
        rules_dir.join(self.relative_path)
    }
}

/// The closed allowlist of managed rule contexts. Any name outside this table
/// is rejected by [`RuleFileFactory::resolve`].
const MANAGED: [RuleFile; 5] = [
    RuleFile {
        name: "body_regex",
        relative_path: "regex/body_regex.json",
        kind: RuleFileKind::RegexJson,
    },
    RuleFile {
        name: "header_regex",
        relative_path: "regex/header_regex.json",
        kind: RuleFileKind::RegexJson,
    },
    RuleFile {
        name: "path_regex",
        relative_path: "regex/path_regex.json",
        kind: RuleFileKind::RegexJson,
    },
    RuleFile {
        name: "vectorscan_list",
        relative_path: "Vectorscan/strings2block.json",
        kind: RuleFileKind::KeywordJson,
    },
    RuleFile {
        name: "scanners",
        relative_path: "user_agents/scanners.txt",
        kind: RuleFileKind::LineList,
    },
];

/// Factory resolving a rule name to the [`RuleFile`] that backs it.
pub(super) struct RuleFileFactory;

impl RuleFileFactory {
    /// Resolve a caller-supplied rule name against the closed allowlist.
    /// Returns `None` for any name not in the table.
    pub(super) fn resolve(name: &str) -> Option<RuleFile> {
        MANAGED.iter().find(|entry| entry.name == name).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_every_managed_name_to_its_path_and_kind() {
        let cases = [
            ("body_regex", "regex/body_regex.json", RuleFileKind::RegexJson),
            (
                "header_regex",
                "regex/header_regex.json",
                RuleFileKind::RegexJson,
            ),
            ("path_regex", "regex/path_regex.json", RuleFileKind::RegexJson),
            (
                "vectorscan_list",
                "Vectorscan/strings2block.json",
                RuleFileKind::KeywordJson,
            ),
            (
                "scanners",
                "user_agents/scanners.txt",
                RuleFileKind::LineList,
            ),
        ];
        for (name, path, kind) in cases {
            match RuleFileFactory::resolve(name) {
                Some(rule_file) => {
                    assert_eq!(rule_file.relative_path, path);
                    assert_eq!(rule_file.kind, kind);
                }
                None => panic!("managed name {name} must resolve"),
            }
        }
    }

    #[test]
    fn rejects_names_outside_the_allowlist() {
        // A real file in the repository that is NOT one of the five managed
        // contexts must not resolve — the endpoints cannot edit it.
        for name in ["rules.json", "addr/blocklist.txt", "../../etc/passwd", ""] {
            match RuleFileFactory::resolve(name) {
                Some(_) => panic!("unmanaged name {name} must not resolve"),
                None => {}
            }
        }
    }

    #[test]
    fn absolute_path_joins_under_rules_dir() {
        match RuleFileFactory::resolve("body_regex") {
            Some(rule_file) => {
                let abs = rule_file.absolute_path(Path::new("/srv/rules"));
                assert_eq!(abs, Path::new("/srv/rules/regex/body_regex.json"));
            }
            None => panic!("body_regex must resolve"),
        }
    }
}
