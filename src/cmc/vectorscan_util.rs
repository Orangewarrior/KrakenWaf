//! Shared Vectorscan plumbing for the CMC detectors.
//!
//! Every detector that has a Vectorscan fast-path used to carry its own
//! near-identical `build_vectorscan` helper: turn each pattern into a
//! `Pattern::new(bytes, flags, Some(idx))`, collect, and `BlockDatabase::new`.
//! Only three things ever varied — the `Flag` set, how the pattern string is
//! turned into bytes (raw, `regex_escape`, or `regex_escape_literal`), and
//! whether the index cast used `expect` or `filter_map`. This builder captures
//! the shared shape: callers pass their flags and a `to_expr` closure, and the
//! `idx -> u32` cast lives here once (via `filter_map`, so an out-of-range index
//! is skipped rather than panicking).
//!
//! The *scanning* side is deliberately left in each detector: scan semantics
//! genuinely differ (first-match `Scan::Terminate` vs. collect-all
//! `Scan::Continue`, and some detectors need the distinct match count), so a
//! shared scan helper would have to re-encode those differences anyway.

#![cfg(feature = "vectorscan-engine")]

use vectorscan::{BlockDatabase, Flag, Pattern};

/// Compile `patterns` into a `BlockDatabase`, tagging each with its index so a
/// match id maps straight back to the source slice. `flags` is the caller's
/// Vectorscan flag set; `to_expr` turns one pattern into the expression bytes
/// Vectorscan should compile (identity, `regex_escape`, …).
///
/// Returns `None` if Vectorscan rejects the pattern set; callers fall back to
/// their Aho-Corasick path in that case. Generic over `&str` and `String`
/// pattern containers.
pub(super) fn build_block_database<P, F>(
    patterns: &[P],
    flags: Flag,
    mut to_expr: F,
) -> Option<BlockDatabase>
where
    F: FnMut(&P) -> Vec<u8>,
{
    let compiled: Vec<Pattern> = patterns
        .iter()
        .enumerate()
        .filter_map(|(idx, pattern)| {
            u32::try_from(idx)
                .ok()
                .map(|id| Pattern::new(to_expr(pattern), flags, Some(id)))
        })
        .collect();

    BlockDatabase::new(compiled).ok()
}
