use crate::{banning::BlockReason, logging::SecurityEvent};

pub(super) fn derive_block_reason(event: &SecurityEvent) -> BlockReason {
    if event.rule_match.starts_with("cmc::detect_bots_n_scanners") {
        return BlockReason::SecurityScanner;
    }
    if event.rule_match == "rate_limiter"
        || event.rule_match.starts_with("rate_limit")
        || matches!(
            event.rule_line_match.as_str(),
            "gcra_budget_exceeded" | "window_exceeded"
        )
    {
        return BlockReason::RateLimit;
    }
    if event.rule_line_match.starts_with("addr/")
        || event.rule_line_match.starts_with("rules/addr/")
        || event.rule_match.starts_with("Spamhaus")
        || event.title.starts_with("Blocked source IP")
        || event.title.starts_with("Blocked IP range")
        || event.title.starts_with("Spamhaus")
    {
        return BlockReason::IpReputation;
    }
    BlockReason::RuleDetection
}

pub(super) fn derive_module_label(engine: &str, rule_match: &str) -> String {
    if engine == "cmc" {
        let module = rule_match
            .strip_prefix("cmc::")
            .and_then(|value| value.split(':').next())
            .unwrap_or("unknown");
        format!("cmc:{module}")
    } else if engine == "libinjection" {
        let variant = rule_match
            .strip_prefix("libinjection::")
            .and_then(|value| value.split(':').next())
            .unwrap_or("unknown");
        format!("libinjection:{variant}")
    } else {
        engine.to_string()
    }
}
