use crate::metrics::WafMetrics;
use uuid::Uuid;

/// Build a W3C traceparent, preserving a valid incoming trace ID while always
/// assigning `KrakenWAF` a fresh parent span ID.
pub(super) fn build_traceparent(incoming: Option<&str>, metrics: &WafMetrics) -> String {
    fn new_parent_id() -> String {
        let bytes = *Uuid::new_v4().as_bytes();
        format!(
            "{:016x}",
            u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        )
    }

    if let Some(value) = incoming {
        let parts: Vec<&str> = value.splitn(4, '-').collect();
        if parts.len() >= 3
            && parts[1].len() == 32
            && parts[1].chars().all(|character| character.is_ascii_hexdigit())
        {
            metrics.inc_traceparent_forwarded();
            return format!("00-{}-{}-01", parts[1], new_parent_id());
        }
    }

    metrics.inc_traceparent_generated();
    format!(
        "00-{:032x}-{}-01",
        Uuid::new_v4().as_u128(),
        new_parent_id()
    )
}
