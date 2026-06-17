//! CMC module control endpoints — inspect and **toggle CMC detection modules in
//! real time**:
//!
//! * `GET  /rule/control/cmc/list`   — JSON overview of every CMC module's state.
//! * `POST /rule/control/cmc/update` — partial patch; only the modules present
//!   in the body change. Unknown fields → 400; absent fields → unchanged.
//!
//! Access control (IP allowlist + Rorschach token) is enforced by
//! [`super::handle_rule_management`] before either handler runs. Every JSON
//! document is typed with `deny_unknown_fields`, and any parse/validation
//! failure returns the generic [`super::bad_request_json`] 400.

use std::sync::Arc;

use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{app::AppState, cmc::CmcUpdateOutcome, proxy::WafResponse};

// ── JSON contracts (all strictly typed with deny_unknown_fields) ──────────────

/// `GET /rule/control/cmc/list` response envelope.
#[derive(Debug, Serialize)]
struct ListResponse {
    status: &'static str,
    modules: ListModules,
}

#[derive(Debug, Serialize)]
struct ListModules {
    #[serde(rename = "CMC-Rules")]
    cmc_rules: CmcRulesView,
}

/// The 18 toggleable CMC modules, in canonical order, as booleans.
#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct CmcRulesView {
    #[serde(rename = "SQLi_comments_detect")]
    sqli_comments_detect: bool,
    #[serde(rename = "Overflow_detect")]
    overflow_detect: bool,
    #[serde(rename = "SSTI_detect")]
    ssti_detect: bool,
    #[serde(rename = "SSI_injection_detect")]
    ssi_injection_detect: bool,
    #[serde(rename = "ESI_injection_detect")]
    esi_injection_detect: bool,
    #[serde(rename = "CRLF_injection_detect")]
    crlf_injection_detect: bool,
    #[serde(rename = "Request_Smuggling_detect")]
    request_smuggling_detect: bool,
    #[serde(rename = "NOSQL_injection_detect")]
    nosql_injection_detect: bool,
    #[serde(rename = "XXE_attack_detect")]
    xxe_attack_detect: bool,
    #[serde(rename = "Anti_exposed_backup")]
    anti_exposed_backup: bool,
    #[serde(rename = "Anti_passwd_leak")]
    anti_passwd_leak: bool,
    #[serde(rename = "Java_deserialize_detect")]
    java_deserialize_detect: bool,
    #[serde(rename = "Detect_db_errors")]
    detect_db_errors: bool,
    #[serde(rename = "Silent_sql_errors")]
    silent_sql_errors: bool,
    #[serde(rename = "Detect_bad_artifacts")]
    detect_bad_artifacts: bool,
    #[serde(rename = "Detect_bots_n_scanners")]
    detect_bots_n_scanners: bool,
    #[serde(rename = "HPP_detect")]
    hpp_detect: bool,
    #[serde(rename = "Open_redirect_n_RFI_detect")]
    open_redirect_n_rfi_detect: bool,
}

impl CmcRulesView {
    fn from_states(states: &[(&'static str, bool)]) -> Self {
        let get = |key: &str| {
            states
                .iter()
                .find(|(k, _)| *k == key)
                .is_some_and(|(_, v)| *v)
        };
        Self {
            sqli_comments_detect: get("SQLi_comments_detect"),
            overflow_detect: get("Overflow_detect"),
            ssti_detect: get("SSTI_detect"),
            ssi_injection_detect: get("SSI_injection_detect"),
            esi_injection_detect: get("ESI_injection_detect"),
            crlf_injection_detect: get("CRLF_injection_detect"),
            request_smuggling_detect: get("Request_Smuggling_detect"),
            nosql_injection_detect: get("NOSQL_injection_detect"),
            xxe_attack_detect: get("XXE_attack_detect"),
            anti_exposed_backup: get("Anti_exposed_backup"),
            anti_passwd_leak: get("Anti_passwd_leak"),
            java_deserialize_detect: get("Java_deserialize_detect"),
            detect_db_errors: get("Detect_db_errors"),
            silent_sql_errors: get("Silent_sql_errors"),
            detect_bad_artifacts: get("Detect_bad_artifacts"),
            detect_bots_n_scanners: get("Detect_bots_n_scanners"),
            hpp_detect: get("HPP_detect"),
            open_redirect_n_rfi_detect: get("Open_redirect_n_RFI_detect"),
        }
    }
}

/// `POST /rule/control/cmc/update` request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRequest {
    modules: UpdateModules,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateModules {
    #[serde(rename = "CMC-Rules")]
    cmc_rules: CmcRulesPatch,
}

/// Partial patch: every module is optional. An absent field leaves the module
/// unchanged; `deny_unknown_fields` turns any unrecognised module name into a
/// deserialization error → HTTP 400.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CmcRulesPatch {
    #[serde(rename = "SQLi_comments_detect")]
    sqli_comments_detect: Option<bool>,
    #[serde(rename = "Overflow_detect")]
    overflow_detect: Option<bool>,
    #[serde(rename = "SSTI_detect")]
    ssti_detect: Option<bool>,
    #[serde(rename = "SSI_injection_detect")]
    ssi_injection_detect: Option<bool>,
    #[serde(rename = "ESI_injection_detect")]
    esi_injection_detect: Option<bool>,
    #[serde(rename = "CRLF_injection_detect")]
    crlf_injection_detect: Option<bool>,
    #[serde(rename = "Request_Smuggling_detect")]
    request_smuggling_detect: Option<bool>,
    #[serde(rename = "NOSQL_injection_detect")]
    nosql_injection_detect: Option<bool>,
    #[serde(rename = "XXE_attack_detect")]
    xxe_attack_detect: Option<bool>,
    #[serde(rename = "Anti_exposed_backup")]
    anti_exposed_backup: Option<bool>,
    #[serde(rename = "Anti_passwd_leak")]
    anti_passwd_leak: Option<bool>,
    #[serde(rename = "Java_deserialize_detect")]
    java_deserialize_detect: Option<bool>,
    #[serde(rename = "Detect_db_errors")]
    detect_db_errors: Option<bool>,
    #[serde(rename = "Silent_sql_errors")]
    silent_sql_errors: Option<bool>,
    #[serde(rename = "Detect_bad_artifacts")]
    detect_bad_artifacts: Option<bool>,
    #[serde(rename = "Detect_bots_n_scanners")]
    detect_bots_n_scanners: Option<bool>,
    #[serde(rename = "HPP_detect")]
    hpp_detect: Option<bool>,
    #[serde(rename = "Open_redirect_n_RFI_detect")]
    open_redirect_n_rfi_detect: Option<bool>,
}

impl CmcRulesPatch {
    /// Flatten the present fields into `(module_key, value)` pairs in canonical order.
    fn pairs(&self) -> Vec<(String, bool)> {
        let mut pairs = Vec::new();
        let mut push = |key: &str, v: Option<bool>| {
            if let Some(v) = v {
                pairs.push((key.to_string(), v));
            }
        };
        push("SQLi_comments_detect", self.sqli_comments_detect);
        push("Overflow_detect", self.overflow_detect);
        push("SSTI_detect", self.ssti_detect);
        push("SSI_injection_detect", self.ssi_injection_detect);
        push("ESI_injection_detect", self.esi_injection_detect);
        push("CRLF_injection_detect", self.crlf_injection_detect);
        push("Request_Smuggling_detect", self.request_smuggling_detect);
        push("NOSQL_injection_detect", self.nosql_injection_detect);
        push("XXE_attack_detect", self.xxe_attack_detect);
        push("Anti_exposed_backup", self.anti_exposed_backup);
        push("Anti_passwd_leak", self.anti_passwd_leak);
        push("Java_deserialize_detect", self.java_deserialize_detect);
        push("Detect_db_errors", self.detect_db_errors);
        push("Silent_sql_errors", self.silent_sql_errors);
        push("Detect_bad_artifacts", self.detect_bad_artifacts);
        push("Detect_bots_n_scanners", self.detect_bots_n_scanners);
        push("HPP_detect", self.hpp_detect);
        push(
            "Open_redirect_n_RFI_detect",
            self.open_redirect_n_rfi_detect,
        );
        pairs
    }
}

/// `POST /rule/control/cmc/update` response envelope.
#[derive(Debug, Serialize)]
struct UpdateResponse {
    status: &'static str,
    context: &'static str,
    updated: UpdatedModules,
}

#[derive(Debug, Serialize)]
struct UpdatedModules {
    disabled: Vec<String>,
    enabled: Vec<String>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

pub(super) fn handle_list(state: &Arc<AppState>) -> WafResponse {
    let states = state.waf.cmc_module_states();
    let body = ListResponse {
        status: "ok",
        modules: ListModules {
            cmc_rules: CmcRulesView::from_states(&states),
        },
    };
    super::json_response(state, StatusCode::OK, &body)
}

pub(super) fn handle_update(state: &Arc<AppState>, body: &[u8]) -> WafResponse {
    let request: UpdateRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(_) => return super::bad_request_json(state),
    };
    let pairs = request.modules.cmc_rules.pairs();
    match state.waf.cmc_apply_update(&pairs) {
        Ok(CmcUpdateOutcome { enabled, disabled }) => {
            info!(
                target: "krakenwaf",
                enabled = ?enabled,
                disabled = ?disabled,
                "rule-management: CMC module table updated in real time"
            );
            let body = UpdateResponse {
                status: "ok",
                context: "cmc_update",
                updated: UpdatedModules { disabled, enabled },
            };
            super::json_response(state, StatusCode::OK, &body)
        }
        // Unknown module key. `deny_unknown_fields` normally turns this into a
        // deserialization error above; this is the defensive belt-and-braces case.
        Err(_unknown_key) => super::bad_request_json(state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_rejects_unknown_module_field() {
        let body = br#"{"modules":{"CMC-Rules":{"Bogus_module":true}}}"#;
        let parsed: Result<UpdateRequest, _> = serde_json::from_slice(body);
        assert!(
            parsed.is_err(),
            "unknown module key must fail deny_unknown_fields"
        );
    }

    #[test]
    fn update_accepts_partial_patch() {
        let body = br#"{"modules":{"CMC-Rules":{"HPP_detect":false,"Silent_sql_errors":false}}}"#;
        let parsed: UpdateRequest = serde_json::from_slice(body).expect("valid partial patch");
        let pairs = parsed.modules.cmc_rules.pairs();
        assert_eq!(
            pairs,
            vec![
                ("Silent_sql_errors".to_string(), false),
                ("HPP_detect".to_string(), false),
            ]
        );
    }

    #[test]
    fn update_rejects_unknown_top_level_field() {
        let body = br#"{"modules":{"CMC-Rules":{}},"extra":1}"#;
        let parsed: Result<UpdateRequest, _> = serde_json::from_slice(body);
        assert!(parsed.is_err());
    }
}
