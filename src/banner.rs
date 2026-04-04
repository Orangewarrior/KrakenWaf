/// Returns the startup banner printed by KrakenWaf.
pub fn banner() -> &'static str {
    r#"
 _  __                _                __        ___    ______
| |/ /_ __ __ _  ___ | | _____ _ __    \ \      / / \  |  ____|
| ' /| '__/ _` |/ _ \| |/ / _ \ '_ \    \ \ /\ / / _ \ | |__
| . \| | | (_| | (_) |   <  __/ | | |    \ V  V / ___ \|  __|
|_|\_\_|  \__,_|\___/|_|\_\___|_| |_|     \_/\_/_/   \_\_|

KrakenWaf - Tokio + TLS + streaming inspection + AppSec-first logging
"#
}
