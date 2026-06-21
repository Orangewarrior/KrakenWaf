//! Small, typed pieces of effective startup configuration.
//!
//! Full configuration assembly still happens in `main`, but security-sensitive
//! cross-field invariants live here so they can be tested without booting the
//! process.

use crate::{cli::Cli, proxy_config::ProxyConfig};
use anyhow::Result;
use std::net::SocketAddr;

/// Built-in fallback port for the dedicated observability listener.
const DEFAULT_METRICS_PORT: u16 = 4343;

/// Built-in fallback port for the rule-management control-plane listener.
const DEFAULT_RULE_MANAGEMENT_PORT: u16 = 4342;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlPlaneAddrs {
    pub listen: SocketAddr,
    pub metrics: SocketAddr,
    pub rule_management: SocketAddr,
}

impl ControlPlaneAddrs {
    #[must_use]
    pub fn resolve(listen: SocketAddr, cli: &Cli, proxy: Option<&ProxyConfig>) -> Self {
        let metrics_port = cli.metrics_port.unwrap_or_else(|| {
            proxy
                .and_then(|cfg| cfg.metrics_port)
                .unwrap_or(DEFAULT_METRICS_PORT)
        });
        let rule_management_port = cli.rule_management_port.unwrap_or_else(|| {
            proxy
                .and_then(|cfg| cfg.rule_management_port)
                .unwrap_or(DEFAULT_RULE_MANAGEMENT_PORT)
        });
        Self {
            listen,
            metrics: SocketAddr::new(listen.ip(), metrics_port),
            rule_management: SocketAddr::new(listen.ip(), rule_management_port),
        }
    }

    /// The dedicated metrics listener must really be dedicated. Previous
    /// startup code only warned on collision, which left `/metrics` unavailable
    /// because the data-plane handler intentionally does not serve metrics.
    ///
    /// # Errors
    /// Returns an error when the metrics port collides with the proxy listener.
    pub fn validate_metrics(self) -> Result<()> {
        if self.metrics == self.listen {
            anyhow::bail!(
                "metrics-port collides with the proxy listen address ({addr}); choose a distinct \
                 dedicated observability port",
                addr = self.metrics
            );
        }
        Ok(())
    }

    /// Rule management is a control plane. If it was explicitly enabled by
    /// provisioning Rorschach secrets, a port collision is a startup error
    /// rather than a warning that silently disables live rule management.
    ///
    /// # Errors
    /// Returns an error when the rule-management listener collides with either
    /// the data-plane or observability listener.
    pub fn validate_rule_management(self) -> Result<()> {
        if self.rule_management == self.listen {
            anyhow::bail!(
                "rule-management-port collides with the proxy listen address ({addr}); choose a \
                 distinct control-plane port",
                addr = self.rule_management
            );
        }
        if self.rule_management == self.metrics {
            anyhow::bail!(
                "rule-management-port collides with the metrics listener ({addr}); choose distinct \
                 observability and rule-management ports",
                addr = self.rule_management
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse_cli(extra_args: &[&str]) -> Cli {
        let mut command_line = vec!["krakenwaf"];
        command_line.extend_from_slice(extra_args);
        Cli::parse_from(command_line)
    }

    #[test]
    fn resolves_ports_from_cli_then_defaults() {
        let cli = parse_cli(&[
            "--listen",
            "127.0.0.1:8443",
            "--metrics-port",
            "9443",
            "--rule-management-port",
            "9442",
        ]);
        let addrs = ControlPlaneAddrs::resolve(cli.listen, &cli, None);
        assert_eq!(addrs.metrics.to_string(), "127.0.0.1:9443");
        assert_eq!(addrs.rule_management.to_string(), "127.0.0.1:9442");
    }

    #[test]
    fn rejects_metrics_collision() {
        let cli = parse_cli(&["--listen", "127.0.0.1:8443", "--metrics-port", "8443"]);
        let addrs = ControlPlaneAddrs::resolve(cli.listen, &cli, None);
        assert!(addrs.validate_metrics().is_err());
    }

    #[test]
    fn rejects_rule_management_collision_with_metrics() {
        let cli = parse_cli(&[
            "--listen",
            "127.0.0.1:8443",
            "--metrics-port",
            "9443",
            "--rule-management-port",
            "9443",
        ]);
        let addrs = ControlPlaneAddrs::resolve(cli.listen, &cli, None);
        assert!(addrs.validate_rule_management().is_err());
    }
}
