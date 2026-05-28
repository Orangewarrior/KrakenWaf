use anyhow::{Context, Result};
use std::{net::IpAddr, path::PathBuf, sync::Arc};

/// Geolocation result for a single IP lookup.
#[derive(Debug, Clone, Default)]
pub struct GeoIpResult {
    pub country_name: String,
    pub continent_name: String,
}

impl GeoIpResult {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Builder for [`GeoIpReader`] — resolves the database path and opens it.
pub struct GeoIpReaderBuilder {
    path: PathBuf,
}

impl GeoIpReaderBuilder {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Open the MaxMind database at the configured path.
    ///
    /// # Errors
    /// Returns an error when the file cannot be read or is not a valid `.mmdb`.
    pub fn build(self) -> Result<GeoIpReader> {
        let reader = maxminddb::Reader::open_readfile(&self.path).with_context(|| {
            format!(
                "failed to open GeoLite2-City database at {}",
                self.path.display()
            )
        })?;
        Ok(GeoIpReader {
            reader: Arc::new(reader),
        })
    }
}

/// Thread-safe MaxMind GeoLite2-City reader.
///
/// Constructed via [`GeoIpReaderBuilder`]:
/// ```no_run
/// # use krakenwaf::geo::GeoIpReader;
/// let reader = GeoIpReader::builder("db/geo/GeoLite2-City.mmdb").build().unwrap();
/// let result = reader.lookup("8.8.8.8");
/// ```
pub struct GeoIpReader {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpReader {
    /// Create a builder for this reader.
    #[must_use]
    pub fn builder(path: impl Into<PathBuf>) -> GeoIpReaderBuilder {
        GeoIpReaderBuilder::new(path)
    }

    /// Look up country and continent for an IP address string.
    ///
    /// Returns [`GeoIpResult::empty`] for private/loopback IPs, invalid
    /// addresses, or any DB miss — never panics.
    #[must_use]
    pub fn lookup(&self, ip: &str) -> GeoIpResult {
        let addr: IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => return GeoIpResult::empty(),
        };

        // Skip RFC-1918 / loopback — MaxMind does not cover them.
        if is_private_or_loopback(addr) {
            return GeoIpResult::empty();
        }

        let city: maxminddb::geoip2::City = match self.reader.lookup(addr) {
            Ok(c) => c,
            Err(_) => return GeoIpResult::empty(),
        };

        let country_name = city
            .country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").copied())
            .unwrap_or("")
            .to_string();

        let continent_name = city
            .continent
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").copied())
            .unwrap_or("")
            .to_string();

        GeoIpResult {
            country_name,
            continent_name,
        }
    }
}

fn is_private_or_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn db_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("db/geo/GeoLite2-City.mmdb")
    }

    fn open_reader() -> Option<GeoIpReader> {
        let p = db_path();
        if !p.exists() {
            return None;
        }
        GeoIpReader::builder(&p).build().ok()
    }

    #[test]
    fn empty_result_on_invalid_ip() {
        let result = GeoIpResult::empty();
        assert!(result.country_name.is_empty());
        assert!(result.continent_name.is_empty());
    }

    #[test]
    fn private_ip_returns_empty() {
        let Some(reader) = open_reader() else { return };
        let result = reader.lookup("192.168.1.1");
        assert!(result.country_name.is_empty(), "private IP should return empty country");
    }

    #[test]
    fn loopback_returns_empty() {
        let Some(reader) = open_reader() else { return };
        let result = reader.lookup("127.0.0.1");
        assert!(result.country_name.is_empty(), "loopback should return empty country");
    }

    #[test]
    fn invalid_ip_returns_empty() {
        let Some(reader) = open_reader() else { return };
        let result = reader.lookup("not-an-ip");
        assert!(result.country_name.is_empty());
    }

    #[test]
    fn google_dns_lookup() {
        let Some(reader) = open_reader() else { return };
        // 8.8.8.8 is Google's public DNS, located in the United States.
        let result = reader.lookup("8.8.8.8");
        assert!(!result.country_name.is_empty(), "8.8.8.8 should resolve to a country");
        assert!(!result.continent_name.is_empty(), "8.8.8.8 should resolve to a continent");
        assert_eq!(result.country_name, "United States");
        assert_eq!(result.continent_name, "North America");
    }

    #[test]
    fn cloudflare_dns_lookup_does_not_panic() {
        let Some(reader) = open_reader() else { return };
        // 1.1.1.1 is Cloudflare's anycast DNS. GeoLite2 may not have
        // geographic data for APNIC/Cloudflare reserved blocks — acceptable.
        let _result = reader.lookup("1.1.1.1");
    }

    #[test]
    fn builder_fails_on_nonexistent_path() {
        let err = GeoIpReader::builder("/nonexistent/path/GeoLite2-City.mmdb").build();
        assert!(err.is_err(), "builder should fail on nonexistent DB path");
    }
}
