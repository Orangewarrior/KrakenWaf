
use crate::error::KrakenError;
use anyhow::{Context, Result};
use parking_lot::RwLock;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni, ServerConfig},
    sign::CertifiedKey,
};
use rustls_pki_types::pem::PemObject;
use std::{path::{Path, PathBuf}, sync::Arc};
use tokio_rustls::TlsAcceptor;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct SniEntry {
    pub server_name: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub is_default: bool,
}

/// Holds the active `ServerConfig` behind an `RwLock` so a SIGHUP can atomically
/// swap it while live connections continue using the previous config uninterrupted.
///
/// Use [`TlsConfigStore::acceptor`] to obtain a fresh `TlsAcceptor` per accepted
/// TCP connection — the clone is essentially free (`Arc` increment).
#[derive(Clone)]
pub struct TlsConfigStore {
    inner: Arc<RwLock<Arc<ServerConfig>>>,
    sni_csv: PathBuf,
}

impl TlsConfigStore {
    /// Factory constructor: load TLS configuration from `sni_csv` on disk.
    ///
    /// # Errors
    /// Returns an error if the SNI map is unreadable or any certificate fails to load.
    pub fn new(sni_csv: PathBuf) -> Result<Self> {
        let config = build_tls_config(&sni_csv)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(config)),
            sni_csv,
        })
    }

    /// Hot-reload: re-read the SNI map from disk and atomically replace the config.
    ///
    /// # Errors
    /// Returns an error if the new config cannot be built (old config stays active).
    pub fn reload(&self) -> Result<()> {
        let new_config = build_tls_config(&self.sni_csv)?;
        *self.inner.write() = new_config;
        Ok(())
    }

    /// Create a `TlsAcceptor` backed by the current config snapshot.
    /// Called once per accepted TCP connection — just clones an `Arc`.
    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.inner.read().clone())
    }
}

/// Build a `ServerConfig` with ALPN `["h2", "http/1.1"]` and SNI-aware cert
/// resolution. The first entry marked `default=true` in the CSV serves as the
/// fallback certificate for clients that send no SNI.
///
/// # Errors
/// Returns an error if the SNI CSV cannot be read or any certificate/key file fails to load.
pub fn build_tls_config(sni_csv: &Path) -> Result<Arc<ServerConfig>> {
    let entries = load_sni_entries(sni_csv)?;
    let mut resolver = ResolvesServerCertUsingSni::new();
    let mut default_cert: Option<CertifiedKey> = None;

    for entry in &entries {
        let cert = load_certified_key(&entry.cert_path, &entry.key_path)?;
        if entry.is_default {
            default_cert = Some(cert.clone());
        }
        resolver
            .add(&entry.server_name, cert)
            .with_context(|| format!("failed to add SNI certificate for {}", entry.server_name))?;
    }

    let default = default_cert.ok_or(KrakenError::MissingDefaultCertificate)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FallbackResolver {
            resolver,
            default: Arc::new(default),
        }));

    // Advertise HTTP/2 and HTTP/1.1 via ALPN. The hyper auto::Builder selects
    // the negotiated protocol, defaulting to HTTP/1.1 for older clients.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

fn load_sni_entries(path: &Path) -> Result<Vec<SniEntry>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read SNI map {}", path.display()))?;
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split(',').map(str::trim).collect();
        if !(parts.len() == 3 || parts.len() == 4) {
            anyhow::bail!("invalid SNI map line {} in {}", idx + 1, path.display());
        }
        out.push(SniEntry {
            server_name: parts[0].to_string(),
            cert_path: PathBuf::from(parts[1]),
            key_path: PathBuf::from(parts[2]),
            is_default: parts.get(3).is_some_and(|v| v.eq_ignore_ascii_case("true") || *v == "1"),
        });
    }
    Ok(out)
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("failed to open certificate {}", cert_path.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("failed to parse certificate chain {}", cert_path.display()))?;

    // PrivateKeyDer::from_pem_file auto-detects PKCS#8, RSA PRIVATE KEY, and EC PRIVATE KEY.
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("no supported private key found in {}", key_path.display()))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .with_context(|| format!("failed to build signing key from {}", key_path.display()))?;
    Ok(CertifiedKey::new(cert_chain, signing_key))
}

#[derive(Debug)]
struct FallbackResolver {
    resolver: ResolvesServerCertUsingSni,
    default: Arc<CertifiedKey>,
}

impl ResolvesServerCert for FallbackResolver {
    fn resolve(&self, ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Extract SNI before moving ch into the resolver (borrow ends after map).
        let sni = ch.server_name().map(str::to_owned);
        if let Some(cert) = self.resolver.resolve(ch) { Some(cert) } else {
            // Serve the default certificate but always log: in multi-tenant deployments
            // this may expose the wrong cert to a client — operators must know it happened.
            if let Some(name) = &sni { warn!(
                target: "krakenwaf",
                sni = %name,
                "TLS: SNI not found in sni_map, serving default certificate — \
                 add an entry for this hostname to silence this warning"
            ); } else { warn!(
                target: "krakenwaf",
                "TLS: ClientHello carries no SNI, serving default certificate"
            ); }
            Some(self.default.clone())
        }
    }
}
