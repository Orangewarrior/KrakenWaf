
use crate::error::KrakenError;
use anyhow::{Context, Result};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni, ServerConfig},
    sign::CertifiedKey,
};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::{fs::File, io::BufReader, path::{Path, PathBuf}, sync::Arc};

#[derive(Debug, Clone)]
pub struct SniEntry {
    pub server_name: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub is_default: bool,
}

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

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FallbackResolver {
            resolver,
            default: Arc::new(default),
        }));

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
            is_default: parts.get(3).map(|v| v.eq_ignore_ascii_case("true") || *v == "1").unwrap_or(false),
        });
    }
    Ok(out)
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let cert_file = File::open(cert_path)
        .with_context(|| format!("failed to open certificate {}", cert_path.display()))?;
    let key_file = File::open(key_path)
        .with_context(|| format!("failed to open key {}", key_path.display()))?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    let cert_chain: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .with_context(|| format!("failed to parse certificate chain {}", cert_path.display()))?;

    let mut keys: Vec<PrivateKeyDer<'static>> = pkcs8_private_keys(&mut key_reader)
        .map(|r| r.map(Into::into))
        .collect::<Result<_, _>>()
        .with_context(|| format!("failed to parse PKCS#8 key {}", key_path.display()))?;

    if keys.is_empty() {
        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        keys = rsa_private_keys(&mut key_reader)
            .map(|r| r.map(Into::into))
            .collect::<Result<_, _>>()
            .with_context(|| format!("failed to parse RSA key {}", key_path.display()))?;
    }

    let key = keys.into_iter().next().with_context(|| format!("no private key found in {}", key_path.display()))?;
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
        self.resolver.resolve(ch).or_else(|| Some(self.default.clone()))
    }
}
