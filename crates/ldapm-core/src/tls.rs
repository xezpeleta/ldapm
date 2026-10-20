//! Pinned-CA TLS: the root store contains *only* the profile's CA
//! certificate(s). The system trust store is never consulted and there is no
//! code path that disables verification.

use std::path::Path;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::{Error, Result};

/// Parse every certificate in a PEM file. Fails if the file holds none.
pub fn load_ca(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let ca_err = |reason: String| Error::CaCert { path: path.to_path_buf(), reason };
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| ca_err(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ca_err(e.to_string()))?;
    if certs.is_empty() {
        return Err(ca_err("no PEM certificate found".into()));
    }
    Ok(certs)
}

/// Build a rustls client config trusting only the certificates in `ca_path`.
pub fn client_config(ca_path: &Path) -> Result<Arc<ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in load_ca(ca_path)? {
        roots.add(cert).map_err(|e| Error::CaCert {
            path: ca_path.to_path_buf(),
            reason: format!("not a usable CA certificate: {e}"),
        })?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}
